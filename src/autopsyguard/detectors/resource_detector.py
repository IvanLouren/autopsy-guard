"""Detect abnormal resource consumption by the Autopsy process.

Covers crash type 6: High Resource Consumption (CPU, memory, disk).

This is an anomaly detector — it fires warnings when Autopsy's resource
usage exceeds configured thresholds, which often precedes a crash.
"""

from __future__ import annotations

import logging
import time
from pathlib import Path

import psutil

from autopsyguard.config import MonitorConfig
from autopsyguard.detectors.base import BaseDetector
from autopsyguard.models import CrashEvent, CrashType, Severity
import autopsyguard.utils.process_utils as process_utils
from autopsyguard.platform_utils import get_autopsy_process_names, get_java_process_names

logger = logging.getLogger(__name__)


class ResourceDetector(BaseDetector):
    """Monitors CPU, memory, and disk usage for anomalies."""

    def __init__(self, config: MonitorConfig) -> None:
        super().__init__(config)
        self._high_cpu_since: float | None = None
        self._cpu_warning_reported = False
        self._mem_warning_reported = False
        self._disk_warning_reported = False
        self._external_mem_warning_reported = False
        self._proc: psutil.Process | None = None
        self._proc_pid: int | None = None
        self._external_mem_last_alert_ts: float | None = None
        self._external_mem_last_signature: tuple[float, float, float] | None = None
        self._external_mem_cooldown_seconds = 600.0
        self._external_mem_min_delta_percent = 1.0
        self._external_mem_min_delta_fraction = 5.0
        self._external_mem_min_delta_other_gb = 0.5
        self._autopsy_names = {n.lower() for n in get_autopsy_process_names()}
        self._java_names = {n.lower() for n in get_java_process_names()}

    @property
    def name(self) -> str:
        return "ResourceDetector"

    def check(self) -> list[CrashEvent]:
        events: list[CrashEvent] = []

        pid = process_utils.find_autopsy_pid()
        if pid is not None:
            events.extend(self._check_cpu(pid))
            events.extend(self._check_memory(pid))
            events.extend(self._check_external_memory_pressure(pid))
        else:
            self._proc = None
            self._proc_pid = None

        events.extend(self._check_disk())

        return events

    # ------------------------------------------------------------------
    # CPU
    # ------------------------------------------------------------------

    def _check_cpu(self, pid: int) -> list[CrashEvent]:
        now = time.time()
        try:
            proc = self._proc if self._proc is not None and self._proc_pid == pid else psutil.Process(pid)
            if proc is not self._proc:
                try:
                    proc.cpu_percent(interval=0.1)
                except Exception:
                    pass
                self._proc = proc
                self._proc_pid = pid
                logger.debug("Rebuilt Autopsy process cache for PID %s", pid)
            # Use non-blocking measurement: `interval=None` returns the
            # percentage since the last call to `cpu_percent()` for this
            # process. This avoids blocking the monitoring loop for 100ms
            # per detector call. Note: the first call after process start
            # may return 0.0; discard that first sample to avoid spurious
            # high-CPU detections immediately after process discovery.
            cpu = proc.cpu_percent(interval=None)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            self._high_cpu_since = None
            self._proc = None
            self._proc_pid = None
            return []

        # The cached process has already been warmed once, so a sample of
        # 0.0 now represents an actual idle reading rather than a psutil
        # bootstrap artifact.
        try:
            cpu = float(cpu)
        except Exception:
            cpu = 0.0

        # Interpret psutil's process CPU percent: can exceed 100% when
        # the process uses multiple logical cores (e.g. 250% ~= 2.5 cores).
        # Normalize cpu_count to an int; mocks may return MagicMock so guard.
        try:
            cpu_count_raw = psutil.cpu_count(logical=True)
            cpu_count = int(cpu_count_raw) if cpu_count_raw else 1
        except Exception:
            cpu_count = 1

        # Ensure numeric cpu value
        try:
            cpu = float(cpu)
        except Exception:
            cpu = 0.0

        cores_used = cpu / 100.0
        per_core_percent = (cpu / cpu_count) if cpu_count else cpu

        # Trigger if either total process CPU percentage exceeds the configured
        # process-wide threshold OR the per-core average exceeds the per-core threshold.
        # Compare using floats and guard against non-numeric values from mocks
        try:
            triggers_total = float(cpu) >= float(self.config.cpu_warning_percent)
        except Exception:
            triggers_total = False
        try:
            triggers_per_core = float(per_core_percent) >= float(getattr(self.config, "cpu_per_core_warning_percent", 100.0))
        except Exception:
            triggers_per_core = False

        if triggers_total or triggers_per_core:
            if self._high_cpu_since is None:
                self._high_cpu_since = now
            elapsed = now - self._high_cpu_since
            if elapsed >= self.config.cpu_warning_duration and not self._cpu_warning_reported:
                self._cpu_warning_reported = True
                # Build a clearer message including cores used and per-core percent
                message_parts = [
                    f"Autopsy (PID {pid}) sustained CPU at {cpu:.1f}%",
                    f"(≈{cores_used:.1f} cores; ≈{per_core_percent:.1f}% per core)",
                ]
                if triggers_total and not triggers_per_core:
                    message_parts.append(f"exceeding total threshold {self.config.cpu_warning_percent:.0f}%")
                elif triggers_per_core and not triggers_total:
                    message_parts.append(f"exceeding per-core threshold {self.config.cpu_per_core_warning_percent:.0f}%")
                else:
                    message_parts.append("exceeding both total and per-core thresholds")
                message_parts.append(f"for {elapsed:.0f}s")
                message = " ".join(message_parts)
                return [CrashEvent(
                    crash_type=CrashType.HIGH_RESOURCE_USAGE,
                    severity=Severity.WARNING,
                    message=message,
                    details={
                        "pid": pid,
                        "cpu_percent": cpu,
                        "cores_used": cores_used,
                        "cpu_count": cpu_count,
                        "cpu_per_core_percent": per_core_percent,
                        "cpu_per_core_warning_percent": getattr(self.config, "cpu_per_core_warning_percent", None),
                        "duration_seconds": elapsed,
                    },
                )]
        else:
            self._high_cpu_since = None
            self._cpu_warning_reported = False

        return []

    # ------------------------------------------------------------------
    # Memory
    # ------------------------------------------------------------------

    def _check_memory(self, pid: int) -> list[CrashEvent]:
        try:
            proc = self._proc if self._proc is not None and self._proc_pid == pid else psutil.Process(pid)
            mem_info = proc.memory_info()
            system_mem = psutil.virtual_memory()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return []

        try:
            rss = int(mem_info.rss)
            total = int(system_mem.total)
            usage_percent = (rss / total) * 100
        except Exception:
            # Be defensive in tests where memory fields may be mocked
            return []

        if usage_percent >= self.config.memory_warning_percent:
            if not self._mem_warning_reported:
                self._mem_warning_reported = True
                rss_gb = rss / (1024**3)
                total_bytes = int(system_mem.total)
                return [CrashEvent(
                    crash_type=CrashType.HIGH_RESOURCE_USAGE,
                    severity=Severity.WARNING,
                    message=(
                        f"Autopsy (PID {pid}) using {usage_percent:.1f}% "
                        f"of system RAM ({rss_gb:.1f} GB)"
                    ),
                    details={
                        "pid": pid,
                        "rss_bytes": rss,
                        "system_total_bytes": total_bytes,
                        "usage_percent": usage_percent,
                    },
                )]
        else:
            self._mem_warning_reported = False

        return []

    # ------------------------------------------------------------------
    # Disk
    # ------------------------------------------------------------------

    def _check_disk(self) -> list[CrashEvent]:
        """Check free space on the partition hosting the case directory."""
        case_dir = self.config.case_dir
        if not case_dir.is_dir():
            return []

        try:
            usage = psutil.disk_usage(str(case_dir))
        except OSError:
            return []

        free_gb = usage.free / (1024**3)

        if free_gb < self.config.disk_min_free_gb:
            if not self._disk_warning_reported:
                self._disk_warning_reported = True
                return [CrashEvent(
                    crash_type=CrashType.HIGH_RESOURCE_USAGE,
                    severity=Severity.CRITICAL,
                    message=(
                        f"Disk space critically low: {free_gb:.2f} GB free "
                        f"on {case_dir.anchor}"
                    ),
                    details={
                        "free_gb": free_gb,
                        "total_gb": usage.total / (1024**3),
                        "partition": case_dir.anchor,
                    },
                )]
        else:
            self._disk_warning_reported = False

        return []

    # ------------------------------------------------------------------
    # External memory pressure
    # ------------------------------------------------------------------

    def _is_java_like_process(self, proc: psutil.Process) -> bool:
        try:
            name = (proc.name() or "").lower()
        except Exception:
            name = ""
        if name in self._java_names:
            return True

        try:
            cmd = " ".join(str(x).lower() for x in (proc.cmdline() or []))
        except Exception:
            cmd = ""
        return any(marker in cmd for marker in ("org.sleuthkit.autopsy", "org.apache.solr", "keywordsearch", "solr"))

    def _collect_autopsy_related_processes(
        self,
        autopsy_pid: int,
        *,
        root_proc: psutil.Process | None = None,
    ) -> tuple[dict[int, tuple[str, int]], dict[int, str]]:
        """Return related process map + source metadata for Autopsy attribution.

        Returns:
            - related: PID -> (name, rss_bytes)
            - sources: PID -> source tag ("root", "tree", "global", "both")
        """
        root = root_proc
        if root is None:
            try:
                root = psutil.Process(autopsy_pid)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                return {}, {}

        related: dict[int, tuple[str, int]] = {}
        sources: dict[int, str] = {}
        try:
            root_mem = int(root.memory_info().rss)
        except Exception:
            root_mem = 0
        try:
            root_name = root.name() or "autopsy"
        except Exception:
            root_name = "autopsy"
        related[autopsy_pid] = (root_name, root_mem)
        sources[autopsy_pid] = "root"

        try:
            children = root.children(recursive=True)
        except Exception:
            children = []
        for child in children:
            try:
                if not self._is_java_like_process(child):
                    continue
                rss = int(child.memory_info().rss)
                name = child.name() or "java"
                related[child.pid] = (name, rss)
                sources[child.pid] = "tree"
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
            except Exception:
                continue

        # Windows/process-chain fallback:
        # Solr JVM may not appear under Autopsy tree. Attribute those JVMs to
        # Autopsy if they match strong Solr signatures.
        global_solr = self._collect_global_solr_related_processes(now=time.time())
        for g_pid, (g_name, g_rss) in global_solr.items():
            if g_pid not in related:
                related[g_pid] = (g_name, g_rss)
                sources[g_pid] = "global"
            elif sources.get(g_pid) == "tree":
                sources[g_pid] = "both"

        return related, sources

    def _looks_like_solr_java_cmdline(self, cmdline: list[object], *, solr_port: int) -> bool:
        """Best-effort Solr JVM matcher using command-line markers."""
        if not cmdline:
            return False
        cmd = " ".join(str(x).lower() for x in cmdline)
        port_token = f":{solr_port}"
        markers = (
            "solr",
            "start.jar",
            "org.apache.solr",
            "-dsolr.",
            "solr.port",
        )
        if any(marker in cmd for marker in markers):
            return True
        return port_token in cmd

    def _collect_global_solr_related_processes(self, *, now: float) -> dict[int, tuple[str, int]]:
        """Find Solr JVMs even if not parented under the tracked Autopsy PID."""
        related: dict[int, tuple[str, int]] = {}
        for proc in psutil.process_iter(["pid", "name", "cmdline", "create_time", "exe", "memory_info"]):
            try:
                proc_pid = int(proc.info.get("pid"))
                proc_name_raw = proc.info.get("name") or "java"
                proc_name = str(proc_name_raw).lower()
                cmdline = proc.info.get("cmdline") or []
                exe = proc.info.get("exe")
                create_time = float(proc.info.get("create_time") or 0.0)
                age_s = now - create_time if create_time > 0 else 0.0
                mem_info = proc.info.get("memory_info")
                rss = int(mem_info.rss) if mem_info is not None else 0

                # Is this a JVM-like process?
                is_java = proc_name in self._java_names
                if not is_java and cmdline:
                    first = Path(str(cmdline[0])).name.lower()
                    is_java = first in self._java_names
                if not is_java and exe:
                    try:
                        is_java = Path(str(exe)).name.lower() in self._java_names
                    except Exception:
                        pass
                if not is_java:
                    continue

                if self._looks_like_solr_java_cmdline(cmdline, solr_port=self.config.solr_port):
                    related[proc_pid] = (str(proc_name_raw), rss)
                elif age_s >= 15.0:
                    # Fallback when cmdline was unavailable in proc.info.
                    try:
                        if not cmdline and self._looks_like_solr_java_cmdline(proc.cmdline(), solr_port=self.config.solr_port):
                            related[proc_pid] = (str(proc_name_raw), rss)
                    except Exception:
                        pass
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
            except Exception:
                continue
        return related

    def _check_external_memory_pressure(self, pid: int) -> list[CrashEvent]:
        """Detect when system memory is high but Autopsy is NOT the main consumer.

        If total system memory usage exceeds the warning threshold but Autopsy
        accounts for less than half of the used memory, another process is the
        real cause.  Report the top memory consumers so the user can act.
        """
        try:
            system_mem = psutil.virtual_memory()
            proc = self._proc if self._proc is not None and self._proc_pid == pid else psutil.Process(pid)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return []

        try:
            system_used = int(system_mem.used)
            system_total = int(system_mem.total)
            system_percent = float(system_mem.percent)
        except Exception:
            return []

        related, related_sources = self._collect_autopsy_related_processes(pid, root_proc=proc)
        if not related:
            return []
        autopsy_rss = sum(rss for _, rss in related.values())
        autopsy_rss = max(0, min(autopsy_rss, system_used))

        # Only trigger when system memory is high
        if system_percent < self.config.memory_warning_percent:
            self._external_mem_warning_reported = False
            return []

        # Check if Autopsy is NOT the main consumer (< 50% of used memory)
        autopsy_fraction = autopsy_rss / system_used if system_used > 0 else 1.0
        if autopsy_fraction >= 0.5:
            # Autopsy is the dominant consumer — the existing memory check handles this
            self._external_mem_warning_reported = False
            return []

        # Find top 5 external (non-Autopsy-tree) processes by memory.
        exclude_pids = set(related.keys())

        top_procs: list[tuple[str, int, float]] = []  # (name, pid, rss_bytes)
        try:
            for p in psutil.process_iter(["pid", "name", "memory_info"]):
                try:
                    p_pid = p.info["pid"]
                    p_name = (p.info.get("name") or "").lower()
                    p_mem = p.info.get("memory_info")
                    if p_pid in exclude_pids or p_name in self._autopsy_names:
                        continue
                    if p_mem is not None:
                        rss = int(p_mem.rss)
                        top_procs.append((p.info.get("name") or "unknown", p_pid, rss))
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except Exception:
            return []

        # Sort by RSS descending and take top 5
        top_procs.sort(key=lambda x: x[2], reverse=True)
        top_5 = top_procs[:5]
        child_top = sorted(
            [
                (proc_name, proc_pid, rss)
                for proc_pid, (proc_name, rss) in related.items()
                if proc_pid != pid
            ],
            key=lambda x: x[2],
            reverse=True,
        )[:5]

        # Build message
        autopsy_gb = autopsy_rss / (1024**3)
        other_used_gb = max(0.0, (system_used - autopsy_rss) / (1024**3))
        top_list = ", ".join(
            f"{name} (PID {p_pid}, {rss / (1024**3):.1f} GB)"
            for name, p_pid, rss in top_5
        )
        child_list = ", ".join(
            f"{name} (PID {p_pid}, {rss / (1024**3):.1f} GB)"
            for name, p_pid, rss in child_top
        )

        now = time.time()
        current_signature = (
            round(system_percent, 1),
            round(autopsy_fraction * 100.0, 1),
            round(other_used_gb, 1),
        )
        if self._external_mem_last_alert_ts is not None and self._external_mem_last_signature is not None:
            elapsed = now - self._external_mem_last_alert_ts
            prev_system_pct, prev_autopsy_frac_pct, prev_other_used_gb = self._external_mem_last_signature
            changed_meaningfully = (
                abs(current_signature[0] - prev_system_pct) >= self._external_mem_min_delta_percent
                or abs(current_signature[1] - prev_autopsy_frac_pct) >= self._external_mem_min_delta_fraction
                or abs(current_signature[2] - prev_other_used_gb) >= self._external_mem_min_delta_other_gb
            )
            if elapsed < self._external_mem_cooldown_seconds and not changed_meaningfully:
                logger.debug(
                    "Suppressing near-duplicate external memory pressure alert (elapsed=%.1fs, signature=%s)",
                    elapsed,
                    current_signature,
                )
                return []

        self._external_mem_warning_reported = True
        self._external_mem_last_alert_ts = now
        self._external_mem_last_signature = current_signature
        return [CrashEvent(
            crash_type=CrashType.HIGH_RESOURCE_USAGE,
            severity=Severity.WARNING,
            message=(
                f"System memory at {system_percent:.1f}% but Autopsy only uses "
                f"{autopsy_gb:.1f} GB ({autopsy_fraction * 100:.0f}% of used). "
                f"Other processes are consuming {other_used_gb:.1f} GB "
                f"(Autopsy child JVMs excluded from external consumers)."
            ),
            details={
                "system_memory_percent": system_percent,
                "autopsy_rss_gb": round(autopsy_gb, 2),
                "autopsy_fraction_of_used": round(autopsy_fraction * 100, 1),
                "other_used_gb": round(other_used_gb, 2),
                "autopsy_related_pids": sorted(exclude_pids),
                "autopsy_related_sources": {
                    str(r_pid): related_sources.get(r_pid, "unknown")
                    for r_pid in sorted(exclude_pids)
                },
                "autopsy_child_consumers": child_list,
                "top_consumers_external": top_list,
                # Backward-compatible key for existing templates/parsers.
                "top_consumers": top_list,
            },
        )]

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

