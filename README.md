# AutopsyGuard

AutopsyGuard is a **real-time monitoring system** for the Autopsy digital forensics tool. It tracks execution, detects anomalies, logs activity, and sends notifications on Windows and Linux systems.

## 🎯 Problem

Autopsy can crash or hang during long forensic analysis jobs, potentially losing hours of work. AutopsyGuard provides early detection of failures so analysts can respond quickly.

## ✅ Detection Capabilities

| Detection Type | What It Catches |
|---------------|-----------------|
| `[OUT_OF_MEMORY]` | Java heap exhaustion (OutOfMemoryError) |
| `[PROCESS_DISAPPEARED]` | Crash or unexpected shutdown |
| `[JVM_CRASH]` | Fatal JVM errors (hs_err_pid files) |
| `[HANG]` | Frozen process (sustained low CPU) |
| `[SOLR_CRASH]` | Solr child process death |
| `[HIGH_RESOURCE]` | CPU/Memory/Disk threshold warnings |
| `[LOG_ERROR]` | SEVERE/FATAL entries in logs |

## 🚀 Quick Start

### Installation

```bash
pip install -e .
```

### Running the Monitor

```bash
python -m autopsyguard.monitor <case_directory> --install-dir <autopsy_install_path> --poll-interval 5
```

**Example:**
```bash
python -m autopsyguard.monitor "C:\Users\user\Cases\MyCase" --install-dir "C:\Program Files\Autopsy-4.22.1" --poll-interval 5
```

The monitor will:
- Track the Autopsy process
- Watch log files for errors
- Detect crashes and hangs
- Alert on resource issues

Press `Ctrl+C` to stop.

## 🧪 Testing with Simulations

The `simulations/` folder contains scripts to test detection capabilities with real Autopsy failures.

### Test 1: OutOfMemoryError Detection

```bash
# 1. Close Autopsy first!

# 2. Prepare (limits JVM heap to 64MB)
python simulations/sim_oom.py prepare --install-dir "C:\Program Files\Autopsy-4.22.1"

# 3. Start monitor in one terminal
python -m autopsyguard.monitor "C:\path\to\case" --install-dir "C:\Program Files\Autopsy-4.22.1" --poll-interval 5

# 4. Open Autopsy, open a case, start ingest → Watch for [OUT_OF_MEMORY] alert

# 5. Restore when done
python simulations/sim_oom.py restore --install-dir "C:\Program Files\Autopsy-4.22.1"
```

### Test 2: JVM Crash Detection

```bash
# 1. Close Autopsy first!

# 2. Prepare (limits heap to trigger OOM)
python simulations/sim_oom.py prepare --install-dir "C:\Program Files\Autopsy-4.22.1"

# 3. Start monitor and open Autopsy → Open case and start ingest → Watch for [OUT_OF_MEMORY] alert

# 4. Restore when done
python simulations/sim_oom.py restore --install-dir "C:\Program Files\Autopsy-4.22.1"
```

### Other Simulations

| Script | Description |
|--------|-------------|
| `sim_oom.py` | Triggers real OutOfMemoryError |
| `sim_log_errors.py` | Injects SEVERE/FATAL log entries |
| `sim_process_kill.py` | Simulates process crash |
| `sim_solr_crash.py` | Kills Solr child process |

## 📁 Project Structure

```
autopsy-guard/
├── src/autopsyguard/
│   ├── monitor.py        # Main monitoring loop
│   ├── platform_utils.py # Cross-platform helpers
│   ├── config.py         # Configuration
│   └── models.py         # Data models
├── simulations/
│   ├── run_monitor.py    # Monitor runner
│   ├── sim_oom.py        # OOM simulation
│   └── ...
└── pyproject.toml
```

## 🖥️ Platform Support

- **Windows**: Tested with Autopsy 4.22.1
- **Linux**: Supported (paths adjusted automatically)

## 📋 Requirements

- Python 3.11+
- psutil
