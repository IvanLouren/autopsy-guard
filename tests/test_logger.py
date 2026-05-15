from __future__ import annotations

import logging
from pathlib import Path

from autopsyguard.logger import setup_logging


def test_setup_logging_writes_rotating_file(tmp_path: Path) -> None:
    root = logging.getLogger()
    old_handlers = list(root.handlers)
    old_level = root.level
    log_dir = tmp_path / "logs"
    try:
        setup_logging(log_dir=log_dir, level=logging.INFO)
        logging.getLogger("autopsyguard.test").info("hello-log-file")

        log_file = log_dir / "autopsyguard.log"
        assert log_file.exists()
        content = log_file.read_text(encoding="utf-8")
        assert "hello-log-file" in content
    finally:
        root.handlers.clear()
        for h in old_handlers:
            root.addHandler(h)
        root.setLevel(old_level)
