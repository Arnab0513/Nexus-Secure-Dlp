"""
NEXUS Endpoint Agent — Structured Logging Configuration.

Configures Python's logging module with:
- Rotating file handler (logs/nexus_agent.log)
- Console handler (stdout)
- Consistent format across all modules
"""

from __future__ import annotations

import logging
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path

from config import LoggingConfig, agent_base_dir

_LOG_FORMAT = "[%(asctime)s] [%(levelname)-8s] [%(name)-20s] %(message)s"
_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"
_INITIALIZED = False


def setup_logging(config: LoggingConfig | None = None) -> None:
    """
    Initialize the logging system.

    Safe to call multiple times — only the first call takes effect.

    Parameters
    ----------
    config : LoggingConfig, optional
        Logging settings from NexusConfig.  Uses defaults if omitted.
    """
    global _INITIALIZED
    if _INITIALIZED:
        return
    _INITIALIZED = True

    if config is None:
        config = LoggingConfig()

    level = getattr(logging, config.level.upper(), logging.INFO)
    root_logger = logging.getLogger()
    root_logger.setLevel(level)

    formatter = logging.Formatter(_LOG_FORMAT, datefmt=_DATE_FORMAT)

    # ---- Console handler ------------------------------------------
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(level)
    console_handler.setFormatter(formatter)
    root_logger.addHandler(console_handler)

    # ---- File handler ---------------------------------------------
    log_path = config.resolved_file()
    log_path.parent.mkdir(parents=True, exist_ok=True)

    file_handler = RotatingFileHandler(
        filename=str(log_path),
        maxBytes=config.max_bytes,
        backupCount=config.backup_count,
        encoding="utf-8",
    )
    file_handler.setLevel(level)
    file_handler.setFormatter(formatter)
    root_logger.addHandler(file_handler)

    # Suppress noisy third-party loggers
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("watchdog").setLevel(logging.WARNING)


def get_logger(name: str) -> logging.Logger:
    """
    Return a named logger for the given module.

    Usage::

        from utils.logging_config import get_logger
        logger = get_logger(__name__)
        logger.info("Module initialized")
    """
    return logging.getLogger(name)
