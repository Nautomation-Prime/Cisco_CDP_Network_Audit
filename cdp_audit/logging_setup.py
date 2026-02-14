"""Logging bootstrap for the application."""

import logging
import logging.config
import os
from pathlib import Path

from .app_config import config


def configure_logging() -> None:
    """Configure logging using INI file if available; otherwise use basic logging."""
    cfg_env = os.getenv("LOGGING_CONFIG", "").strip()
    default_cfg = config.LOGGING_CONFIG_PATH
    cfg_path = Path(cfg_env) if cfg_env else default_cfg

    if cfg_path.exists():
        logging.config.fileConfig(str(cfg_path), disable_existing_loggers=False)
        return

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
