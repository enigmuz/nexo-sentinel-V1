"""Logging configuration for Nexo Sentinel."""

import sys
from pathlib import Path
from loguru import logger

# Remove default handler
logger.remove()

# Create logs directory
logs_dir = Path("logs")
logs_dir.mkdir(exist_ok=True)

# Add console handler (with UTF-8 encoding for Windows compatibility)
import io
_stdout_utf8 = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace", line_buffering=True)

logger.add(
    _stdout_utf8,
    format="<level>{time:YYYY-MM-DD HH:mm:ss}</level> | <level>{level: <8}</level> | <cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - <level>{message}</level>",
    level="INFO",
    colorize=False,
)

# Add file handler
logger.add(
    logs_dir / "nexo_sentinel.log",
    format="{time:YYYY-MM-DD HH:mm:ss} | {level: <8} | {name}:{function}:{line} - {message}",
    level="DEBUG",
    rotation="500 MB",
    retention="7 days"
)

__all__ = ["logger"]
