"""Logging utilities for darnit.

This module provides a centralized logging configuration for the darnit
framework. By default, logs are silent (NullHandler) to avoid spamming users.
Users can configure logging by getting the 'darnit' logger and adding
their own handlers.

Example:
    import logging
    logging.getLogger("darnit").setLevel(logging.DEBUG)
    logging.getLogger("darnit").addHandler(logging.StreamHandler())
"""

import logging
from typing import Optional

# Package-level logger - silent by default (NullHandler)
_logger: Optional[logging.Logger] = None


def get_logger(name: str = "") -> logging.Logger:
    """Get a logger for the darnit package.

    Args:
        name: Optional submodule name (e.g., "utils", "sieve").
              If provided, returns a child logger like "darnit.utils".

    Returns:
        Logger instance. Silent by default unless the user configures handlers.
    """
    global _logger
    if _logger is None:
        _logger = logging.getLogger("darnit")
        _logger.addHandler(logging.NullHandler())  # Silent by default

    if name:
        return _logger.getChild(name)
    return _logger


__all__ = ["get_logger"]
