"""Core utilities for the darnit framework.

This module provides fundamental utilities used across the framework:
- Logging configuration
- Data models
- Common utilities
- Adapter interfaces
"""

from .logging import get_logger
from .models import AuditResult, CheckResult
from .utils import (
    validate_local_path,
    detect_repo_from_git,
    get_git_commit,
    get_git_ref,
    gh_api_safe,
)
from .adapters import (
    CheckAdapter,
    RemediationAdapter,
)
from .plugin import (
    ControlSpec,
    ComplianceImplementation,
)
from .discovery import (
    discover_implementations,
    get_implementation,
    get_default_implementation,
)

__all__ = [
    # Logging
    "get_logger",
    # Models
    "AuditResult",
    "CheckResult",
    # Utils
    "validate_local_path",
    "detect_repo_from_git",
    "get_git_commit",
    "get_git_ref",
    "gh_api_safe",
    # Adapters
    "CheckAdapter",
    "RemediationAdapter",
    # Plugin system
    "ControlSpec",
    "ComplianceImplementation",
    "discover_implementations",
    "get_implementation",
    "get_default_implementation",
]
