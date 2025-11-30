"""Remediation infrastructure for darnit framework.

This module provides generic remediation utilities:
- Helper functions for file operations and detection
- GitHub API integration for repository configuration

Implementation-specific remediations (like OSPS orchestrator and actions)
should be in the respective implementation packages.
"""

from .helpers import (
    ensure_directory,
    write_file_safe,
    check_file_exists,
    get_repo_maintainers,
    detect_workflow_checks,
    format_success,
    format_error,
    format_warning,
)
from .github import (
    enable_branch_protection,
)

__all__ = [
    # Helpers
    "ensure_directory",
    "write_file_safe",
    "check_file_exists",
    "get_repo_maintainers",
    "detect_workflow_checks",
    "format_success",
    "format_error",
    "format_warning",
    # GitHub
    "enable_branch_protection",
]
