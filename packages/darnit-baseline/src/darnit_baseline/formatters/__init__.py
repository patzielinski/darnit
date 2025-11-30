"""OSPS-specific output formatters."""

from .sarif import (
    generate_sarif_audit,
    build_sarif_rules,
    result_to_sarif_result,
    get_location_for_control,
)

__all__ = [
    "generate_sarif_audit",
    "build_sarif_rules",
    "result_to_sarif_result",
    "get_location_for_control",
]
