"""Plugin system for darnit compliance implementations.

This module defines the protocol that compliance implementations must follow
to be discovered and used by the darnit framework.

Implementations register via Python entry points under 'darnit.implementations'.
"""

from typing import Protocol, List, Dict, Any, Optional, runtime_checkable
from dataclasses import dataclass


@dataclass
class ControlSpec:
    """Specification for a compliance control.

    This is a framework-level definition that implementations provide.
    """
    control_id: str
    name: str
    description: str
    level: int
    domain: str
    metadata: Dict[str, Any]


@runtime_checkable
class ComplianceImplementation(Protocol):
    """Protocol for compliance check implementations.

    Implementations must provide this interface to be discoverable
    by the darnit framework.

    Example:
        class OSPSBaselineImplementation:
            name = "openssf-baseline"
            display_name = "OpenSSF Baseline"
            version = "0.1.0"
            spec_version = "OSPS v2025.10.10"

            def get_all_controls(self) -> List[ControlSpec]:
                ...
    """

    @property
    def name(self) -> str:
        """Unique identifier for this implementation (e.g., 'openssf-baseline')."""
        ...

    @property
    def display_name(self) -> str:
        """Human-readable name (e.g., 'OpenSSF Baseline')."""
        ...

    @property
    def version(self) -> str:
        """Implementation version (e.g., '0.1.0')."""
        ...

    @property
    def spec_version(self) -> str:
        """Specification version this implements (e.g., 'OSPS v2025.10.10')."""
        ...

    def get_all_controls(self) -> List[ControlSpec]:
        """Get all controls defined by this implementation."""
        ...

    def get_controls_by_level(self, level: int) -> List[ControlSpec]:
        """Get controls for a specific maturity level."""
        ...

    def get_check_functions(self) -> Dict[str, Any]:
        """Get the check functions for running audits.

        Returns:
            Dict with 'level1', 'level2', 'level3' keys mapping to check functions.
        """
        ...

    def get_rules_catalog(self) -> Dict[str, Any]:
        """Get the rules catalog for SARIF output."""
        ...

    def get_remediation_registry(self) -> Dict[str, Any]:
        """Get the remediation registry for auto-fixes."""
        ...


__all__ = [
    "ControlSpec",
    "ComplianceImplementation",
]
