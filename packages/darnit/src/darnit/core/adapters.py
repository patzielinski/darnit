"""Abstract base classes for pluggable check and remediation adapters."""

from abc import ABC, abstractmethod
from typing import Dict, List, Any

from darnit.core.models import (
    CheckResult,
    RemediationResult,
    AdapterCapability,
)


class CheckAdapter(ABC):
    """Base class for check adapters."""

    @abstractmethod
    def name(self) -> str:
        """Return adapter name."""
        pass

    @abstractmethod
    def capabilities(self) -> AdapterCapability:
        """Return what controls this adapter can check."""
        pass

    @abstractmethod
    def check(
        self,
        control_id: str,
        owner: str,
        repo: str,
        local_path: str,
        config: Dict[str, Any]
    ) -> CheckResult:
        """Run check for a specific control."""
        pass

    def check_batch(
        self,
        control_ids: List[str],
        owner: str,
        repo: str,
        local_path: str,
        config: Dict[str, Any]
    ) -> List[CheckResult]:
        """
        Run checks for multiple controls in a single invocation.
        Default implementation calls check() for each control.
        Override for adapters that support batch operations.
        """
        results = []
        for control_id in control_ids:
            results.append(self.check(control_id, owner, repo, local_path, config))
        return results

    def supports_control(self, control_id: str) -> bool:
        """Check if this adapter can handle a specific control."""
        caps = self.capabilities()
        return "*" in caps.control_ids or control_id in caps.control_ids


class RemediationAdapter(ABC):
    """Base class for remediation adapters."""

    @abstractmethod
    def name(self) -> str:
        """Return adapter name."""
        pass

    @abstractmethod
    def capabilities(self) -> AdapterCapability:
        """Return what controls this adapter can remediate."""
        pass

    @abstractmethod
    def remediate(
        self,
        control_id: str,
        owner: str,
        repo: str,
        local_path: str,
        config: Dict[str, Any],
        dry_run: bool = True
    ) -> RemediationResult:
        """Apply remediation for a specific control."""
        pass

    def preview(
        self,
        control_id: str,
        owner: str,
        repo: str,
        local_path: str,
        config: Dict[str, Any]
    ) -> str:
        """Preview what remediation would do (dry run)."""
        result = self.remediate(control_id, owner, repo, local_path, config, dry_run=True)
        return result.message

    def supports_control(self, control_id: str) -> bool:
        """Check if this adapter can handle a specific control."""
        caps = self.capabilities()
        return "*" in caps.control_ids or control_id in caps.control_ids
