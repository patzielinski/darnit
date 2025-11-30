"""Pydantic models for CNCF .project.yaml schema with OpenSSF Baseline extension.

This module defines the schema for .project.yaml files following the CNCF
.project specification with the x-openssf-baseline extension for compliance
tracking.

Schema Structure:
    - Standard CNCF .project fields (name, description, security, governance, etc.)
    - OpenSSF Baseline extension (x-openssf-baseline) for compliance-specific config

Reference:
    - CNCF .project spec: https://github.com/cncf/automation/tree/main/utilities/dot-project
    - OpenSSF Baseline: https://baseline.openssf.org/
"""

from datetime import date
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from pydantic import BaseModel, ConfigDict, Field, HttpUrl, EmailStr


# =============================================================================
# Enums
# =============================================================================


class ProjectType(str, Enum):
    """Types of projects with different control applicability."""
    SOFTWARE = "software"
    SPECIFICATION = "specification"
    DOCUMENTATION = "documentation"
    INFRASTRUCTURE = "infrastructure"
    DATA = "data"


class ControlStatusValue(str, Enum):
    """Valid status values for control overrides."""
    NA = "n/a"
    ENABLED = "enabled"
    DISABLED = "disabled"


class ContributorAgreementType(str, Enum):
    """Types of contributor agreements."""
    DCO = "dco"
    CLA = "cla"
    NONE = "none"


class SBOMFormat(str, Enum):
    """Supported SBOM formats."""
    CYCLONEDX = "cyclonedx"
    SPDX = "spdx"


class SigningMethod(str, Enum):
    """Supported signing methods."""
    SIGSTORE = "sigstore"
    GPG = "gpg"
    MINISIGN = "minisign"


class ProvenanceFormat(str, Enum):
    """Supported provenance formats."""
    SLSA = "slsa"
    IN_TOTO = "in-toto"


# =============================================================================
# Base Reference Types
# =============================================================================


class PathRef(BaseModel):
    """Reference to a local file path."""
    path: str

    model_config = ConfigDict(extra="forbid")


class UrlRef(BaseModel):
    """Reference to an external URL."""
    url: HttpUrl

    model_config = ConfigDict(extra="forbid")


class RepoRef(BaseModel):
    """Reference to a file in another repository."""
    repo: str  # "owner/repo" format
    path: Optional[str] = None
    ref: Optional[str] = None  # branch, tag, or commit

    model_config = ConfigDict(extra="forbid")


class SectionRef(BaseModel):
    """Reference to a section/heading within another file."""
    section: str  # Format: "section.key#heading" or "path#heading"

    model_config = ConfigDict(extra="forbid")


class NARef(BaseModel):
    """Explicit N/A status for a resource."""
    status: str = "n/a"
    reason: str

    model_config = ConfigDict(extra="forbid")


# Union type for flexible references
ResourceRef = Union[PathRef, UrlRef, RepoRef, SectionRef, NARef, str]


def parse_resource_ref(value: Any) -> Optional[ResourceRef]:
    """Parse a resource reference from YAML data."""
    if value is None:
        return None

    if isinstance(value, str):
        return value  # Simple path string

    if isinstance(value, dict):
        if value.get("status") == "n/a":
            return NARef(**value)
        if "section" in value:
            return SectionRef(**value)
        if "url" in value:
            return UrlRef(**value)
        if "repo" in value:
            return RepoRef(**value)
        if "path" in value:
            return PathRef(**value)

    return None


def get_path_from_ref(ref: Optional[ResourceRef]) -> Optional[str]:
    """Extract path from a resource reference."""
    if ref is None:
        return None
    if isinstance(ref, str):
        return ref
    if isinstance(ref, PathRef):
        return ref.path
    if isinstance(ref, NARef):
        return None  # N/A has no path
    return None


# =============================================================================
# CNCF Standard Schema Components
# =============================================================================


class MaturityEntry(BaseModel):
    """CNCF maturity phase entry."""
    phase: str  # sandbox, incubating, graduated
    date: date
    issue: Optional[str] = None  # URL to maturity issue

    model_config = ConfigDict(extra="forbid")


class Audit(BaseModel):
    """Security or compliance audit record."""
    date: date
    type: str  # security, performance, compliance
    url: str  # URL to audit report

    model_config = ConfigDict(extra="forbid")


class SecurityConfig(BaseModel):
    """Security documentation references (CNCF standard)."""
    policy: Optional[PathRef] = None
    threat_model: Optional[PathRef] = None
    contact: Optional[EmailStr] = None

    model_config = ConfigDict(extra="allow")  # Allow extension fields


class GovernanceConfig(BaseModel):
    """Governance documentation references (CNCF standard)."""
    contributing: Optional[PathRef] = None
    codeowners: Optional[PathRef] = None
    governance_doc: Optional[PathRef] = None
    gitvote_config: Optional[PathRef] = None

    model_config = ConfigDict(extra="allow")  # Allow extension fields


class LegalConfig(BaseModel):
    """Legal documentation references (CNCF standard)."""
    license: Optional[PathRef] = None

    model_config = ConfigDict(extra="allow")  # Allow extension fields


class DocumentationConfig(BaseModel):
    """Project documentation references (CNCF standard)."""
    readme: Optional[PathRef] = None
    support: Optional[PathRef] = None
    architecture: Optional[PathRef] = None
    api: Optional[PathRef] = None

    model_config = ConfigDict(extra="allow")  # Allow extension fields


# =============================================================================
# OpenSSF Baseline Extension Models (x-openssf-baseline)
# =============================================================================


class ControlOverride(BaseModel):
    """Override status for a specific OSPS control."""
    status: ControlStatusValue
    reason: Optional[str] = None

    model_config = ConfigDict(extra="forbid")


class ArtifactConfig(BaseModel):
    """Build artifact configuration."""
    path: Optional[str] = None
    format: Optional[str] = None  # cyclonedx, spdx, slsa
    enabled: Optional[bool] = None
    method: Optional[str] = None  # sigstore, gpg

    model_config = ConfigDict(extra="forbid")


class ContributorAgreementConfig(BaseModel):
    """Contributor licensing configuration."""
    type: ContributorAgreementType
    url: Optional[str] = None

    model_config = ConfigDict(extra="forbid")


class CIConfig(BaseModel):
    """CI/CD configuration references."""
    provider: Optional[str] = None  # github, gitlab, jenkins
    workflows: List[str] = Field(default_factory=list)
    dependency_scanning: Optional[str] = None
    security_scanning: List[str] = Field(default_factory=list)
    testing: List[str] = Field(default_factory=list)
    code_quality: List[str] = Field(default_factory=list)

    model_config = ConfigDict(extra="allow")


class ProjectContext(BaseModel):
    """User-confirmed project context that affects control evaluation."""
    has_subprojects: Optional[bool] = None
    has_releases: Optional[bool] = None
    is_library: Optional[bool] = None
    has_compiled_assets: Optional[bool] = None
    ci_provider: Optional[str] = None

    model_config = ConfigDict(extra="allow")


class ExtendedGovernance(BaseModel):
    """Extended governance fields not in CNCF spec (yet)."""
    maintainers: Optional[PathRef] = None
    code_of_conduct: Optional[PathRef] = None

    model_config = ConfigDict(extra="allow")


class ExtendedQuality(BaseModel):
    """Quality tracking fields."""
    changelog: Optional[PathRef] = None

    model_config = ConfigDict(extra="allow")


class ExtendedSecurity(BaseModel):
    """Extended security fields."""
    advisories: Optional[str] = None  # URL or path
    secrets_policy: Optional[PathRef] = None
    vex_policy: Optional[SectionRef] = None
    sca_policy: Optional[SectionRef] = None
    sast_policy: Optional[SectionRef] = None

    model_config = ConfigDict(extra="allow")


class ExtendedLegal(BaseModel):
    """Extended legal fields."""
    contributor_agreement: Optional[ContributorAgreementConfig] = None

    model_config = ConfigDict(extra="allow")


class DependenciesConfig(BaseModel):
    """Dependency management configuration."""
    lockfile: Optional[str] = None
    manifest: Optional[str] = None
    docs: Optional[str] = None

    model_config = ConfigDict(extra="allow")


class ArtifactsConfig(BaseModel):
    """Build artifacts configuration."""
    sbom: Optional[ArtifactConfig] = None
    signing: Optional[ArtifactConfig] = None
    provenance: Optional[ArtifactConfig] = None

    model_config = ConfigDict(extra="allow")


class BaselineExtension(BaseModel):
    """OpenSSF Baseline extension schema (x-openssf-baseline).

    This extension provides fields for OpenSSF Baseline compliance that are
    not (yet) part of the CNCF .project standard.
    """
    # Extension metadata
    version: str = "1.0"
    osps_version: Optional[str] = None  # e.g., "v2025.10.10"

    # Control overrides - mark controls as N/A with reasoning
    controls: Dict[str, ControlOverride] = Field(default_factory=dict)

    # User-confirmed project context
    context: Optional[ProjectContext] = None

    # Extended fields (to be upstreamed to CNCF)
    governance: Optional[ExtendedGovernance] = None
    quality: Optional[ExtendedQuality] = None
    security: Optional[ExtendedSecurity] = None
    legal: Optional[ExtendedLegal] = None
    artifacts: Optional[ArtifactsConfig] = None
    dependencies: Optional[DependenciesConfig] = None
    ci: Optional[CIConfig] = None

    model_config = ConfigDict(extra="allow")


# =============================================================================
# Main Project Config
# =============================================================================


class ProjectConfig(BaseModel):
    """Complete .project.yaml configuration.

    Combines CNCF standard fields with OpenSSF Baseline extension.

    Example:
        ```yaml
        name: "my-project"
        description: "A project description"
        schema_version: "1.0"
        type: "software"

        security:
          policy:
            path: "SECURITY.md"

        x-openssf-baseline:
          version: "1.0"
          controls:
            OSPS-BR-02.01:
              status: n/a
              reason: "Specification project"
        ```
    """
    # Core metadata (CNCF standard)
    name: str
    description: str = ""
    schema_version: str = "1.0"
    type: str = "software"

    # CNCF-specific metadata
    maturity_log: List[MaturityEntry] = Field(default_factory=list)
    repositories: List[str] = Field(default_factory=list)
    website: Optional[str] = None
    artwork: Optional[str] = None
    social: Dict[str, str] = Field(default_factory=dict)
    mailing_lists: List[str] = Field(default_factory=list)

    # Documentation sections (CNCF standard)
    security: Optional[SecurityConfig] = None
    governance: Optional[GovernanceConfig] = None
    legal: Optional[LegalConfig] = None
    documentation: Optional[DocumentationConfig] = None
    audits: List[Audit] = Field(default_factory=list)

    # OpenSSF Baseline extension
    x_openssf_baseline: Optional[BaselineExtension] = Field(
        default=None,
        alias="x-openssf-baseline"
    )

    # Internal tracking (not serialized)
    config_path: Optional[str] = Field(default=None, exclude=True)
    local_path: Optional[str] = Field(default=None, exclude=True)

    # Project type exclusions (set by implementation)
    _type_exclusions: Dict[str, Set[str]] = {}

    model_config = ConfigDict(
        populate_by_name=True,  # Allow both alias and field name
        extra="allow",  # Allow unknown fields for forward compatibility
    )

    # =========================================================================
    # Convenience Accessors
    # =========================================================================

    def get_extension(self) -> BaselineExtension:
        """Get the baseline extension, creating if needed."""
        if self.x_openssf_baseline is None:
            self.x_openssf_baseline = BaselineExtension()
        return self.x_openssf_baseline

    def get_path(self, section: str, field: str) -> Optional[str]:
        """Get a path reference with extension fallback.

        Resolution order:
        1. Standard .project field (if available)
        2. Extension field (x-openssf-baseline.*)
        3. Returns None if not found

        Args:
            section: Section name (e.g., "security", "governance")
            field: Field name within section (e.g., "policy", "maintainers")

        Returns:
            Path string or None
        """
        # Try standard section first
        std_section = getattr(self, section, None)
        if std_section and isinstance(std_section, BaseModel):
            ref = getattr(std_section, field, None)
            if ref:
                if isinstance(ref, PathRef):
                    return ref.path
                if isinstance(ref, str):
                    return ref

        # Try extension
        if self.x_openssf_baseline:
            ext_section = getattr(self.x_openssf_baseline, section, None)
            if ext_section:
                if isinstance(ext_section, BaseModel):
                    ref = getattr(ext_section, field, None)
                    if ref:
                        if isinstance(ref, PathRef):
                            return ref.path
                        if isinstance(ref, str):
                            return ref
                elif isinstance(ext_section, dict) and field in ext_section:
                    ref = ext_section[field]
                    if isinstance(ref, dict) and "path" in ref:
                        return ref["path"]
                    if isinstance(ref, str):
                        return ref

        return None

    def is_control_applicable(self, control_id: str) -> Tuple[bool, Optional[str]]:
        """Check if control is applicable (not overridden as N/A).

        Args:
            control_id: OSPS control ID (e.g., "OSPS-BR-02.01")

        Returns:
            Tuple of (is_applicable, reason_if_not)
        """
        # Check explicit override first
        if self.x_openssf_baseline:
            override = self.x_openssf_baseline.controls.get(control_id)
            if override and override.status == ControlStatusValue.NA:
                return False, override.reason

        # Check project type exclusions
        exclusions = self._type_exclusions.get(self.type, set())
        for excl in exclusions:
            if control_id.startswith(excl):
                return False, f"Not applicable for {self.type} projects"

        return True, None

    def set_type_exclusions(self, exclusions: Dict[str, Set[str]]):
        """Set project type exclusions from implementation."""
        self._type_exclusions = exclusions

    def get_excluded_controls(self) -> Dict[str, str]:
        """Get all excluded controls with reasons."""
        excluded: Dict[str, str] = {}

        # Add project type exclusions
        type_exclusions = self._type_exclusions.get(self.type, set())
        for excl in type_exclusions:
            excluded[excl] = f"Default exclusion for {self.type} projects"

        # Add explicit overrides
        if self.x_openssf_baseline:
            for control_id, override in self.x_openssf_baseline.controls.items():
                if override.status == ControlStatusValue.NA:
                    excluded[control_id] = override.reason or "Marked as N/A"

        return excluded

    def get_security_contact(self) -> Optional[str]:
        """Get security contact email."""
        if self.security and self.security.contact:
            return str(self.security.contact)
        return None

    def get_audits(self) -> List[Audit]:
        """Get list of audits."""
        return self.audits

    def get_ci_provider(self) -> Optional[str]:
        """Get CI provider name."""
        # Check extension first
        if self.x_openssf_baseline and self.x_openssf_baseline.ci:
            return self.x_openssf_baseline.ci.provider

        # Check context
        if self.x_openssf_baseline and self.x_openssf_baseline.context:
            return self.x_openssf_baseline.context.ci_provider

        return None

    def get_contributor_agreement_type(self) -> Optional[str]:
        """Get contributor agreement type (dco/cla/none)."""
        if self.x_openssf_baseline and self.x_openssf_baseline.legal:
            if self.x_openssf_baseline.legal.contributor_agreement:
                return self.x_openssf_baseline.legal.contributor_agreement.type.value
        return None


# =============================================================================
# Factory Functions
# =============================================================================


def create_minimal_config(
    name: str,
    description: str = "",
    project_type: str = "software"
) -> ProjectConfig:
    """Create a minimal project configuration.

    Args:
        name: Project name
        description: Project description
        project_type: Type of project

    Returns:
        Minimal ProjectConfig instance
    """
    return ProjectConfig(
        name=name,
        description=description,
        type=project_type,
        x_openssf_baseline=BaselineExtension(version="1.0")
    )


def create_full_config(
    name: str,
    description: str = "",
    project_type: str = "software",
    **kwargs: Any
) -> ProjectConfig:
    """Create a full project configuration with all sections.

    Args:
        name: Project name
        description: Project description
        project_type: Type of project
        **kwargs: Additional fields to set

    Returns:
        ProjectConfig instance with all sections initialized
    """
    return ProjectConfig(
        name=name,
        description=description,
        type=project_type,
        security=SecurityConfig(),
        governance=GovernanceConfig(),
        legal=LegalConfig(),
        documentation=DocumentationConfig(),
        x_openssf_baseline=BaselineExtension(
            version="1.0",
            governance=ExtendedGovernance(),
            quality=ExtendedQuality(),
            security=ExtendedSecurity(),
            legal=ExtendedLegal(),
            artifacts=ArtifactsConfig(),
            dependencies=DependenciesConfig(),
            ci=CIConfig(),
        ),
        **kwargs
    )
