"""Configuration management for darnit framework.

This module provides configuration loading and management for .project.yaml
files following the CNCF .project specification with OpenSSF Baseline extension.
"""

from .schema import (
    # Enums
    ProjectType,
    ControlStatusValue,
    ContributorAgreementType,
    SBOMFormat,
    SigningMethod,
    ProvenanceFormat,
    # Reference types
    PathRef,
    UrlRef,
    RepoRef,
    SectionRef,
    NARef,
    ResourceRef,
    parse_resource_ref,
    get_path_from_ref,
    # CNCF standard
    MaturityEntry,
    Audit,
    SecurityConfig,
    GovernanceConfig,
    LegalConfig,
    DocumentationConfig,
    # Baseline extension
    ControlOverride,
    ArtifactConfig,
    ContributorAgreementConfig,
    CIConfig,
    ProjectContext,
    ExtendedGovernance,
    ExtendedQuality,
    ExtendedSecurity,
    ExtendedLegal,
    DependenciesConfig,
    ArtifactsConfig,
    BaselineExtension,
    # Main config
    ProjectConfig,
    # Factory functions
    create_minimal_config,
    create_full_config,
)

from .loader import (
    # Core functions
    load_project_config,
    save_project_config,
    get_project_config,
    init_project_config,
    config_exists,
    get_config_path,
    get_extension_path,
    list_extension_files,
    clear_config_cache,
    # Extension registry
    ExtensionSpec,
    EXTENSION_REGISTRY,
    get_extension_by_key,
    get_default_extension,
    # Constants
    PROJECT_DIR,
    PROJECT_FILE,
    EXTENSION_FILE,
    CNCF_STANDARD_FIELDS,
)

from .discovery import (
    discover_files,
    discover_ci_config,
    discover_project_name,
    sync_discovered_to_config,
)

# Legacy exports (deprecated)
from .models import (
    ReferenceStatus,
    ResourceReference,
    ControlStatus,
)

__all__ = [
    # Enums
    "ProjectType",
    "ControlStatusValue",
    "ContributorAgreementType",
    "SBOMFormat",
    "SigningMethod",
    "ProvenanceFormat",
    # Reference types
    "PathRef",
    "UrlRef",
    "RepoRef",
    "SectionRef",
    "NARef",
    "ResourceRef",
    "parse_resource_ref",
    "get_path_from_ref",
    # CNCF standard
    "MaturityEntry",
    "Audit",
    "SecurityConfig",
    "GovernanceConfig",
    "LegalConfig",
    "DocumentationConfig",
    # Baseline extension
    "ControlOverride",
    "ArtifactConfig",
    "ContributorAgreementConfig",
    "CIConfig",
    "ProjectContext",
    "ExtendedGovernance",
    "ExtendedQuality",
    "ExtendedSecurity",
    "ExtendedLegal",
    "DependenciesConfig",
    "ArtifactsConfig",
    "BaselineExtension",
    # Main config
    "ProjectConfig",
    # Factory functions
    "create_minimal_config",
    "create_full_config",
    # Loader - core
    "load_project_config",
    "save_project_config",
    "get_project_config",
    "init_project_config",
    "config_exists",
    "get_config_path",
    "get_extension_path",
    "list_extension_files",
    "clear_config_cache",
    # Loader - extension registry
    "ExtensionSpec",
    "EXTENSION_REGISTRY",
    "get_extension_by_key",
    "get_default_extension",
    # Loader - constants
    "PROJECT_DIR",
    "PROJECT_FILE",
    "EXTENSION_FILE",
    "CNCF_STANDARD_FIELDS",
    # Discovery
    "discover_files",
    "discover_ci_config",
    "discover_project_name",
    "sync_discovered_to_config",
    # Legacy (deprecated)
    "ReferenceStatus",
    "ResourceReference",
    "ControlStatus",
]
