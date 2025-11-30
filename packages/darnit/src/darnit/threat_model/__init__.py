"""Threat modeling capabilities using STRIDE methodology.

This module provides automated threat analysis for codebases, including:
- Asset discovery (entry points, auth, data stores, secrets)
- STRIDE-based threat identification
- Risk scoring and prioritization
- Report generation (Markdown, SARIF, JSON)

Usage:
    from darnit.threat_model import (
        discover_all_assets,
        analyze_stride_threats,
        generate_markdown_threat_model,
    )

    # Discover assets
    assets = discover_all_assets("/path/to/repo")

    # Analyze threats
    injection_sinks = discover_injection_sinks("/path/to/repo")
    threats = analyze_stride_threats(assets, injection_sinks)

    # Generate report
    report = generate_markdown_threat_model(
        "/path/to/repo", assets, threats, [], assets.frameworks_detected
    )

Note:
    MCP tool functions (generate_threat_model, analyze_threats, etc.) are
    still in main.py and will be migrated incrementally.
"""

# Data models
from .models import (
    StrideCategory,
    RiskLevel,
    CodeLocation,
    EntryPoint,
    DataStore,
    SensitiveData,
    SecretReference,
    AuthMechanism,
    RiskScore,
    Threat,
    AssetInventory,
    ThreatAnalysis,
)

# Detection patterns
from .patterns import (
    FRAMEWORK_PATTERNS,
    AUTH_PATTERNS,
    SENSITIVE_DATA_PATTERNS,
    INJECTION_PATTERNS,
    SECRET_PATTERNS,
    DATASTORE_PATTERNS,
    SKIP_DIRECTORIES,
    SOURCE_EXTENSIONS,
)

# Discovery functions
from .discovery import (
    detect_frameworks,
    discover_entry_points,
    discover_authentication,
    discover_sensitive_data,
    discover_secrets,
    discover_data_stores,
    discover_injection_sinks,
    discover_all_assets,
)

# STRIDE analysis
from .stride import (
    calculate_risk_score,
    analyze_stride_threats,
    identify_control_gaps,
)

# Output generators
from .generators import (
    generate_markdown_threat_model,
    generate_sarif_threat_model,
    generate_json_summary,
)

__all__ = [
    # Enums
    "StrideCategory",
    "RiskLevel",
    # Data classes
    "CodeLocation",
    "EntryPoint",
    "DataStore",
    "SensitiveData",
    "SecretReference",
    "AuthMechanism",
    "RiskScore",
    "Threat",
    "AssetInventory",
    "ThreatAnalysis",
    # Patterns
    "FRAMEWORK_PATTERNS",
    "AUTH_PATTERNS",
    "SENSITIVE_DATA_PATTERNS",
    "INJECTION_PATTERNS",
    "SECRET_PATTERNS",
    "DATASTORE_PATTERNS",
    "SKIP_DIRECTORIES",
    "SOURCE_EXTENSIONS",
    # Discovery
    "detect_frameworks",
    "discover_entry_points",
    "discover_authentication",
    "discover_sensitive_data",
    "discover_secrets",
    "discover_data_stores",
    "discover_injection_sinks",
    "discover_all_assets",
    # Analysis
    "calculate_risk_score",
    "analyze_stride_threats",
    "identify_control_gaps",
    # Generators
    "generate_markdown_threat_model",
    "generate_sarif_threat_model",
    "generate_json_summary",
]
