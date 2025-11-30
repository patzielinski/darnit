"""darnit - Generic compliance audit framework with plugin architecture.

This framework provides the core infrastructure for running compliance audits
against various standards. Implementations (like darnit-baseline for OpenSSF
Baseline) register via Python entry points.

Usage:
    from darnit.core.discovery import discover_implementations

    implementations = discover_implementations()
    baseline = implementations.get("openssf-baseline")
"""

__version__ = "0.1.0"
