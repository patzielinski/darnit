"""Sieve remediation handler for generating dynamic STRIDE threat models.

Uses the tree-sitter discovery pipeline (``ts_discovery.discover_all``)
with optional Opengrep taint enrichment and the new Markdown generator
(``ts_generators.generate_markdown_threat_model``). On pipeline failure,
falls back to the static template content (pre-resolved by the executor).
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from darnit.core.logging import get_logger
from darnit.sieve.handler_registry import (
    HandlerContext,
    HandlerResult,
    HandlerResultStatus,
)

from .discovery_models import FileScanStats
from .ranking import apply_cap, rank_findings
from .ts_discovery import DiscoveryConfig, discover_all
from .ts_generators import generate_markdown_threat_model as ts_generate_markdown

logger = get_logger("threat_model.remediation")


def _empty_scan_stats() -> FileScanStats:
    """A zeroed FileScanStats, used when discovery cannot run at all."""
    return FileScanStats(
        total_files_seen=0,
        excluded_dir_count=0,
        unsupported_file_count=0,
        in_scope_files=0,
        by_language={},
        shallow_mode=False,
        shallow_threshold=500,
    )



@dataclass
class _TsRunOutput:
    """Result of running the new tree-sitter pipeline + markdown generator.

    ``content`` is the rendered Markdown draft. ``evidence`` is the subset
    of fields destined for ``HandlerResult.evidence``. ``failure_reason`` is
    set iff ``content`` is None — callers should fall back to the legacy
    generator.
    """

    content: str | None
    evidence: dict[str, Any]
    failure_reason: str | None


def _run_ts_pipeline(
    local_path: str,
    shallow_threshold: int,
    max_findings: int,
) -> _TsRunOutput:
    """Run the full new pipeline: discovery → ranking → markdown generation.

    Never raises — on any failure returns ``_TsRunOutput(content=None, …)``
    so the handler can fall back to the legacy regex-era generator.
    """
    from dataclasses import asdict as _asdict

    try:
        result = discover_all(
            Path(local_path),
            config=DiscoveryConfig(shallow_threshold=shallow_threshold),
        )
    except Exception as exc:  # noqa: BLE001 — never break the handler
        logger.warning(
            "ts_discovery.discover_all raised (%s); falling back to template",
            exc,
        )
        return _TsRunOutput(
            content=None,
            evidence={
                "file_scan_stats": _asdict(_empty_scan_stats()),
                "entry_point_count": 0,
                "data_store_count": 0,
                "candidate_finding_count": 0,
                "trimmed_overflow": {"by_category": {}, "total": 0},
                "opengrep_available": False,
                "opengrep_degraded_reason": f"ts_discovery failed: {exc}",
            },
            failure_reason=f"ts_discovery: {exc}",
        )

    ranked = rank_findings(result.findings)
    emitted, overflow = apply_cap(ranked, max_findings=max_findings)

    evidence: dict[str, Any] = {
        "file_scan_stats": _asdict(result.file_scan_stats)
        if result.file_scan_stats is not None
        else _asdict(_empty_scan_stats()),
        "entry_point_count": len(result.entry_points),
        "data_store_count": len(result.data_stores),
        "candidate_finding_count": len(emitted),
        "trimmed_overflow": {
            "by_category": {k.value: v for k, v in overflow.by_category.items()},
            "total": overflow.total,
        },
        "opengrep_available": result.opengrep_available,
        "opengrep_degraded_reason": result.opengrep_degraded_reason,
    }

    try:
        content = ts_generate_markdown(
            repo_path=local_path,
            result=result,
            capped_findings=emitted,
            overflow=overflow,
        )
    except Exception as exc:  # noqa: BLE001 — generator must never crash handler
        logger.warning(
            "ts_generators.generate_markdown_threat_model raised (%s); "
            "falling back to legacy generator",
            exc,
        )
        return _TsRunOutput(
            content=None,
            evidence=evidence,
            failure_reason=f"ts_generators: {exc}",
        )

    return _TsRunOutput(content=content, evidence=evidence, failure_reason=None)



def generate_threat_model_handler(
    config: dict[str, Any],
    context: HandlerContext,
) -> HandlerResult:
    """Generate a dynamic STRIDE threat model for remediation.

    Runs the full analysis pipeline (framework detection, asset discovery,
    threat analysis, attack chain detection) and writes a detailed Markdown
    report. Falls back to static template content on analysis failure.

    Config fields:
        path: str - Output file path relative to repository root
        overwrite: bool - Whether to overwrite existing file (default: false)
        content: str - Pre-resolved template content (fallback, provided by executor)

    Context fields:
        local_path: str - Repository root path

    Returns:
        HandlerResult with PASS on success, ERROR on unrecoverable failure.
    """
    path = config.get("path", "")
    if not path:
        return HandlerResult(
            status=HandlerResultStatus.ERROR,
            message="No path specified for threat model generation",
        )

    local_path = context.local_path
    full_path = os.path.join(local_path, path)

    shallow_threshold = int(config.get("shallow_threshold", 500))
    max_findings = int(config.get("max_findings", 50))

    # Respect overwrite flag — skip-if-exists is the conservative default.
    if os.path.exists(full_path) and not config.get("overwrite", False):
        return HandlerResult(
            status=HandlerResultStatus.PASS,
            message=f"Threat model already exists: {path}",
            evidence={
                "path": path,
                "action": "skipped",
                "note": (
                    "Pre-existing threat model preserved. Re-run with "
                    "overwrite=true to regenerate."
                ),
            },
        )

    # The tree-sitter pipeline is the primary draft source.
    # On any failure it produces evidence only and returns content=None,
    # at which point we fall back to the legacy regex-era generator.
    ts_output = _run_ts_pipeline(local_path, shallow_threshold, max_findings)
    ts_evidence = ts_output.evidence

    content: str | None = ts_output.content
    if content is None:
        logger.info(
            "ts_pipeline did not produce content (%s); falling back to template",
            ts_output.failure_reason,
        )
    else:
        # Short-circuit: skip legacy _run_dynamic_analysis entirely. The new
        # generator's output is what users actually see.
        try:
            os.makedirs(os.path.dirname(full_path) or ".", exist_ok=True)
            with open(full_path, "w", encoding="utf-8") as f:
                f.write(content)
        except OSError as e:
            return HandlerResult(
                status=HandlerResultStatus.ERROR,
                message=f"Failed to write threat model: {e}",
                evidence={
                    "path": path,
                    "error": str(e),
                    **ts_evidence,
                },
            )
        return HandlerResult(
            status=HandlerResultStatus.PASS,
            message=(
                f"Generated threat model via tree-sitter pipeline: {path} "
                "— calling agent should verify findings per the embedded "
                "verification prompt block"
            ),
            confidence=1.0,
            evidence={
                "path": path,
                "action": "created",
                "llm_verification_required": True,
                "note": (
                    "Threat model produced by the tree-sitter discovery "
                    "pipeline. Review each finding against its embedded code "
                    "snippet and remove any false positives the calling "
                    "agent judges as non-threats before committing."
                ),
                "generator": "ts_generators",
                **ts_evidence,
            },
        )

    # Template fallback — used when the new pipeline fails entirely.
    fallback_content = config.get("content", "")
    if not fallback_content:
        return HandlerResult(
            status=HandlerResultStatus.ERROR,
            message=(
                f"Tree-sitter pipeline failed ({ts_output.failure_reason}) "
                f"and no template content available"
            ),
            evidence={
                "path": path,
                "error": ts_output.failure_reason or "unknown",
                **ts_evidence,
            },
        )

    try:
        os.makedirs(os.path.dirname(full_path) or ".", exist_ok=True)
        with open(full_path, "w", encoding="utf-8") as f:
            f.write(fallback_content)
    except OSError as write_err:
        return HandlerResult(
            status=HandlerResultStatus.ERROR,
            message=f"Failed to write fallback template: {write_err}",
            evidence={
                "path": path,
                "error": str(write_err),
                **ts_evidence,
            },
        )

    return HandlerResult(
        status=HandlerResultStatus.PASS,
        message=f"Tree-sitter pipeline unavailable — created from template: {path}",
        confidence=1.0,
        evidence={
            "path": path,
            "action": "created_from_template",
            "fallback_reason": ts_output.failure_reason,
            **ts_evidence,
        },
    )


__all__ = [
    "generate_threat_model_handler",
]
