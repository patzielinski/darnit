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

from .discovery_models import CandidateFinding, FileScanStats
from .ranking import rank_findings
from .ts_discovery import DiscoveryConfig, discover_all
from .ts_generators import (
    _severity_band,
)
from .ts_generators import (
    generate_markdown_threat_model as ts_generate_markdown,
)

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
    of fields destined for ``HandlerResult.evidence``. ``findings`` is the
    ranked finding list for building LLM consultation payloads.
    ``failure_reason`` is set iff ``content`` is None — callers should fall
    back to the legacy generator.
    """

    content: str | None
    evidence: dict[str, Any]
    findings: list[CandidateFinding]
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
                "opengrep_available": False,
                "opengrep_degraded_reason": f"ts_discovery failed: {exc}",
            },
            findings=[],
            failure_reason=f"ts_discovery: {exc}",
        )

    ranked = rank_findings(result.findings)

    evidence: dict[str, Any] = {
        "file_scan_stats": _asdict(result.file_scan_stats)
        if result.file_scan_stats is not None
        else _asdict(_empty_scan_stats()),
        "entry_point_count": len(result.entry_points),
        "data_store_count": len(result.data_stores),
        "candidate_finding_count": len(ranked),
        "opengrep_available": result.opengrep_available,
        "opengrep_degraded_reason": result.opengrep_degraded_reason,
    }

    try:
        content = ts_generate_markdown(
            repo_path=local_path,
            result=result,
            capped_findings=ranked,
            overflow=None,
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
            findings=ranked,
            failure_reason=f"ts_generators: {exc}",
        )

    return _TsRunOutput(
        content=content, evidence=evidence, findings=ranked, failure_reason=None
    )


def _build_llm_consultation(
    findings: list[CandidateFinding],
    path: str,
) -> dict[str, Any]:
    """Build an LLM consultation payload for threat model verification.

    Returns a structured dict that the calling agent can use to review
    each finding and refine the generated threat model. The agent is
    expected to:

    1. Read the generated file at ``path``
    2. For each finding in ``findings_to_review``, judge whether it is
       a true positive or false positive based on the code snippet
    3. For true positives, optionally enrich the rationale with
       project-specific context
    4. Remove false positives from the file
    5. Commit the refined file
    """
    review_items: list[dict[str, Any]] = []
    for f in findings:
        band = _severity_band(f.severity, f.confidence)
        item: dict[str, Any] = {
            "title": f.title,
            "category": f.category.value,
            "severity_band": band,
            "score": round(f.severity * f.confidence, 2),
            "location": f"{f.primary_location.file}:{f.primary_location.line}",
            "rationale": f.rationale,
            "source": f.source.value,
            "query_id": f.query_id,
        }
        if f.code_snippet:
            marker_idx = f.code_snippet.marker_line - f.code_snippet.start_line
            if 0 <= marker_idx < len(f.code_snippet.lines):
                item["anchor_line"] = f.code_snippet.lines[marker_idx]

        # Per-finding review guidance based on category and confidence
        if band == "LOW":
            item["review_hint"] = (
                "LOW-risk finding — likely noise without taint analysis. "
                "Verify briefly; remove if the code path is internal-only."
            )
        elif f.confidence < 0.5:
            item["review_hint"] = (
                "Low-confidence structural match. Check whether external "
                "input actually reaches this code path."
            )
        else:
            item["review_hint"] = (
                "Review the code snippet. Does the described threat apply "
                "given this project's architecture? If yes, consider adding "
                "project-specific context (e.g., which callers reach this "
                "sink, what data flows through it, what mitigations exist)."
            )

        review_items.append(item)

    # Summary stats for the agent
    from collections import Counter

    band_counts = Counter(i["severity_band"] for i in review_items)
    category_counts = Counter(i["category"] for i in review_items)

    return {
        "action": "review_threat_model",
        "file_path": path,
        "total_findings": len(review_items),
        "summary": {
            "by_severity": dict(band_counts),
            "by_category": dict(category_counts),
        },
        "instructions": (
            "The threat model at the file path above was generated by "
            "darnit's tree-sitter structural analysis pipeline. Review "
            "the findings below. For each finding:\n"
            "1. Read the code at the indicated location\n"
            "2. Judge: TRUE POSITIVE (real threat) or FALSE POSITIVE "
            "(not a real threat in this project's context)\n"
            "3. For true positives: enrich the finding's narrative in "
            "the file with project-specific details (which callers "
            "reach this code, what data flows through, existing "
            "mitigations)\n"
            "4. For false positives: remove the finding from the file\n"
            "5. After reviewing all findings, commit the refined file"
        ),
        "findings_to_review": review_items,
    }


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
        consultation = _build_llm_consultation(ts_output.findings, path)
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
                "llm_consultation": consultation,
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
