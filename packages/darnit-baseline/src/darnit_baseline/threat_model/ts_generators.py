"""Output generators for the tree-sitter discovery pipeline.

Produces the three required output formats (Markdown, SARIF 2.1.0, JSON)
from a :class:`DiscoveryResult` + a ranked-and-capped list of
:class:`CandidateFinding`. The Markdown draft follows the structural
contract documented in
``specs/010-threat-model-ast/contracts/output-format-contract.md``:

1. ``# Threat Model Report``
2. ``## Executive Summary``
3. ``## Asset Inventory``
4. ``## Data Flow Diagram``
5. ``## STRIDE Threats``
6. ``## Attack Chains``
7. ``## Recommendations Summary``
8. ``## Verification Prompts``  (wrapped in ``<!-- darnit:verification-prompt-block -->``)
9. ``## Limitations``

Replaces the legacy ``generators.generate_markdown_threat_model`` as the
primary output generator for the threat model handler.
"""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from .discovery_models import (
    CandidateFinding,
    DiscoveredDataStore,
    DiscoveredEntryPoint,
    DiscoveryResult,
    TrimmedOverflow,
)
from .models import StrideCategory

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

VERIFICATION_PROMPT_OPEN = "<!-- darnit:verification-prompt-block -->"
VERIFICATION_PROMPT_CLOSE = "<!-- /darnit:verification-prompt-block -->"


@dataclass(frozen=True)
class GeneratorOptions:
    """Tunables passed to the Markdown / SARIF / JSON emitters."""

    detail_level: str = "detailed"  # "detailed" | "summary"
    max_dfd_nodes: int = 50


# ---------------------------------------------------------------------------
# STRIDE category ordering & titles
# ---------------------------------------------------------------------------

_STRIDE_ORDER: tuple[StrideCategory, ...] = (
    StrideCategory.SPOOFING,
    StrideCategory.TAMPERING,
    StrideCategory.REPUDIATION,
    StrideCategory.INFORMATION_DISCLOSURE,
    StrideCategory.DENIAL_OF_SERVICE,
    StrideCategory.ELEVATION_OF_PRIVILEGE,
)

_STRIDE_HEADINGS: dict[StrideCategory, str] = {
    StrideCategory.SPOOFING: "Spoofing",
    StrideCategory.TAMPERING: "Tampering",
    StrideCategory.REPUDIATION: "Repudiation",
    StrideCategory.INFORMATION_DISCLOSURE: "Information Disclosure",
    StrideCategory.DENIAL_OF_SERVICE: "Denial of Service",
    StrideCategory.ELEVATION_OF_PRIVILEGE: "Elevation of Privilege",
}

_STRIDE_ABBREV: dict[StrideCategory, str] = {
    StrideCategory.SPOOFING: "S",
    StrideCategory.TAMPERING: "T",
    StrideCategory.REPUDIATION: "R",
    StrideCategory.INFORMATION_DISCLOSURE: "I",
    StrideCategory.DENIAL_OF_SERVICE: "D",
    StrideCategory.ELEVATION_OF_PRIVILEGE: "E",
}


def _severity_band(severity: int, confidence: float) -> str:
    """Map ``severity × confidence`` to a human-readable band."""
    score = severity * confidence
    if score >= 7.0:
        return "CRITICAL"
    if score >= 4.5:
        return "HIGH"
    if score >= 2.0:
        return "MEDIUM"
    return "LOW"


def _risk_counts(findings: list[CandidateFinding]) -> dict[str, int]:
    counts: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        band = _severity_band(f.severity, f.confidence)
        counts[band] += 1
    return counts


# ---------------------------------------------------------------------------
# Per-section renderers
# ---------------------------------------------------------------------------


def _render_executive_summary(
    repo_path: str,
    result: DiscoveryResult,
    findings: list[CandidateFinding],
) -> list[str]:
    md: list[str] = ["## Executive Summary", ""]

    languages = ", ".join(sorted((result.file_scan_stats.by_language or {}).keys()))
    frameworks = ", ".join(
        sorted({ep.framework for ep in result.entry_points if ep.framework})
    )
    md.append(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    md.append(f"**Repository:** `{repo_path}`")
    md.append(f"**Languages scanned:** {languages or 'none'}")
    md.append(f"**Frameworks detected:** {frameworks or 'none'}")
    md.append("")

    counts = _risk_counts(findings)
    if counts["CRITICAL"] > 0:
        md.append(
            f"⚠️ **{counts['CRITICAL']} CRITICAL** findings require "
            f"immediate attention."
        )
    elif counts["HIGH"] > 0:
        md.append(f"🔴 **{counts['HIGH']} HIGH** severity findings identified.")
    elif counts["MEDIUM"] > 0:
        md.append(
            f"🟡 **{counts['MEDIUM']} MEDIUM** severity findings should be "
            f"reviewed."
        )
    else:
        md.append(
            "🟢 No high-severity findings detected by the structural pipeline. "
            "Review the Limitations section for scope caveats."
        )
    md.append("")

    md.append("| Risk Level | Count |")
    md.append("|------------|-------|")
    md.append(f"| 🔴 Critical | {counts['CRITICAL']} |")
    md.append(f"| 🟠 High | {counts['HIGH']} |")
    md.append(f"| 🟡 Medium | {counts['MEDIUM']} |")
    md.append(f"| 🟢 Low | {counts['LOW']} |")
    md.append(f"| ℹ️ Info | {counts['INFO']} |")
    md.append("")
    return md


def _render_asset_inventory(result: DiscoveryResult) -> list[str]:
    md: list[str] = ["## Asset Inventory", ""]

    # Entry Points
    md.append("### Entry Points")
    md.append("")
    if result.entry_points:
        md.append("| Kind | Framework | Method | Path / Name | Location |")
        md.append("|------|-----------|--------|-------------|----------|")
        for ep in result.entry_points[:30]:
            path_or_name = ep.route_path or ep.name
            md.append(
                f"| {ep.kind.value} | {ep.framework or '—'} | "
                f"{ep.http_method or '—'} | `{path_or_name}` | "
                f"`{ep.location.file}:{ep.location.line}` |"
            )
        if len(result.entry_points) > 30:
            md.append(
                f"| … | | | | *{len(result.entry_points) - 30} more entries not shown* |"
            )
    else:
        if result.file_scan_stats.in_scope_files > 50:
            md.append(
                f"⚠️ No entry points detected in a repository with "
                f"{result.file_scan_stats.in_scope_files} source files. "
                f"This likely indicates missing query coverage for the "
                f"project's framework or registration pattern. Review the "
                f"Limitations section."
            )
        else:
            md.append(
                "No HTTP route handlers, CLI commands, or MCP tool endpoints detected."
            )
    md.append("")

    # Data Stores
    md.append("### Data Stores")
    md.append("")
    if result.data_stores:
        md.append("| Technology | Kind | Import Evidence | Location |")
        md.append("|------------|------|-----------------|----------|")
        for ds in result.data_stores[:30]:
            evidence = ds.import_evidence or ds.dependency_manifest_evidence or "—"
            md.append(
                f"| {ds.technology} | {ds.kind.value} | `{evidence}` | "
                f"`{ds.location.file}:{ds.location.line}` |"
            )
    else:
        md.append("No data stores detected.")
    md.append("")

    # Authentication Mechanisms
    md.append("### Authentication Mechanisms")
    md.append("")
    auth_entries = [ep for ep in result.entry_points if ep.has_auth_decorator]
    if auth_entries:
        for ep in auth_entries:
            md.append(
                f"- `{ep.name}` at `{ep.location.file}:{ep.location.line}` "
                f"({ep.framework or 'unknown framework'})"
            )
    else:
        md.append(
            "⚠️ No authentication decorators identified by the structural "
            "pipeline. This does NOT mean the application is unauthenticated — "
            "it means no recognized decorator pattern was found. Review the "
            "entry points above manually."
        )
    md.append("")
    return md


def _render_dfd(result: DiscoveryResult, options: GeneratorOptions) -> list[str]:
    md: list[str] = ["## Data Flow Diagram", ""]

    stats = result.file_scan_stats
    if stats is not None and stats.shallow_mode:
        md.append(
            "Data flow diagram omitted in shallow analysis mode. "
            "Re-run with a smaller in-scope file set for the full DFD."
        )
        md.append("")
        return md

    if not result.entry_points and not result.data_stores:
        md.append("No assets discovered; data flow diagram empty.")
        md.append("")
        return md

    md.append("```mermaid")
    md.append("flowchart LR")
    md.append('    User(["External Actor"])')

    # Entry point nodes — cap at max_dfd_nodes to keep the diagram readable
    ep_nodes: list[tuple[str, DiscoveredEntryPoint]] = []
    for idx, ep in enumerate(result.entry_points[: options.max_dfd_nodes]):
        node_id = f"EP{idx}"
        label = ep.route_path or ep.name or ep.kind.value
        # Strip characters Mermaid mis-parses
        label_clean = label.replace('"', "'").replace("`", "'")
        md.append(f'    {node_id}["{label_clean}"]')
        ep_nodes.append((node_id, ep))

    # Data store nodes
    ds_nodes: list[tuple[str, DiscoveredDataStore]] = []
    if result.data_stores:
        md.append("    subgraph DataLayer[\"Data Layer\"]")
        for idx, ds in enumerate(result.data_stores[: options.max_dfd_nodes]):
            node_id = f"DS{idx}"
            md.append(f'        {node_id}[("{ds.technology}")]')
            ds_nodes.append((node_id, ds))
        md.append("    end")

    # Edges: User → every entry point
    for node_id, _ep in ep_nodes:
        md.append(f"    User --> {node_id}")

    # Edges: each entry point → data stores. Try locality heuristic first
    # (same file); if that produces zero edges, fall back to connecting
    # every entry point to every data store (the application uses all
    # stores; we just can't tell which routes access which from
    # structural analysis alone without cross-file call-graph resolution).
    locality_edges: list[str] = []
    for ep_id, ep in ep_nodes:
        ep_file = ep.location.file
        for ds_id, ds in ds_nodes:
            if ds.location.file == ep_file:
                locality_edges.append(f"    {ep_id} --> {ds_id}")

    if locality_edges:
        md.extend(locality_edges)
    elif ds_nodes:
        # No same-file locality; connect every EP to every DS as a
        # "this application uses these stores" approximation.
        for ep_id, _ep in ep_nodes:
            for ds_id, _ds in ds_nodes:
                md.append(f"    {ep_id} --> {ds_id}")

    md.append("```")
    md.append("")

    total_nodes = len(result.entry_points) + len(result.data_stores)
    if total_nodes > options.max_dfd_nodes:
        md.append(
            f"*DFD simplified: only the top {options.max_dfd_nodes} nodes are "
            f"shown (total asset count: {total_nodes}).*"
        )
        md.append("")
    return md


def _render_finding(finding: CandidateFinding, index: int) -> list[str]:
    abbrev = _STRIDE_ABBREV[finding.category]
    heading = (
        f"#### TM-{abbrev}-{index:03d}: {finding.title}"
    )
    band = _severity_band(finding.severity, finding.confidence)
    md: list[str] = [heading, ""]
    md.append(
        f"**Risk:** {band} (severity × confidence = "
        f"{finding.severity * finding.confidence:.2f})"
    )
    md.append(
        f"**Location:** `{finding.primary_location.file}:"
        f"{finding.primary_location.line}`"
    )
    md.append(f"**Source:** `{finding.source.value}` — query `{finding.query_id}`")
    if finding.enclosing_function:
        md.append(f"**Enclosing function:** `{finding.enclosing_function}`")
    md.append("")
    md.append(finding.rationale)
    md.append("")

    # Code snippet block with >>> marker
    md.append("```")
    snippet = finding.code_snippet
    for offset, line in enumerate(snippet.lines):
        line_no = snippet.start_line + offset
        prefix = ">>> " if line_no == snippet.marker_line else "    "
        md.append(f"{prefix}{line_no:4d} | {line}")
    md.append("```")
    md.append("")

    # Optional data-flow trace for taint findings
    if finding.data_flow is not None:
        md.append("**Data Flow Trace:**")
        md.append("")
        md.append("```")
        md.append(
            f">>> source at line {finding.data_flow.source.location.line}: "
            f"{finding.data_flow.source.content}"
        )
        for step in finding.data_flow.intermediate:
            md.append(
                f"    step   at line {step.location.line}: {step.content}"
            )
        md.append(
            f">>> sink   at line {finding.data_flow.sink.location.line}: "
            f"{finding.data_flow.sink.content}"
        )
        md.append("```")
        md.append("")

    return md


def _render_stride_threats(findings: list[CandidateFinding]) -> list[str]:
    md: list[str] = ["## STRIDE Threats", ""]
    by_category: dict[StrideCategory, list[CandidateFinding]] = defaultdict(list)
    for f in findings:
        by_category[f.category].append(f)

    # Per-category counters for stable TM-X-NNN ids
    counter: Counter[StrideCategory] = Counter()
    for cat in _STRIDE_ORDER:
        md.append(f"### {_STRIDE_HEADINGS[cat]}")
        md.append("")
        cat_findings = by_category.get(cat, [])
        if not cat_findings:
            md.append("No threats identified in this category.")
            md.append("")
            continue
        for f in cat_findings:
            counter[cat] += 1
            md.extend(_render_finding(f, counter[cat]))
    return md


def _render_attack_chains(result: DiscoveryResult) -> list[str]:
    md: list[str] = ["## Attack Chains", ""]
    stats = result.file_scan_stats
    if stats is not None and stats.shallow_mode:
        md.append(
            "Attack chain detection skipped in shallow analysis mode. "
            "Re-run with a smaller in-scope file set to compute chains."
        )
        md.append("")
        return md
    # Attack chain detection across the structural discovery pipeline is
    # a future enhancement. For now we report honestly that no chains
    # were computed rather than emitting phantom chains.
    md.append("No compound attack paths identified.")
    md.append("")
    return md


def _render_recommendations(findings: list[CandidateFinding]) -> list[str]:
    md: list[str] = ["## Recommendations Summary", ""]

    immediate = [
        f for f in findings if _severity_band(f.severity, f.confidence) in ("CRITICAL", "HIGH")
    ]
    short_term = [
        f for f in findings if _severity_band(f.severity, f.confidence) == "MEDIUM"
    ]

    md.append("### Immediate Actions (Critical / High)")
    md.append("")
    if immediate:
        for i, f in enumerate(immediate, start=1):
            md.append(
                f"{i}. **{f.title}** — `{f.primary_location.file}:"
                f"{f.primary_location.line}`"
            )
    else:
        md.append("No critical or high severity findings.")
    md.append("")

    md.append("### Short-term Actions (Medium)")
    md.append("")
    if short_term:
        for i, f in enumerate(short_term, start=1):
            md.append(
                f"{i}. **{f.title}** — `{f.primary_location.file}:"
                f"{f.primary_location.line}`"
            )
    else:
        md.append("No medium severity findings.")
    md.append("")

    return md


def _render_verification_prompts() -> list[str]:
    md: list[str] = ["## Verification Prompts", ""]
    md.append(VERIFICATION_PROMPT_OPEN)
    md.append("")
    md.append(
        "**For the calling agent (Claude via MCP):** this draft was produced "
        "by the darnit tree-sitter discovery pipeline. Before committing, "
        "follow these steps for each finding listed above:"
    )
    md.append("")
    md.append(
        "1. Read the embedded code snippet. The line prefixed with `>>>` is "
        "the anchor line for the finding."
    )
    md.append(
        "2. Ask: does the code at this location plausibly exhibit the "
        "described threat? If not, remove the finding entirely from the "
        "committed file."
    )
    md.append(
        "3. For findings you keep, refine the narrative with project-specific "
        "details where helpful (which caller reaches this sink, what data "
        "flows through it, etc.)."
    )
    md.append(
        "4. Preserve the STRIDE category headings even when their content "
        "changes. Downstream consumers parse H2 headers from this document."
    )
    md.append(
        "5. Preserve this `darnit:verification-prompt-block` section — it "
        "marks the draft as having gone through review. Once every finding "
        "has been verified or removed, commit the file through the normal "
        "`darnit-remediate` skill flow."
    )
    md.append("")
    md.append(
        "*Findings marked with Risk LOW or MEDIUM are often noise in the "
        "absence of taint analysis. The draft caps the top 50 findings by "
        "severity × confidence; see Limitations for what was trimmed.*"
    )
    md.append("")
    md.append(VERIFICATION_PROMPT_CLOSE)
    md.append("")
    return md


def _render_limitations(
    result: DiscoveryResult, overflow: TrimmedOverflow | None
) -> list[str]:
    md: list[str] = ["## Limitations", ""]
    stats = result.file_scan_stats

    if stats is not None:
        by_lang = ", ".join(
            f"{lang}={count}" for lang, count in sorted(stats.by_language.items())
        )
        md.append(
            f"- Scanned **{stats.in_scope_files}** in-scope files "
            f"({by_lang or 'none'})."
        )
        md.append(
            f"- Skipped **{stats.excluded_dir_count}** vendor/build directories "
            f"and **{stats.unsupported_file_count}** files in unsupported languages."
        )
        if stats.shallow_mode:
            md.append(
                f"- **Shallow analysis mode** was active because the in-scope "
                f"file count exceeded the threshold ({stats.shallow_threshold}). "
                f"The following analyses were reduced or skipped: "
                f"injection-sink queries, call-graph extraction, attack-chain "
                f"computation, and the full DFD. Re-run with a narrower scope "
                f"for the complete analysis."
            )

    md.append(
        f"- Opengrep taint analysis: "
        f"{'available' if result.opengrep_available else 'not available'}."
    )
    if result.opengrep_degraded_reason:
        md.append(f"  - Reason: {result.opengrep_degraded_reason}")
    if not result.opengrep_available:
        md.append(
            "- Without Opengrep, findings for dangerous sinks (subprocess, "
            "eval, etc.) are emitted at low confidence because we cannot "
            "confirm external input reaches the sink. Many such findings are "
            "filtered by the literal-list safety check or deprioritized by "
            "the top-N cap. Install Opengrep for higher-confidence taint "
            "findings."
        )

    if overflow is not None and overflow.total > 0:
        md.append("")
        md.append(
            f"- **{overflow.total}** additional candidate findings were trimmed "
            f"to fit the draft's finding cap:"
        )
        for cat, count in overflow.by_category.items():
            if count > 0:
                md.append(f"  - {_STRIDE_HEADINGS[cat]}: {count} trimmed")
        md.append(
            "  - Raise the `max_findings` TOML config on the SA-03.02 "
            "remediation handler to include more findings."
        )

    md.append("")
    md.append(
        "*This is a threat-modeling aid, not an exhaustive vulnerability "
        "scan. Full dynamic and cross-function taint analysis is out of "
        "scope for darnit; use Kusari Inspector or an equivalent SAST tool "
        "for deeper coverage.*"
    )
    md.append("")
    return md


# ---------------------------------------------------------------------------
# Top-level entry points
# ---------------------------------------------------------------------------


def generate_markdown_threat_model(
    repo_path: str,
    result: DiscoveryResult,
    capped_findings: list[CandidateFinding],
    overflow: TrimmedOverflow | None,
    options: GeneratorOptions | None = None,
) -> str:
    """Render the full Markdown draft from a DiscoveryResult.

    Primary markdown generator for the threat model handler.
    """
    options = options or GeneratorOptions()
    md: list[str] = ["# Threat Model Report", ""]
    md.extend(_render_executive_summary(repo_path, result, capped_findings))
    md.extend(_render_asset_inventory(result))
    md.extend(_render_dfd(result, options))
    md.extend(_render_stride_threats(capped_findings))
    md.extend(_render_attack_chains(result))
    md.extend(_render_recommendations(capped_findings))
    md.extend(_render_verification_prompts())
    md.extend(_render_limitations(result, overflow))
    return "\n".join(md) + "\n"


def generate_sarif_threat_model(
    result: DiscoveryResult,
    capped_findings: list[CandidateFinding],
) -> str:
    """Produce a SARIF 2.1.0 document describing the capped findings."""

    rules_index: dict[str, int] = {}
    rules: list[dict[str, Any]] = []

    def _rule_for(finding: CandidateFinding) -> int:
        rule_id = finding.query_id
        if rule_id not in rules_index:
            rules_index[rule_id] = len(rules)
            rules.append(
                {
                    "id": rule_id,
                    "name": rule_id,
                    "shortDescription": {"text": finding.title},
                    "fullDescription": {"text": finding.rationale},
                    "defaultConfiguration": {
                        "level": _sarif_level(finding.severity, finding.confidence)
                    },
                }
            )
        return rules_index[rule_id]

    results: list[dict[str, Any]] = []
    for finding in capped_findings:
        rule_idx = _rule_for(finding)
        entry: dict[str, Any] = {
            "ruleId": finding.query_id,
            "ruleIndex": rule_idx,
            "level": _sarif_level(finding.severity, finding.confidence),
            "message": {"text": finding.title},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": finding.primary_location.file},
                        "region": {
                            "startLine": finding.primary_location.line,
                            "startColumn": finding.primary_location.column,
                            "endLine": finding.primary_location.end_line,
                            "endColumn": finding.primary_location.end_column,
                        },
                        "contextRegion": {
                            "startLine": finding.code_snippet.start_line,
                            "snippet": {
                                "text": "\n".join(finding.code_snippet.lines)
                            },
                        },
                    }
                }
            ],
            "properties": {
                "source": finding.source.value,
                "category": finding.category.value,
                "severity": finding.severity,
                "confidence": finding.confidence,
                "rationale": finding.rationale,
                "enclosingFunction": finding.enclosing_function,
            },
        }
        if finding.data_flow is not None:
            entry["properties"]["dataFlowTrace"] = {
                "source": {
                    "line": finding.data_flow.source.location.line,
                    "content": finding.data_flow.source.content,
                },
                "intermediate": [
                    {"line": s.location.line, "content": s.content}
                    for s in finding.data_flow.intermediate
                ],
                "sink": {
                    "line": finding.data_flow.sink.location.line,
                    "content": finding.data_flow.sink.content,
                },
            }
        results.append(entry)

    sarif = {
        "version": "2.1.0",
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "darnit-baseline",
                        "informationUri": "https://github.com/kusari-oss/darnit",
                        "rules": rules,
                    }
                },
                "results": results,
                "properties": {
                    "fileScanStats": _stats_to_dict(result),
                    "opengrepAvailable": result.opengrep_available,
                    "opengrepDegradedReason": result.opengrep_degraded_reason,
                },
            }
        ],
    }
    return json.dumps(sarif, indent=2)


def _sarif_level(severity: int, confidence: float) -> str:
    score = severity * confidence
    if score >= 7.0:
        return "error"
    if score >= 4.0:
        return "warning"
    return "note"


def generate_json_summary(
    result: DiscoveryResult,
    capped_findings: list[CandidateFinding],
    overflow: TrimmedOverflow | None,
) -> str:
    """Produce a JSON serialization of the full discovery result."""
    payload: dict[str, Any] = {
        "entry_points": [
            {
                "id": ep.id,
                "kind": ep.kind.value,
                "name": ep.name,
                "framework": ep.framework,
                "language": ep.language,
                "route_path": ep.route_path,
                "http_method": ep.http_method,
                "has_auth_decorator": ep.has_auth_decorator,
                "location": {
                    "file": ep.location.file,
                    "line": ep.location.line,
                },
                "source_query": ep.source_query,
            }
            for ep in result.entry_points
        ],
        "data_stores": [
            {
                "id": ds.id,
                "kind": ds.kind.value,
                "technology": ds.technology,
                "language": ds.language,
                "location": {
                    "file": ds.location.file,
                    "line": ds.location.line,
                },
                "import_evidence": ds.import_evidence,
                "dependency_manifest_evidence": ds.dependency_manifest_evidence,
                "source_query": ds.source_query,
            }
            for ds in result.data_stores
        ],
        "findings": [
            {
                "category": f.category.value,
                "title": f.title,
                "source": f.source.value,
                "severity": f.severity,
                "confidence": f.confidence,
                "risk_score": f.severity * f.confidence,
                "location": {
                    "file": f.primary_location.file,
                    "line": f.primary_location.line,
                },
                "query_id": f.query_id,
                "has_data_flow": f.data_flow is not None,
            }
            for f in capped_findings
        ],
        "file_scan_stats": _stats_to_dict(result),
        "trimmed_overflow": (
            {
                "total": overflow.total,
                "by_category": {
                    cat.value: count for cat, count in overflow.by_category.items()
                },
            }
            if overflow is not None
            else {"total": 0, "by_category": {}}
        ),
        "opengrep_available": result.opengrep_available,
        "opengrep_degraded_reason": result.opengrep_degraded_reason,
    }
    return json.dumps(payload, indent=2)


def _stats_to_dict(result: DiscoveryResult) -> dict[str, Any]:
    stats = result.file_scan_stats
    if stats is None:
        return {}
    return {
        "total_files_seen": stats.total_files_seen,
        "excluded_dir_count": stats.excluded_dir_count,
        "unsupported_file_count": stats.unsupported_file_count,
        "in_scope_files": stats.in_scope_files,
        "by_language": dict(stats.by_language),
        "shallow_mode": stats.shallow_mode,
        "shallow_threshold": stats.shallow_threshold,
    }


__all__ = [
    "GeneratorOptions",
    "VERIFICATION_PROMPT_OPEN",
    "VERIFICATION_PROMPT_CLOSE",
    "generate_markdown_threat_model",
    "generate_sarif_threat_model",
    "generate_json_summary",
]
