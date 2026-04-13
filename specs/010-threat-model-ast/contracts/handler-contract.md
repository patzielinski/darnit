# Contract: Remediation Handler Interface

The contract between the darnit sieve remediation orchestrator and `generate_threat_model_handler`. This is a **preservation contract**: the rewrite must not change what callers observe.

## Function signature

```python
from darnit.sieve.handler_registry import HandlerContext, HandlerResult

def generate_threat_model_handler(
    config: dict[str, Any],
    context: HandlerContext,
) -> HandlerResult: ...
```

Registered via the implementation's `register_handlers()` method under the short name `"generate_threat_model"`, referenced from TOML as:

```toml
[[controls."OSPS-SA-03.02".remediation.handlers]]
handler = "generate_threat_model"
path = "THREAT_MODEL.md"
overwrite = false
# max_findings, snippet_context_lines, shallow_threshold, exclude_dirs — all new, all optional
```

## Input

### `config: dict[str, Any]`

| Key | Type | Default | Required | Notes |
|-----|------|---------|----------|-------|
| `path` | `str` | — | Yes | File path relative to `context.local_path`. Must be one of the paths OSPS-SA-03.02's existence pass checks for the control to pass. |
| `overwrite` | `bool` | `False` | No | When `True`, replace an existing file; when `False` (default), skip writing and return PASS. |
| `content` | `str` | `""` | No | Pre-resolved static template content for fallback path. Passed by the remediation executor; the handler uses this only if dynamic analysis fails. |
| `max_findings` | `int` | `50` | No | Maximum number of ranked findings emitted to the draft. |
| `snippet_context_lines` | `int` | `10` | No | Lines of code context per finding. Automatically reduced to `5` when shallow mode activates. |
| `shallow_threshold` | `int` | `500` | No | In-scope file count above which shallow mode activates. |
| `exclude_dirs` | `list[str]` | `[]` | No | User-supplied directories to exclude in addition to the baseline list. Baseline exclusions cannot be disabled. |

### `context: HandlerContext`

Uses only the existing public fields: `local_path`, `project_context`, `logger`. No new context fields.

## Output

### `HandlerResult`

Returns exactly one `HandlerResult` per invocation. Status is always `PASS` or `ERROR` (never `INCONCLUSIVE` — this is a remediation handler, not a check handler).

**Success (dynamic analysis wrote a new file):**
```python
HandlerResult(
    status=HandlerResultStatus.PASS,
    message=f"Generated threat model: {path}",
    confidence=1.0,
    evidence={
        "path": "THREAT_MODEL.md",
        "action": "created",
        "llm_verification_required": True,
        "note": "<review guidance string>",
        "file_scan_stats": {
            "total_files_seen": 412,
            "excluded_file_count": 87,
            "in_scope_files": 325,
            "by_language": {"python": 210, "typescript": 95, "yaml": 20},
            "shallow_mode": False,
            "shallow_threshold": 500,
        },
        "trimmed_overflow": {
            "by_category": {"tampering": 12, "information_disclosure": 8},
            "total": 20,
        },
        "opengrep_available": True,
        "opengrep_degraded_reason": None,
    },
)
```

**Success (pre-existing file preserved):**
```python
HandlerResult(
    status=HandlerResultStatus.PASS,
    message=f"Threat model already exists: {path}",
    evidence={
        "path": "THREAT_MODEL.md",
        "action": "skipped",
        "note": "Pre-existing threat model preserved. Re-run with overwrite=true to regenerate.",
    },
)
```

**Success (dynamic analysis failed, fell back to static template):**
```python
HandlerResult(
    status=HandlerResultStatus.PASS,
    message=f"Dynamic analysis unavailable — created from template: {path}",
    confidence=1.0,
    evidence={
        "path": "THREAT_MODEL.md",
        "action": "created_from_template",
        "fallback_reason": "<exception str>",
    },
)
```

**Error (unrecoverable):**
```python
HandlerResult(
    status=HandlerResultStatus.ERROR,
    message="<why>",
    evidence={"path": "THREAT_MODEL.md", "error": "<detail>"},
)
```

## Behavioral contract

### Preserved from the current handler

- **Signature**: unchanged.
- **`HandlerResult` status domain**: `{PASS, ERROR}` only.
- **`evidence["path"]`**: always set, always repo-relative.
- **`evidence["action"]`**: one of `{"created", "skipped", "created_from_template"}`.
- **`evidence["llm_verification_required"]`**: `True` for `action == "created"`, absent otherwise.
- **Fallback path**: when dynamic analysis raises, the handler writes the pre-resolved template content supplied via `config["content"]` (if present) and returns `PASS` with `action == "created_from_template"`.
- **File path**: always respects `config["path"]` verbatim. The handler never picks a path on its own.

### Changed

- **`evidence` keys added**: `file_scan_stats`, `trimmed_overflow`, `opengrep_available`, `opengrep_degraded_reason`. All additive — existing consumers ignoring unknown keys continue to work.
- **Draft content**: produced by the new tree-sitter + optional Opengrep pipeline rather than the old regex-based one. Sections and markers within the Markdown draft are preserved (see `output-format-contract.md`).

## Error handling

| Condition | Handler response |
|-----------|------------------|
| `config["path"]` missing or empty | `ERROR`, message `"No path specified for threat model generation"` |
| File exists, `overwrite=False` | `PASS`, `action="skipped"` |
| File exists, `overwrite=True` | Overwrite, `action="created"` |
| Tree-sitter import fails | Fall back to static template if `config["content"]` present; otherwise `ERROR` |
| Opengrep binary not installed | Proceed tree-sitter-only; log warning; set `evidence["opengrep_available"] = False` |
| Opengrep subprocess times out or errors | Proceed tree-sitter-only; `evidence["opengrep_degraded_reason"]` set |
| Opengrep returns rule-schema errors in `errors[]` | Proceed with returned findings; `evidence["opengrep_degraded_reason"]` set |
| File write fails (permissions, disk) | `ERROR`, evidence includes `error` string |
| Discovery pipeline raises unexpectedly | Fall back to static template if available; otherwise `ERROR` |

## Non-goals of this contract

- The handler does not call any LLM. The `llm_verification_required: True` flag is a hint to the calling agent (which is itself the LLM, invoked via a skill).
- The handler does not re-audit the control. It generates the file; the next audit run verifies SA-03.02 independently.
- The handler does not commit to git. Git operations are handled by the separate `commit_remediation_changes` and `create_remediation_pr` tools.
