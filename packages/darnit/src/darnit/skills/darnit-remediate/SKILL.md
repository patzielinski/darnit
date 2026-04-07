---
name: darnit-remediate
description: Apply automated fixes for failing compliance controls. Shows a plan first, then creates a branch with fixes and optionally a PR. Use when the user wants to fix compliance failures, apply remediations, or create a compliance PR.
compatibility: Requires darnit MCP server running (darnit serve)
metadata:
  author: kusari-oss
  version: "2.0"
---

# Compliance Remediation

Show a dry-run plan of fixes for failing controls, get confirmation, then apply changes on a new branch. After applying, enhance generated template files with project-specific content.

## Workflow

### 1. Show dry-run plan

Call `remediate_audit_findings` with `dry_run: true` and any profile mentioned.
The tool internally runs an audit (or uses cached results) — do NOT run a separate audit call.

Present the plan:
- **Safe auto-fixes**: what will be created or modified
- **Unsafe / manual**: why these can't be auto-fixed, what to do instead
- **No fix available**: controls without remediation handlers

Ask: "Apply the safe auto-fixes? This will create a new branch."

### 2. Apply fixes (if confirmed)

Call `remediate_audit_findings` with:
- `dry_run: false`
- `branch_name: "fix/compliance"` (or `"fix/compliance-{profile}"` if a profile was specified)
- `auto_commit: true`

This single call creates the branch, applies all remediations, and commits. Do NOT make separate calls to `create_remediation_branch` or `commit_remediation_changes`.

### 3. Review generated files (quality check)

Read the generated files and check for obvious issues:

- Broken syntax (e.g., malformed YAML, invalid workflow expressions)
- Placeholder values that were not substituted (e.g., leftover `${...}` tokens)
- Files that are clearly wrong for this project type

**Rules for this step:**
- Only use confirmed context from `.project/project.yaml` for project-specific values (maintainers, contacts, governance, etc.)
- Do NOT scrape names, emails, or other values from existing repo files (SECURITY.md, CODEOWNERS, git history, etc.)
- Do NOT add content beyond what the templates produced — the templates already use `${context.*}` and `${scan.*}` variables
- If a template produced reasonable output, leave it alone
- Only fix clear errors, not style preferences

If any files were fixed, make a new commit describing the specific fixes.

### 4. Offer PR creation

Ask if the user wants a PR. If yes, call `create_remediation_pr` and display the URL.

### 5. Summary

Show: branch name, controls fixed, files changed, PR URL (if created), and remaining manual items.

## Gotchas

- Always show the dry-run plan first. Never apply changes without confirmation.
- Do NOT call `audit_openssf_baseline` separately — `remediate_audit_findings` handles audit internally.
- Do NOT call `create_remediation_branch` or `commit_remediation_changes` separately — use the `branch_name` and `auto_commit` params instead.
- If `remediate_audit_findings` fails mid-way, report which files were already changed so the user can review.
- The tool respects the `safe` flag on remediations — only safe remediations are auto-applied. Unsafe ones are listed but excluded.
- If there are unresolved context questions, the remediation tool will block and tell you. Suggest running `/darnit-context` first.

## Error handling

If the tool returns a context warning, suggest running `/darnit-context` first.
If branch creation fails, report the error — the tool aborts before applying any changes.
