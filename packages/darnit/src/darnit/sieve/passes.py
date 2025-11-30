"""Verification pass implementations for the sieve system."""

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional
import re
import os

from darnit.core.logging import get_logger

from .models import (
    CheckContext,
    PassResult,
    PassOutcome,
    VerificationPhase,
    LLMConsultationRequest,
)

logger = get_logger("sieve.passes")


def _file_exists(local_path: str, *patterns: str) -> Optional[str]:
    """Check if any file matching patterns exists. Returns first match or None."""
    for pattern in patterns:
        # Handle simple glob-like patterns
        if "*" in pattern:
            import glob

            matches = glob.glob(os.path.join(local_path, pattern))
            if matches:
                return matches[0]
        else:
            path = os.path.join(local_path, pattern)
            if os.path.isfile(path):
                return path
    return None


def _read_file(local_path: str, filename: str) -> Optional[str]:
    """Read file contents, return None if not found."""
    # Try multiple locations
    candidates = [
        os.path.join(local_path, filename),
        os.path.join(local_path, ".github", filename),
        os.path.join(local_path, "docs", filename),
    ]
    for path in candidates:
        if os.path.isfile(path):
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    return f.read()
            except (IOError, OSError):
                pass
    return None


def _file_contains(
    local_path: str, file_patterns: List[str], content_pattern: str
) -> bool:
    """Check if any matching file contains the content pattern."""
    for file_pattern in file_patterns:
        content = _read_file(local_path, file_pattern)
        if content and re.search(content_pattern, content, re.IGNORECASE):
            return True
    return False


@dataclass
class DeterministicPass:
    """Pass 1: Deterministic checks (file existence, API booleans, config)."""

    phase: VerificationPhase = field(
        default=VerificationPhase.DETERMINISTIC, init=False
    )

    # Configurable checks
    file_must_exist: Optional[List[str]] = None  # Any of these patterns
    file_must_not_exist: Optional[List[str]] = None
    api_check: Optional[Callable[[str, str], PassResult]] = None
    config_check: Optional[Callable[[CheckContext], PassResult]] = None

    def execute(self, context: CheckContext) -> PassResult:
        checks_performed = []

        # File existence checks
        if self.file_must_exist:
            checks_performed.append(f"file_exists({self.file_must_exist})")
            found = _file_exists(context.local_path, *self.file_must_exist)
            if found:
                return PassResult(
                    phase=self.phase,
                    outcome=PassOutcome.PASS,
                    message=f"Required file found: {os.path.basename(found)}",
                    evidence={"file_found": found, "files_checked": self.file_must_exist},
                )
            else:
                return PassResult(
                    phase=self.phase,
                    outcome=PassOutcome.FAIL,
                    message=f"Required file not found: {self.file_must_exist}",
                    evidence={"files_checked": self.file_must_exist},
                )

        if self.file_must_not_exist:
            checks_performed.append(f"file_not_exists({self.file_must_not_exist})")
            found = _file_exists(context.local_path, *self.file_must_not_exist)
            if found:
                return PassResult(
                    phase=self.phase,
                    outcome=PassOutcome.FAIL,
                    message=f"Prohibited file found: {os.path.basename(found)}",
                    evidence={"file_found": found},
                )

        # API check
        if self.api_check:
            checks_performed.append("api_check()")
            try:
                return self.api_check(context.owner, context.repo)
            except (RuntimeError, ValueError, TypeError, KeyError, AttributeError, IOError, OSError) as e:
                return PassResult(
                    phase=self.phase,
                    outcome=PassOutcome.ERROR,
                    message=f"API check failed: {str(e)}",
                    evidence={"error": str(e)},
                )

        # Config check
        if self.config_check:
            checks_performed.append("config_check()")
            try:
                return self.config_check(context)
            except (RuntimeError, ValueError, TypeError, KeyError, AttributeError, IOError, OSError) as e:
                return PassResult(
                    phase=self.phase,
                    outcome=PassOutcome.ERROR,
                    message=f"Config check failed: {str(e)}",
                    evidence={"error": str(e)},
                )

        # No deterministic check configured - inconclusive
        return PassResult(
            phase=self.phase,
            outcome=PassOutcome.INCONCLUSIVE,
            message="No deterministic check available",
            details={"checks_performed": checks_performed},
        )

    def describe(self) -> str:
        parts = []
        if self.file_must_exist:
            parts.append(f"Check file exists: {self.file_must_exist}")
        if self.file_must_not_exist:
            parts.append(f"Check file absent: {self.file_must_not_exist}")
        if self.api_check:
            parts.append("GitHub API check")
        if self.config_check:
            parts.append("Configuration check")
        return "; ".join(parts) or "No deterministic checks"


@dataclass
class PatternPass:
    """Pass 2: Pattern/heuristic checks (regex, content analysis)."""

    phase: VerificationPhase = field(default=VerificationPhase.PATTERN, init=False)

    # Configurable pattern checks
    file_patterns: Optional[List[str]] = None  # Files to search
    content_patterns: Optional[Dict[str, str]] = None  # name -> regex
    pass_if_any_match: bool = True  # vs pass_if_all_match
    fail_if_no_match: bool = False  # Return FAIL instead of INCONCLUSIVE
    custom_analyzer: Optional[Callable[[CheckContext], PassResult]] = None

    def execute(self, context: CheckContext) -> PassResult:
        checks_performed = []
        matches_found = []

        # Content pattern matching
        if self.file_patterns and self.content_patterns:
            for pattern_name, regex in self.content_patterns.items():
                checks_performed.append(f"pattern({pattern_name})")
                if _file_contains(context.local_path, self.file_patterns, regex):
                    matches_found.append(pattern_name)

            if self.pass_if_any_match and matches_found:
                return PassResult(
                    phase=self.phase,
                    outcome=PassOutcome.PASS,
                    message=f"Pattern matches found: {matches_found}",
                    evidence={"patterns_matched": matches_found},
                )
            elif not self.pass_if_any_match and len(matches_found) == len(
                self.content_patterns
            ):
                return PassResult(
                    phase=self.phase,
                    outcome=PassOutcome.PASS,
                    message="All required patterns matched",
                    evidence={"patterns_matched": matches_found},
                )
            elif matches_found:
                # Some but not all - inconclusive, let next pass decide
                return PassResult(
                    phase=self.phase,
                    outcome=PassOutcome.INCONCLUSIVE,
                    message=f"Partial pattern matches: {matches_found}",
                    evidence={
                        "patterns_matched": matches_found,
                        "patterns_missing": list(
                            set(self.content_patterns.keys()) - set(matches_found)
                        ),
                    },
                )
            else:
                # No matches
                if self.fail_if_no_match:
                    return PassResult(
                        phase=self.phase,
                        outcome=PassOutcome.FAIL,
                        message="No pattern matches found",
                        evidence={"patterns_checked": list(self.content_patterns.keys())},
                    )
                return PassResult(
                    phase=self.phase,
                    outcome=PassOutcome.INCONCLUSIVE,
                    message="No pattern matches found",
                    evidence={"patterns_checked": list(self.content_patterns.keys())},
                )

        # Custom analyzer
        if self.custom_analyzer:
            checks_performed.append("custom_analyzer()")
            try:
                return self.custom_analyzer(context)
            except (RuntimeError, ValueError, TypeError, KeyError, AttributeError, IOError, OSError) as e:
                return PassResult(
                    phase=self.phase,
                    outcome=PassOutcome.ERROR,
                    message=f"Custom analyzer failed: {str(e)}",
                    evidence={"error": str(e)},
                )

        return PassResult(
            phase=self.phase,
            outcome=PassOutcome.INCONCLUSIVE,
            message="No pattern checks available",
            details={"checks_performed": checks_performed},
        )

    def describe(self) -> str:
        parts = []
        if self.content_patterns:
            parts.append(
                f"Pattern match in {self.file_patterns}: {list(self.content_patterns.keys())}"
            )
        if self.custom_analyzer:
            parts.append("Custom content analyzer")
        return "; ".join(parts) or "No pattern checks"


@dataclass
class LLMPass:
    """Pass 3: LLM-assisted verification via consultation protocol."""

    phase: VerificationPhase = field(default=VerificationPhase.LLM, init=False)

    # Consultation configuration
    prompt_template: str = ""
    files_to_include: Optional[List[str]] = None  # Include file contents in context
    analysis_hints: List[str] = field(default_factory=list)
    confidence_threshold: float = 0.8
    max_file_content_length: int = 5000  # Truncate long files

    def execute(self, context: CheckContext) -> PassResult:
        # Gather context for LLM
        gathered_context = dict(context.gathered_evidence)

        if self.files_to_include:
            for pattern in self.files_to_include:
                content = _read_file(context.local_path, pattern)
                if content:
                    # Truncate long content
                    if len(content) > self.max_file_content_length:
                        content = (
                            content[: self.max_file_content_length]
                            + f"\n... [truncated, {len(content)} total chars]"
                        )
                    gathered_context[f"file:{pattern}"] = content

        # Format prompt template with context
        try:
            formatted_prompt = self.prompt_template.format(
                control_id=context.control_id,
                owner=context.owner,
                repo=context.repo,
                local_path=context.local_path,
                **context.control_metadata,
            )
        except KeyError:
            # If template has unfilled placeholders, use as-is
            formatted_prompt = self.prompt_template

        # Create consultation request
        request = LLMConsultationRequest(
            control_id=context.control_id,
            control_name=context.control_metadata.get("name", context.control_id),
            control_description=context.control_metadata.get("full", ""),
            prompt=formatted_prompt,
            context=gathered_context,
            analysis_hints=self.analysis_hints,
            expected_response='{"status": "PASS|FAIL|INCONCLUSIVE", "confidence": 0.0-1.0, "reasoning": "...", "evidence": [...]}',
        )

        # Return result that signals consultation needed
        return PassResult(
            phase=self.phase,
            outcome=PassOutcome.INCONCLUSIVE,
            message="LLM consultation required",
            details={
                "consultation_request": request,
                "confidence_threshold": self.confidence_threshold,
            },
        )

    def describe(self) -> str:
        preview = self.prompt_template[:80] + "..." if len(self.prompt_template) > 80 else self.prompt_template
        return f"LLM analysis: {preview}"


@dataclass
class ManualPass:
    """Pass 4: Manual verification (always returns WARN with steps)."""

    phase: VerificationPhase = field(default=VerificationPhase.MANUAL, init=False)

    verification_steps: List[str] = field(default_factory=list)
    verification_docs_url: Optional[str] = None

    def execute(self, context: CheckContext) -> PassResult:
        steps = self.verification_steps or [
            f"Review {context.control_id} requirements in OSPS specification",
            "Manually verify compliance based on project context",
            "Document verification results",
        ]

        return PassResult(
            phase=self.phase,
            outcome=PassOutcome.INCONCLUSIVE,  # Manual always inconclusive (returns WARN)
            message="Manual verification required",
            details={"verification_steps": steps, "docs_url": self.verification_docs_url},
        )

    def describe(self) -> str:
        return f"Manual verification: {len(self.verification_steps)} steps"
