"""Tests for confidence-aware asset discovery.

Validates that the threat model correctly distinguishes between:
  - Actual technology usage (HIGH/MEDIUM confidence)
  - Pattern definitions and string references (LOW confidence)
"""

import os
import textwrap

import pytest

from darnit_baseline.threat_model.dependencies import parse_dependency_manifests
from darnit_baseline.threat_model.discovery import (
    _line_is_string_or_comment,
    _match_is_in_string_context,
    _python_imports,
    detect_frameworks,
    discover_data_stores,
    discover_injection_sinks,
)
from darnit_baseline.threat_model.models import Confidence

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

@pytest.fixture
def tmp_repo(tmp_path):
    """Create a minimal repo structure for testing."""
    return tmp_path


def _write(repo, rel_path, content):
    """Write a file into the tmp repo."""
    path = repo / rel_path
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(content))


# ---------------------------------------------------------------------------
# _python_imports
# ---------------------------------------------------------------------------

class TestPythonImports:
    def test_extracts_imports(self):
        code = textwrap.dedent("""\
            import os
            import json
            from pathlib import Path
            from sqlalchemy.orm import Session
        """)
        imports = _python_imports(code)
        assert imports == {"os", "json", "pathlib", "sqlalchemy"}

    def test_ignores_string_references(self):
        code = textwrap.dedent("""\
            PATTERNS = {
                "postgresql": r"psycopg|postgres",
                "redis": r"redis\\.|ioredis",
            }
        """)
        imports = _python_imports(code)
        assert "psycopg" not in imports
        assert "redis" not in imports

    def test_handles_syntax_error_gracefully(self):
        code = "this is not valid python {{{"
        imports = _python_imports(code)
        assert imports == set()


# ---------------------------------------------------------------------------
# _line_is_string_or_comment
# ---------------------------------------------------------------------------

class TestLineIsStringOrComment:
    def test_python_comment(self):
        assert _line_is_string_or_comment("  # import psycopg2")

    def test_js_comment(self):
        assert _line_is_string_or_comment("  // require('express')")

    def test_raw_string_pattern(self):
        assert _line_is_string_or_comment('        r"pg\\.|postgres|psycopg",')

    def test_actual_import_is_not_string(self):
        assert not _line_is_string_or_comment("import psycopg2")

    def test_actual_function_call_is_not_string(self):
        assert not _line_is_string_or_comment("conn = psycopg2.connect(DSN)")


# ---------------------------------------------------------------------------
# _match_is_in_string_context
# ---------------------------------------------------------------------------

class TestMatchIsInStringContext:
    def test_regex_pattern_definition(self):
        content = 'PATTERNS = {r"psycopg|postgres"}'
        match_pos = content.index("psycopg")
        assert _match_is_in_string_context(content, match_pos)

    def test_pattern_variable(self):
        content = 'DB_PATTERN = r"pg\\.|postgres"'
        match_pos = content.index("pg")
        assert _match_is_in_string_context(content, match_pos)

    def test_actual_import(self):
        content = "import psycopg2\nconn = psycopg2.connect()"
        match_pos = content.index("psycopg2")
        assert not _match_is_in_string_context(content, match_pos)


# ---------------------------------------------------------------------------
# Dependency manifest parsing
# ---------------------------------------------------------------------------

class TestDependencyManifests:
    def test_pyproject_toml(self, tmp_repo):
        _write(tmp_repo, "pyproject.toml", """\
            [project]
            dependencies = [
                "psycopg2>=2.9",
                "redis>=4.0",
                "fastapi>=0.100",
            ]
        """)
        deps = parse_dependency_manifests(str(tmp_repo))
        assert "postgresql" in deps
        assert "redis" in deps
        assert "fastapi" in deps

    def test_package_json(self, tmp_repo):
        _write(tmp_repo, "package.json", """\
            {
                "dependencies": {
                    "express": "^4.18",
                    "pg": "^8.11",
                    "@prisma/client": "^5.0"
                }
            }
        """)
        deps = parse_dependency_manifests(str(tmp_repo))
        assert "express" in deps
        assert "postgresql" in deps
        assert "prisma" in deps

    def test_requirements_txt(self, tmp_repo):
        _write(tmp_repo, "requirements.txt", """\
            boto3>=1.26
            pymongo==4.5.0
        """)
        deps = parse_dependency_manifests(str(tmp_repo))
        assert "s3" in deps
        assert "mongodb" in deps

    def test_empty_repo(self, tmp_repo):
        deps = parse_dependency_manifests(str(tmp_repo))
        assert deps == set()


# ---------------------------------------------------------------------------
# Data store confidence
# ---------------------------------------------------------------------------

class TestDataStoreConfidence:
    def test_high_confidence_when_in_deps_and_code(self, tmp_repo):
        """Dependency in manifest + import in code → HIGH confidence."""
        _write(tmp_repo, "pyproject.toml", """\
            [project]
            dependencies = ["psycopg2>=2.9"]
        """)
        _write(tmp_repo, "db.py", """\
            import psycopg2
            conn = psycopg2.connect("postgresql://localhost/mydb")
        """)
        stores = discover_data_stores(str(tmp_repo))
        pg = [s for s in stores if s.technology == "postgresql"]
        assert len(pg) == 1
        assert pg[0].confidence == Confidence.HIGH

    def test_medium_confidence_import_no_deps(self, tmp_repo):
        """Import in code but NOT in manifest → MEDIUM confidence."""
        _write(tmp_repo, "db.py", """\
            import psycopg2
            conn = psycopg2.connect("postgresql://localhost/mydb")
        """)
        stores = discover_data_stores(str(tmp_repo))
        pg = [s for s in stores if s.technology == "postgresql"]
        assert len(pg) == 1
        assert pg[0].confidence == Confidence.MEDIUM

    def test_low_confidence_pattern_definition(self, tmp_repo):
        """Pattern in string literal (regex def) → LOW confidence."""
        _write(tmp_repo, "scanner.py", """\
            # Detection patterns for databases
            PATTERNS = {
                "postgresql": {
                    "patterns": [r"pg\\.|postgres|psycopg", r"postgresql://"],
                    "type": "database",
                },
                "redis": {
                    "patterns": [r"redis\\.|ioredis|createClient.*redis"],
                    "type": "cache",
                },
            }
        """)
        stores = discover_data_stores(str(tmp_repo))
        for store in stores:
            assert store.confidence == Confidence.LOW, (
                f"{store.technology} should be LOW confidence when only in pattern defs, "
                f"got {store.confidence}"
            )

    def test_meta_directory_skipped(self, tmp_repo):
        """Files in threat_model/ directories are skipped entirely."""
        _write(tmp_repo, "threat_model/patterns.py", """\
            DATASTORE_PATTERNS = {
                "postgresql": {"patterns": [r"pg\\.|postgres"]},
            }
        """)
        stores = discover_data_stores(str(tmp_repo))
        assert len(stores) == 0


# ---------------------------------------------------------------------------
# Framework detection with deps
# ---------------------------------------------------------------------------

class TestFrameworkDetectionWithDeps:
    def test_detects_from_manifest_without_code_scan(self, tmp_repo):
        """If a framework is in the dependency manifest, detect it immediately."""
        _write(tmp_repo, "pyproject.toml", """\
            [project]
            dependencies = ["fastapi>=0.100"]
        """)
        frameworks = detect_frameworks(str(tmp_repo))
        assert "fastapi" in frameworks

    def test_pattern_in_string_not_detected(self, tmp_repo):
        """A framework name in a regex string should not trigger detection."""
        _write(tmp_repo, "scanner.py", """\
            FRAMEWORK_PATTERNS = {
                "fastapi": {
                    "indicators": [
                        (None, r"from fastapi import"),
                        (None, r"FastAPI()"),
                    ],
                }
            }
        """)
        frameworks = detect_frameworks(str(tmp_repo))
        assert "fastapi" not in frameworks


# ---------------------------------------------------------------------------
# Injection sink filtering
# ---------------------------------------------------------------------------

class TestInjectionSinkFiltering:
    def test_skips_pattern_definitions(self, tmp_repo):
        """Regex patterns defining injection signatures should not be flagged."""
        _write(tmp_repo, "patterns.py", """\
            INJECTION_PATTERNS = {
                "sql_injection": {
                    "patterns": [
                        r"execute\\s*\\(.*\\+",
                        r"cursor.execute\\s*\\(.*f['\"]",
                    ],
                },
            }
        """)
        sinks = discover_injection_sinks(str(tmp_repo))
        assert len(sinks) == 0

    def test_real_injection_still_detected(self, tmp_repo):
        """Actual vulnerable code should still be detected."""
        _write(tmp_repo, "app.py", """\
            import sqlite3
            def get_user(user_id):
                conn = sqlite3.connect("app.db")
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM users WHERE id=" + user_id)
        """)
        sinks = discover_injection_sinks(str(tmp_repo))
        assert len(sinks) > 0


# ---------------------------------------------------------------------------
# Self-scan: run against the darnit repo itself
# ---------------------------------------------------------------------------

class TestSelfScan:
    """Run discovery against the actual darnit source tree.

    The darnit project is a compliance tool — it should NOT show up as
    using PostgreSQL, Redis, MongoDB, etc. just because patterns.py
    defines detection regexes for those technologies.
    """

    @pytest.fixture
    def repo_root(self):
        """Walk up from this test file to find the repo root."""
        here = os.path.dirname(__file__)
        root = here
        for _ in range(10):
            if os.path.isfile(os.path.join(root, "pyproject.toml")):
                return root
            root = os.path.dirname(root)
        pytest.skip("Could not find repo root")

    def test_no_false_positive_datastores(self, repo_root):
        """Darnit should not detect datastores from its own pattern definitions."""
        stores = discover_data_stores(repo_root)
        high_medium = [s for s in stores if s.confidence != Confidence.LOW]
        false_positives = [
            s.technology for s in high_medium
            if s.technology in ("postgresql", "mysql", "mongodb", "redis", "sqlite", "s3")
        ]
        assert false_positives == [], (
            f"False positive datastores detected at HIGH/MEDIUM confidence: {false_positives}"
        )

    def test_no_false_positive_frameworks(self, repo_root):
        """Darnit should not detect web frameworks from pattern definitions."""
        frameworks = detect_frameworks(repo_root)
        web_frameworks = {"nextjs", "express", "fastapi", "django", "flask", "react", "vue"}
        false_positives = set(frameworks) & web_frameworks
        assert false_positives == set(), (
            f"False positive frameworks detected: {false_positives}"
        )
