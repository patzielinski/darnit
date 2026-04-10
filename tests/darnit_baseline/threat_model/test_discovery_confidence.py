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
    _get_docstring_lines,
    _line_is_string_or_comment,
    _match_is_in_string_context,
    _python_imports,
    detect_frameworks,
    discover_data_stores,
    discover_injection_sinks,
    discover_sensitive_data,
)
from darnit_baseline.threat_model.models import Confidence
from darnit_baseline.threat_model.stride import analyze_stride_threats

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

    def test_urlopen_hardcoded_url_not_flagged_as_ssrf(self, tmp_repo):
        """urlopen() with a hardcoded/internal URL is NOT SSRF."""
        _write(tmp_repo, "client.py", """\
            import urllib.request
            PYPI_URL = "https://pypi.org/pypi/{}/json"
            def fetch_package(name):
                url = PYPI_URL.format(name)
                with urllib.request.urlopen(url, timeout=10) as resp:
                    return resp.read()
        """)
        sinks = discover_injection_sinks(str(tmp_repo))
        ssrf = [s for s in sinks if s["type"] == "ssrf"]
        assert len(ssrf) == 0

    def test_urlopen_with_user_input_flagged_as_ssrf(self, tmp_repo):
        """urlopen() with user-controlled URL IS SSRF."""
        _write(tmp_repo, "proxy.py", """\
            import urllib.request
            def fetch_url(request):
                url = request.args.get("url")
                with urllib.request.urlopen(url + request.path, timeout=10) as resp:
                    return resp.read()
        """)
        sinks = discover_injection_sinks(str(tmp_repo))
        ssrf = [s for s in sinks if s["type"] == "ssrf"]
        assert len(ssrf) > 0

    def test_injection_sink_has_user_input_flag(self, tmp_repo):
        """Injection sinks carry has_user_input taint signal."""
        _write(tmp_repo, "app.py", """\
            import sqlite3
            def get_user(request):
                user_id = request.args["id"]
                conn = sqlite3.connect("app.db")
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM users WHERE id=" + user_id)
        """)
        sinks = discover_injection_sinks(str(tmp_repo))
        assert len(sinks) > 0
        assert sinks[0]["has_user_input"] is True

    def test_injection_sink_no_user_input_flag(self, tmp_repo):
        """Injection sink without request context has has_user_input=False."""
        _write(tmp_repo, "setup.py", """\
            import sqlite3
            def init_db():
                conn = sqlite3.connect("app.db")
                cursor = conn.cursor()
                cursor.execute("CREATE TABLE users" + "(id INTEGER)")
        """)
        sinks = discover_injection_sinks(str(tmp_repo))
        assert len(sinks) > 0
        assert sinks[0]["has_user_input"] is False


# ---------------------------------------------------------------------------
# STRIDE threat filtering (taint-aware)
# ---------------------------------------------------------------------------

class TestStrideTaintFiltering:
    def test_no_threats_for_untainted_sinks(self):
        """Injection sinks without user-input taint should NOT generate threats."""
        from darnit_baseline.threat_model.models import AssetInventory

        assets = AssetInventory(
            entry_points=[], data_stores=[], sensitive_data=[],
            secrets=[], authentication=[], frameworks_detected=[],
        )
        sinks = [{
            "type": "ssrf",
            "file": "client.py",
            "line": 10,
            "snippet": "urllib.request.urlopen(api_url)",
            "severity": "high",
            "cwe": "CWE-918",
            "recommendation": "Validate URLs",
            "has_user_input": False,
        }]
        threats = analyze_stride_threats(assets, sinks)
        tampering = [t for t in threats if t.category.value == "tampering"]
        assert len(tampering) == 0

    def test_threats_for_tainted_sinks(self):
        """Injection sinks WITH user-input taint should generate threats."""
        from darnit_baseline.threat_model.models import AssetInventory

        assets = AssetInventory(
            entry_points=[], data_stores=[], sensitive_data=[],
            secrets=[], authentication=[], frameworks_detected=[],
        )
        sinks = [{
            "type": "sql_injection",
            "file": "app.py",
            "line": 5,
            "snippet": 'cursor.execute("SELECT * FROM users WHERE id=" + request.args["id"])',
            "severity": "critical",
            "cwe": "CWE-89",
            "recommendation": "Use parameterized queries",
            "has_user_input": True,
        }]
        threats = analyze_stride_threats(assets, sinks)
        injection_threats = [
            t for t in threats
            if "injection" in t.title.lower() or "sql" in t.title.lower()
        ]
        assert len(injection_threats) == 1


# ---------------------------------------------------------------------------
# Docstring filtering
# ---------------------------------------------------------------------------

class TestDocstringFiltering:
    def test_identifies_module_docstring(self):
        code = textwrap.dedent('''\
            """Module docstring with email and address."""
            x = 1
        ''')
        lines = _get_docstring_lines(code)
        assert 1 in lines

    def test_identifies_function_docstring(self):
        code = textwrap.dedent('''\
            def foo():
                """Function doc with email param."""
                pass
        ''')
        lines = _get_docstring_lines(code)
        assert 2 in lines

    def test_identifies_multiline_docstring(self):
        code = textwrap.dedent('''\
            def foo():
                """First line.

                Args:
                    email: The user email address.
                """
                pass
        ''')
        lines = _get_docstring_lines(code)
        assert 5 in lines  # the "email:" line

    def test_does_not_flag_code_lines(self):
        code = textwrap.dedent('''\
            def foo():
                """Docstring."""
                email = get_email()
        ''')
        lines = _get_docstring_lines(code)
        assert 3 not in lines  # the assignment line


# ---------------------------------------------------------------------------
# Sensitive data false positive filtering
# ---------------------------------------------------------------------------

class TestSensitiveDataFiltering:
    def test_docstring_email_not_flagged(self, tmp_repo):
        """The word 'email' in a docstring should NOT be flagged as PII."""
        _write(tmp_repo, "tools.py", '''\
            def confirm_context(maintainers=None, security_contact=None):
                """Record user-confirmed project context.

                Parameters:
                    security_contact: Security contact email or file reference
                """
                pass
        ''')
        data = discover_sensitive_data(str(tmp_repo))
        pii = [d for d in data if d.data_type == "pii"]
        assert len(pii) == 0

    def test_comment_email_not_flagged(self, tmp_repo):
        """The word 'email' in a comment should NOT be flagged as PII."""
        _write(tmp_repo, "handler.py", """\
            # Parse email addresses from maintainers file
            def parse_maintainers(content):
                return content.split()
        """)
        data = discover_sensitive_data(str(tmp_repo))
        pii = [d for d in data if d.data_type == "pii"]
        assert len(pii) == 0

    def test_real_pii_field_still_flagged(self, tmp_repo):
        """Actual PII field assignments should still be detected."""
        _write(tmp_repo, "models.py", """\
            class User:
                email = Column(String)
                phone_number = Column(String)
        """)
        data = discover_sensitive_data(str(tmp_repo))
        pii = [d for d in data if d.data_type == "pii"]
        assert len(pii) >= 2

    def test_dict_key_pii_still_flagged(self, tmp_repo):
        """PII in dict key assignments should still be detected."""
        _write(tmp_repo, "handler.py", """\
            user_data = {
                "email": request.form["email"],
                "phone": request.form["phone"],
            }
        """)
        data = discover_sensitive_data(str(tmp_repo))
        pii = [d for d in data if d.data_type == "pii"]
        assert len(pii) >= 1

    def test_regex_group_extraction_not_flagged(self, tmp_repo):
        """Extracting email from regex match is metadata parsing, not PII."""
        _write(tmp_repo, "parser.py", """\
            import re
            match = re.match(r"(.+?)\\s*<(.+?)>", line)
            if match:
                name = match.group(1).strip()
                email = match.group(2).strip()
        """)
        data = discover_sensitive_data(str(tmp_repo))
        pii = [d for d in data if d.data_type == "pii"]
        assert len(pii) == 0, (
            f"Regex extraction flagged as PII: {[(d.field_name, d.context) for d in pii]}"
        )

    def test_type_comparison_not_flagged(self, tmp_repo):
        """Type branching on field name (== 'email') is not PII handling."""
        _write(tmp_repo, "validator.py", """\
            def validate(value, ctx_type):
                if ctx_type == "email":
                    return "@" in value
                elif ctx_type == "phone":
                    return value.isdigit()
        """)
        data = discover_sensitive_data(str(tmp_repo))
        pii = [d for d in data if d.data_type == "pii"]
        assert len(pii) == 0, (
            f"Type comparison flagged as PII: {[(d.field_name, d.context) for d in pii]}"
        )

    def test_dataclass_empty_default_not_flagged(self, tmp_repo):
        """Dataclass field with empty default is schema, not PII handling."""
        _write(tmp_repo, "models.py", """\
            from dataclasses import dataclass

            @dataclass
            class Contact:
                email: str = ""
                phone: str = None
        """)
        data = discover_sensitive_data(str(tmp_repo))
        pii = [d for d in data if d.data_type == "pii"]
        assert len(pii) == 0, (
            f"Dataclass default flagged as PII: {[(d.field_name, d.context) for d in pii]}"
        )


# ---------------------------------------------------------------------------
# Template injection detection
# ---------------------------------------------------------------------------

class TestTemplateInjectionDetection:
    def test_jinja2_from_string_detected(self, tmp_repo):
        """Jinja2 from_string() with user input should be detected."""
        _write(tmp_repo, "app.py", """\
            from flask import request
            import jinja2
            def render(request):
                user_template = request.form["template"]
                env = jinja2.Environment()
                result = env.from_string(user_template).render()
        """)
        sinks = discover_injection_sinks(str(tmp_repo))
        template = [s for s in sinks if s["type"] == "template_injection"]
        assert len(template) > 0
        assert template[0]["has_user_input"] is True

    def test_jinja2_from_string_no_user_input(self, tmp_repo):
        """Jinja2 from_string() with static template has no taint."""
        _write(tmp_repo, "renderer.py", """\
            import jinja2
            def render_static():
                env = jinja2.Environment()
                tpl = env.from_string("Hello {{ name }}")
                return tpl.render(name="world")
        """)
        sinks = discover_injection_sinks(str(tmp_repo))
        template = [s for s in sinks if s["type"] == "template_injection"]
        # Sink detected but without user-input taint
        if template:
            assert template[0]["has_user_input"] is False

    def test_render_template_string_detected(self, tmp_repo):
        """Flask render_template_string with user input should be detected."""
        _write(tmp_repo, "app.py", """\
            from flask import request, render_template_string
            def render(request):
                body = request.form["body"]
                return render_template_string(body)
        """)
        sinks = discover_injection_sinks(str(tmp_repo))
        template = [s for s in sinks if s["type"] == "template_injection"]
        assert len(template) > 0
        assert template[0]["has_user_input"] is True


# ---------------------------------------------------------------------------
# Python path traversal detection
# ---------------------------------------------------------------------------

class TestPythonPathTraversalDetection:
    def test_os_path_join_with_user_input(self, tmp_repo):
        """os.path.join with request input should be detected."""
        _write(tmp_repo, "handler.py", """\
            import os
            def download(request):
                filename = request.args["file"]
                full_path = os.path.join("/uploads", filename)
                return open(full_path).read()
        """)
        sinks = discover_injection_sinks(str(tmp_repo))
        path = [s for s in sinks if s["type"] == "path_traversal"]
        assert len(path) > 0
        assert path[0]["has_user_input"] is True

    def test_os_path_join_with_literals_no_taint(self, tmp_repo):
        """os.path.join with only literal strings has no user-input taint."""
        _write(tmp_repo, "config.py", """\
            import os
            base = os.path.join("/etc", "myapp", "config.yml")
        """)
        sinks = discover_injection_sinks(str(tmp_repo))
        path = [s for s in sinks if s["type"] == "path_traversal"]
        # The pattern matches variables too, but no taint
        for s in path:
            assert s["has_user_input"] is False


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

    def test_no_ssrf_false_positives(self, repo_root):
        """Darnit's own urlopen() calls should not be flagged as SSRF."""
        sinks = discover_injection_sinks(repo_root)
        ssrf = [s for s in sinks if s["type"] == "ssrf"]
        assert len(ssrf) == 0, (
            f"SSRF false positives: {[(s['file'], s['line']) for s in ssrf]}"
        )

    def test_no_pii_from_metadata_parsing(self, repo_root):
        """Git metadata parsing and type branching should not be flagged as PII."""
        data = discover_sensitive_data(repo_root)
        pii = [d for d in data if d.data_type == "pii"]
        metadata_fps = [
            d for d in pii
            if "match.group" in d.context
            or "ctx_type ==" in d.context
            or "== \"email\"" in d.context
        ]
        assert len(metadata_fps) == 0, (
            f"False positive PII from metadata/type-checking code: "
            f"{[(d.file, d.line, d.context) for d in metadata_fps]}"
        )

    def test_no_injection_threats_from_self_scan(self, repo_root):
        """Self-scan should produce zero injection threats (no user-facing endpoints)."""
        from darnit_baseline.threat_model.discovery import discover_all_assets
        assets = discover_all_assets(repo_root)
        sinks = discover_injection_sinks(repo_root)
        threats = analyze_stride_threats(assets, sinks)
        injection_threats = [
            t for t in threats
            if "injection" in t.title.lower()
            or "ssrf" in t.title.lower()
            or "xss" in t.title.lower()
            or "template" in t.title.lower()
        ]
        assert len(injection_threats) == 0, (
            f"False positive injection threats from self-scan: "
            f"{[(t.title, t.code_locations[0].file if t.code_locations else '?') for t in injection_threats]}"
        )
