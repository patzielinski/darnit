"""Asset discovery for threat modeling.

This module provides functions to discover security-relevant assets
in a codebase, including entry points, authentication mechanisms,
data stores, sensitive data, and secrets.

Detection uses a confidence-tiered approach:
  HIGH   — technology found in dependency manifest AND imported in code
  MEDIUM — imported/required in code but not in dependency manifest
  LOW    — pattern found in string literal, regex, or comment (likely a
           reference rather than actual usage)
"""

import ast
import os
import re
from typing import Any

from darnit.core.logging import get_logger

from .dependencies import parse_dependency_manifests
from .models import (
    AssetInventory,
    AuthMechanism,
    Confidence,
    DataStore,
    EntryPoint,
    SecretReference,
    SensitiveData,
)
from .patterns import (
    AUTH_PATTERNS,
    DATASTORE_PATTERNS,
    FRAMEWORK_PATTERNS,
    INJECTION_PATTERNS,
    SECRET_PATTERNS,
    SENSITIVE_DATA_PATTERNS,
    SKIP_DIRECTORIES,
    SOURCE_EXTENSIONS,
)

# Directories that contain pattern definitions rather than application code.
# Scanning these produces false positives (e.g. detecting "fastapi" from a
# regex string literal that *defines* the fastapi detection pattern).
_META_DIRECTORIES = {"threat_model", "threat-model"}

logger = get_logger("threat_model.discovery")


# ---------------------------------------------------------------------------
# Helpers: distinguish real usage from pattern definitions
# ---------------------------------------------------------------------------

def _python_imports(content: str) -> set[str]:
    """Extract actual import names from Python source using the AST.

    Returns a set of top-level module names that are genuinely imported
    (``import X`` or ``from X import ...``), ignoring references inside
    string literals, comments, or regex patterns.
    """
    imports: set[str] = set()
    try:
        tree = ast.parse(content)
    except SyntaxError:
        return imports
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imports.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                imports.add(node.module.split(".")[0])
    return imports


def _line_is_string_or_comment(line: str) -> bool:
    """Heuristic: return True if the line is a comment or the match is
    likely inside a string literal / regex definition."""
    stripped = line.lstrip()
    # Python / JS / Go comment
    if stripped.startswith("#") or stripped.startswith("//"):
        return True
    # Python raw string pattern definition (common in pattern files)
    if re.match(r'^["\'].*["\'],?\s*$', stripped):
        return True
    # Regex pattern assignment  r"..." or re.compile(...)
    return bool(re.match(r".*r['\"].*['\"]", stripped))


def _match_is_in_string_context(content: str, match_start: int) -> bool:
    """Check whether a regex match position falls inside a string literal.

    Uses a simple heuristic: count unescaped quotes before the match
    position on the same line.  An odd count means we're inside a string.
    """
    # Find the start of the line containing match_start
    line_start = content.rfind("\n", 0, match_start) + 1
    prefix = content[line_start:match_start]

    # Check for common string-context indicators
    # r"..." pattern definitions
    if re.search(r'r["\']', prefix):
        return True
    # Inside a triple-quoted string
    if '"""' in prefix or "'''" in prefix:
        return True
    # Inside a regular string being assigned to a variable ending in
    # _pattern, _regex, PATTERN, REGEX
    return bool(re.search(r'(?:pattern|regex|PATTERN|REGEX)\s*[=:]\s*', prefix))


# ---------------------------------------------------------------------------
# Framework detection
# ---------------------------------------------------------------------------

def detect_frameworks(
    local_path: str,
    declared_deps: set[str] | None = None,
) -> list[str]:
    """Detect frameworks used in the project.

    Args:
        local_path: Path to the repository
        declared_deps: Pre-parsed dependency identifiers (optional)

    Returns:
        List of detected framework names
    """
    if declared_deps is None:
        declared_deps = parse_dependency_manifests(local_path)

    detected = []

    for framework, config in FRAMEWORK_PATTERNS.items():
        # Fast path: if declared in dependencies, trust it
        if framework in declared_deps:
            detected.append(framework)
            continue

        for indicator in config["indicators"]:
            filename, pattern = indicator
            if filename:
                filepath = os.path.join(local_path, filename)
                if os.path.exists(filepath):
                    if pattern:
                        try:
                            with open(filepath, errors='ignore') as f:
                                content = f.read()
                                if re.search(pattern, content):
                                    detected.append(framework)
                                    break
                        except OSError:
                            pass
                    else:
                        detected.append(framework)
                        break
            elif pattern:
                found = False
                for root, dirs, files in os.walk(local_path):
                    dirs[:] = [
                        d for d in dirs
                        if d not in SKIP_DIRECTORIES and d not in _META_DIRECTORIES
                    ]
                    for fn in files:
                        if fn.endswith(SOURCE_EXTENSIONS):
                            filepath = os.path.join(root, fn)
                            try:
                                with open(filepath, errors='ignore') as f:
                                    content = f.read(10000)

                                # For Python files, verify via AST
                                if fn.endswith('.py'):
                                    py_imports = _python_imports(content)
                                    # Check if pattern target is actually imported
                                    if framework in ("fastapi", "flask", "django"):
                                        if framework in py_imports:
                                            detected.append(framework)
                                            found = True
                                            break
                                        continue

                                if re.search(pattern, content):
                                    # Verify this isn't a string-literal reference
                                    match = re.search(pattern, content)
                                    if match and not _match_is_in_string_context(content, match.start()):
                                        detected.append(framework)
                                        found = True
                                        break
                            except OSError:
                                pass
                    if found:
                        break

    return list(set(detected))


# ---------------------------------------------------------------------------
# Entry point discovery
# ---------------------------------------------------------------------------

def discover_entry_points(local_path: str, frameworks: list[str]) -> list[EntryPoint]:
    """Discover API entry points in the codebase.

    Args:
        local_path: Path to the repository
        frameworks: List of detected frameworks

    Returns:
        List of discovered entry points
    """
    entry_points = []
    entry_id = 0

    for root, dirs, files in os.walk(local_path):
        dirs[:] = [
            d for d in dirs
            if d not in SKIP_DIRECTORIES and d not in _META_DIRECTORIES
        ]

        for filename in files:
            if not filename.endswith(SOURCE_EXTENSIONS):
                continue

            filepath = os.path.join(root, filename)
            rel_path = os.path.relpath(filepath, local_path)

            try:
                with open(filepath, errors='ignore') as f:
                    content = f.read()
                    lines = content.split('\n')
            except OSError:
                continue

            # Check Next.js API routes
            if "nextjs" in frameworks:
                # App Router API routes
                if re.match(r"app/api/.*/route\.(ts|js)x?$", rel_path.replace("\\", "/")):
                    methods = []
                    for method in ['GET', 'POST', 'PUT', 'DELETE', 'PATCH']:
                        if re.search(rf"export\s+(async\s+)?function\s+{method}\b", content):
                            methods.append(method)

                    for method in methods or ['ALL']:
                        entry_id += 1
                        api_path = "/" + "/".join(rel_path.replace("\\", "/").split("/")[:-1])
                        api_path = api_path.replace("/app", "").replace("/route", "")
                        has_auth = bool(re.search(r"getServerSession|auth\(|currentUser|useAuth", content))

                        entry_points.append(EntryPoint(
                            id=f"EP-{entry_id:03d}",
                            entry_type="api_route",
                            path=api_path,
                            method=method,
                            file=rel_path,
                            line=1,
                            authentication_required=has_auth,
                            framework="nextjs"
                        ))

                # Server Actions
                if "'use server'" in content or '"use server"' in content:
                    for i, line in enumerate(lines):
                        if re.match(r"^export\s+(async\s+)?function\s+\w+", line):
                            func_match = re.search(r"function\s+(\w+)", line)
                            if func_match:
                                entry_id += 1
                                entry_points.append(EntryPoint(
                                    id=f"EP-{entry_id:03d}",
                                    entry_type="server_action",
                                    path=func_match.group(1),
                                    method="POST",
                                    file=rel_path,
                                    line=i + 1,
                                    authentication_required=False,
                                    framework="nextjs"
                                ))

            # Check Express routes
            if "express" in frameworks:
                for i, line in enumerate(lines):
                    match = re.search(
                        r"(?:app|router)\.(get|post|put|delete|patch|all)\s*\(\s*['\"]([^'\"]+)['\"]",
                        line, re.IGNORECASE
                    )
                    if match:
                        entry_id += 1
                        entry_points.append(EntryPoint(
                            id=f"EP-{entry_id:03d}",
                            entry_type="api_route",
                            path=match.group(2),
                            method=match.group(1).upper(),
                            file=rel_path,
                            line=i + 1,
                            authentication_required=False,
                            framework="express"
                        ))

            # Check FastAPI routes
            if "fastapi" in frameworks:
                for i, line in enumerate(lines):
                    match = re.search(
                        r"@(?:app|router)\.(get|post|put|delete|patch)\s*\(\s*['\"]([^'\"]+)['\"]",
                        line, re.IGNORECASE
                    )
                    if match:
                        entry_id += 1
                        entry_points.append(EntryPoint(
                            id=f"EP-{entry_id:03d}",
                            entry_type="api_route",
                            path=match.group(2),
                            method=match.group(1).upper(),
                            file=rel_path,
                            line=i + 1,
                            authentication_required=False,
                            framework="fastapi"
                        ))

            # Check Django URLs
            if "django" in frameworks:
                for i, line in enumerate(lines):
                    match = re.search(r"path\s*\(\s*['\"]([^'\"]+)['\"]", line)
                    if match:
                        entry_id += 1
                        entry_points.append(EntryPoint(
                            id=f"EP-{entry_id:03d}",
                            entry_type="api_route",
                            path=match.group(1),
                            method="ANY",
                            file=rel_path,
                            line=i + 1,
                            authentication_required=False,
                            framework="django"
                        ))

            # Check Flask routes
            if "flask" in frameworks:
                for i, line in enumerate(lines):
                    match = re.search(r"@\w+\.route\s*\(\s*['\"]([^'\"]+)['\"]", line)
                    if match:
                        methods_match = re.search(
                            r"methods\s*=\s*\[([^\]]+)\]",
                            lines[i] if i < len(lines) else ""
                        )
                        methods = "GET"
                        if methods_match:
                            methods = methods_match.group(1).replace("'", "").replace('"', "").strip()

                        entry_id += 1
                        entry_points.append(EntryPoint(
                            id=f"EP-{entry_id:03d}",
                            entry_type="api_route",
                            path=match.group(1),
                            method=methods,
                            file=rel_path,
                            line=i + 1,
                            authentication_required=False,
                            framework="flask"
                        ))

    return entry_points


# ---------------------------------------------------------------------------
# Authentication discovery
# ---------------------------------------------------------------------------

def discover_authentication(
    local_path: str,
    declared_deps: set[str] | None = None,
) -> list[AuthMechanism]:
    """Discover authentication mechanisms in the codebase.

    Args:
        local_path: Path to the repository
        declared_deps: Pre-parsed dependency identifiers (optional)

    Returns:
        List of discovered authentication mechanisms
    """
    if declared_deps is None:
        declared_deps = parse_dependency_manifests(local_path)

    auth_mechanisms = []
    auth_id = 0

    for root, dirs, files in os.walk(local_path):
        dirs[:] = [
            d for d in dirs
            if d not in SKIP_DIRECTORIES and d not in _META_DIRECTORIES
        ]

        for filename in files:
            if not filename.endswith(('.ts', '.tsx', '.js', '.jsx', '.py')):
                continue

            filepath = os.path.join(root, filename)
            rel_path = os.path.relpath(filepath, local_path)

            try:
                with open(filepath, errors='ignore') as f:
                    content = f.read()
            except OSError:
                continue

            # For Python files, get real imports for confidence scoring
            py_imports = _python_imports(content) if filename.endswith('.py') else set()

            for auth_type, config in AUTH_PATTERNS.items():
                matches = list(re.finditer(config["pattern"], content))
                if matches:
                    first_match = matches[0]

                    # Determine confidence
                    if _match_is_in_string_context(content, first_match.start()):
                        confidence = Confidence.LOW
                    elif auth_type in declared_deps:
                        confidence = Confidence.HIGH
                    elif filename.endswith('.py'):
                        # Check if the auth library is actually imported
                        auth_module_hints = {
                            "django_auth": "django",
                            "fastapi_security": "fastapi",
                            "passport": "passport",
                            "jwt": "jsonwebtoken",
                        }
                        hint = auth_module_hints.get(auth_type, auth_type)
                        confidence = Confidence.MEDIUM if hint in py_imports else Confidence.LOW
                    else:
                        confidence = Confidence.MEDIUM

                    line_num = content[:first_match.start()].count('\n') + 1

                    auth_id += 1
                    auth_mechanisms.append(AuthMechanism(
                        id=f"AUTH-{auth_id:03d}",
                        auth_type=auth_type,
                        file=rel_path,
                        line=line_num,
                        framework=config["framework"],
                        assets=config["assets"],
                        confidence=confidence,
                    ))
                    break  # Only record first occurrence per file

    return auth_mechanisms


# ---------------------------------------------------------------------------
# Sensitive data discovery
# ---------------------------------------------------------------------------

def discover_sensitive_data(local_path: str) -> list[SensitiveData]:
    """Discover sensitive data fields in the codebase.

    Args:
        local_path: Path to the repository

    Returns:
        List of discovered sensitive data references
    """
    sensitive_data = []
    data_id = 0

    for root, dirs, files in os.walk(local_path):
        dirs[:] = [
            d for d in dirs
            if d not in SKIP_DIRECTORIES and d not in _META_DIRECTORIES
        ]

        for filename in files:
            if not filename.endswith(('.ts', '.tsx', '.js', '.jsx', '.py', '.prisma', '.graphql', '.gql')):
                continue

            filepath = os.path.join(root, filename)
            rel_path = os.path.relpath(filepath, local_path)

            try:
                with open(filepath, errors='ignore') as f:
                    content = f.read()
                    lines = content.split('\n')
            except OSError:
                continue

            for data_type, config in SENSITIVE_DATA_PATTERNS.items():
                for pattern in config["patterns"]:
                    for i, line in enumerate(lines):
                        if _line_is_string_or_comment(line):
                            continue
                        matches = re.findall(pattern, line, re.IGNORECASE)
                        for match in matches:
                            field_name = match if isinstance(match, str) else match[0] if match else ""
                            if field_name:
                                data_id += 1
                                sensitive_data.append(SensitiveData(
                                    id=f"SD-{data_id:03d}",
                                    data_type=data_type,
                                    field_name=field_name,
                                    file=rel_path,
                                    line=i + 1,
                                    context=line.strip()[:100]
                                ))

    return sensitive_data


# ---------------------------------------------------------------------------
# Secret discovery
# ---------------------------------------------------------------------------

def discover_secrets(local_path: str) -> list[SecretReference]:
    """Discover potential secrets in the codebase.

    Args:
        local_path: Path to the repository

    Returns:
        List of discovered potential secrets
    """
    secrets = []
    secret_id = 0

    for root, dirs, files in os.walk(local_path):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRECTORIES]

        for filename in files:
            if not any(filename.endswith(ext) for ext in
                      ['.ts', '.tsx', '.js', '.jsx', '.py', '.env', '.json', '.yaml', '.yml', '.toml']):
                continue

            # Skip lock files
            if 'lock' in filename.lower():
                continue

            filepath = os.path.join(root, filename)
            rel_path = os.path.relpath(filepath, local_path)

            try:
                with open(filepath, errors='ignore') as f:
                    content = f.read()
                    lines = content.split('\n')
            except OSError:
                continue

            for secret_type, config in SECRET_PATTERNS.items():
                for i, line in enumerate(lines):
                    if re.search(config["pattern"], line, re.IGNORECASE):
                        # Skip if it's a reference to env variable
                        if re.search(r"process\.env|os\.environ|getenv|ENV\[", line):
                            continue
                        # Skip if in example/test file
                        if any(x in rel_path.lower() for x in ['example', 'test', 'mock', 'fixture']):
                            continue
                        # Skip pattern definitions (regex strings defining what to look for)
                        if _line_is_string_or_comment(line):
                            continue

                        secret_id += 1
                        secrets.append(SecretReference(
                            id=f"SEC-{secret_id:03d}",
                            secret_type=secret_type,
                            name=line.strip()[:50],
                            file=rel_path,
                            line=i + 1,
                            severity=config["severity"]
                        ))

    return secrets


# ---------------------------------------------------------------------------
# Data store discovery (confidence-aware)
# ---------------------------------------------------------------------------

def discover_data_stores(
    local_path: str,
    declared_deps: set[str] | None = None,
) -> list[DataStore]:
    """Discover data stores used in the project.

    Uses a confidence-tiered approach:
      HIGH   — technology in dependency manifest AND code reference
      MEDIUM — code import but not in manifest
      LOW    — pattern in string literal / regex / comment

    Args:
        local_path: Path to the repository
        declared_deps: Pre-parsed dependency identifiers (optional)

    Returns:
        List of discovered data stores
    """
    if declared_deps is None:
        declared_deps = parse_dependency_manifests(local_path)

    data_stores = []
    store_id = 0
    found_stores: dict[str, Confidence] = {}

    for root, dirs, files in os.walk(local_path):
        dirs[:] = [
            d for d in dirs
            if d not in SKIP_DIRECTORIES and d not in _META_DIRECTORIES
        ]

        for filename in files:
            if not filename.endswith(('.ts', '.tsx', '.js', '.jsx', '.py', '.prisma')):
                continue

            filepath = os.path.join(root, filename)
            rel_path = os.path.relpath(filepath, local_path)

            try:
                with open(filepath, errors='ignore') as f:
                    content = f.read()
            except OSError:
                continue

            # For Python files, get real imports
            py_imports = _python_imports(content) if filename.endswith('.py') else set()

            for store_name, config in DATASTORE_PATTERNS.items():
                # Already found at HIGH confidence — skip
                if found_stores.get(store_name) == Confidence.HIGH:
                    continue

                for pattern in config["patterns"]:
                    match = re.search(pattern, content)
                    if not match:
                        continue

                    # Determine confidence
                    in_deps = store_name in declared_deps
                    in_string = _match_is_in_string_context(content, match.start())

                    if in_string:
                        confidence = Confidence.LOW
                    elif in_deps:
                        confidence = Confidence.HIGH
                    elif filename.endswith('.py'):
                        # Check Python imports for corroboration
                        # Map store names to expected import modules
                        import_hints = {
                            "postgresql": {"psycopg", "psycopg2", "asyncpg", "sqlalchemy"},
                            "mysql": {"pymysql", "mysqlclient", "mysql"},
                            "mongodb": {"pymongo"},
                            "redis": {"redis", "aioredis"},
                            "sqlite": {"sqlite3", "aiosqlite"},
                            "s3": {"boto3"},
                        }
                        expected = import_hints.get(store_name, set())
                        if py_imports & expected:
                            confidence = Confidence.MEDIUM
                        else:
                            confidence = Confidence.LOW
                    else:
                        confidence = Confidence.MEDIUM

                    # Only upgrade, never downgrade
                    prev = found_stores.get(store_name)
                    if prev is not None:
                        conf_order = {Confidence.HIGH: 2, Confidence.MEDIUM: 1, Confidence.LOW: 0}
                        if conf_order[confidence] <= conf_order[prev]:
                            continue

                    line_num = content[:match.start()].count('\n') + 1
                    store_id += 1

                    # Remove previous lower-confidence entry if upgrading
                    if prev is not None:
                        data_stores = [ds for ds in data_stores if ds.technology != store_name]

                    data_stores.append(DataStore(
                        id=f"DS-{store_id:03d}",
                        store_type=config["type"],
                        technology=store_name,
                        file=rel_path,
                        line=line_num,
                        confidence=confidence,
                    ))
                    found_stores[store_name] = confidence
                    break

    return data_stores


# ---------------------------------------------------------------------------
# Injection sink discovery
# ---------------------------------------------------------------------------

def discover_injection_sinks(local_path: str) -> list[dict[str, Any]]:
    """Discover potential injection vulnerabilities.

    Args:
        local_path: Path to the repository

    Returns:
        List of potential injection sinks with metadata
    """
    sinks = []

    for root, dirs, files in os.walk(local_path):
        dirs[:] = [
            d for d in dirs
            if d not in SKIP_DIRECTORIES and d not in _META_DIRECTORIES
        ]

        for filename in files:
            if not filename.endswith(('.ts', '.tsx', '.js', '.jsx', '.py')):
                continue

            filepath = os.path.join(root, filename)
            rel_path = os.path.relpath(filepath, local_path)

            try:
                with open(filepath, errors='ignore') as f:
                    content = f.read()
                    lines = content.split('\n')
            except OSError:
                continue

            for injection_type, config in INJECTION_PATTERNS.items():
                for pattern in config["patterns"]:
                    for i, line in enumerate(lines):
                        if _line_is_string_or_comment(line):
                            continue
                        if re.search(pattern, line):
                            sinks.append({
                                "type": injection_type,
                                "file": rel_path,
                                "line": i + 1,
                                "snippet": line.strip()[:100],
                                "severity": config["severity"],
                                "cwe": config["cwe"],
                                "recommendation": config["recommendation"]
                            })

    return sinks


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

def discover_all_assets(local_path: str, frameworks: list[str] | None = None) -> AssetInventory:
    """Discover all security-relevant assets in the codebase.

    Args:
        local_path: Path to the repository
        frameworks: Optional list of frameworks (auto-detected if not provided)

    Returns:
        Complete asset inventory
    """
    # Parse dependency manifests once, share across all discovery functions
    declared_deps = parse_dependency_manifests(local_path)

    if not frameworks:
        frameworks = detect_frameworks(local_path, declared_deps)

    return AssetInventory(
        entry_points=discover_entry_points(local_path, frameworks),
        data_stores=discover_data_stores(local_path, declared_deps),
        sensitive_data=discover_sensitive_data(local_path),
        secrets=discover_secrets(local_path),
        authentication=discover_authentication(local_path, declared_deps),
        frameworks_detected=frameworks
    )


__all__ = [
    "detect_frameworks",
    "discover_entry_points",
    "discover_authentication",
    "discover_sensitive_data",
    "discover_secrets",
    "discover_data_stores",
    "discover_injection_sinks",
    "discover_all_assets",
]
