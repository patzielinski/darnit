# Threat Model Report

## Executive Summary

**Generated:** 2026-04-12 19:15:28
**Repository:** `mlieberman85/darnit`
**Languages scanned:** python, yaml
**Frameworks detected:** mcp

🔴 **5 HIGH** severity findings identified.

| Risk Level | Count |
|------------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 5 |
| 🟡 Medium | 75 |
| 🟢 Low | 93 |
| ℹ️ Info | 0 |

## Asset Inventory

### Entry Points

| Kind | Framework | Method | Path / Name | Location |
|------|-----------|--------|-------------|----------|
| mcp_tool | mcp | — | `(dynamic — registered from registry.tools)` | `packages/darnit/src/darnit/server/factory.py:149` |
| mcp_tool | mcp | — | `(dynamic — registered from registry.tools)` | `packages/darnit/src/darnit/server/factory.py:195` |

### Data Stores

No data stores detected.

### Authentication Mechanisms

⚠️ No authentication decorators identified by the structural pipeline. This does NOT mean the application is unauthenticated — it means no recognized decorator pattern was found. Review the entry points above manually.

## Data Flow Diagram

```mermaid
flowchart LR
    User(["External Actor"])
    EP0["(dynamic — registered from registry.tools)"]
    EP1["(dynamic — registered from registry.tools)"]
    User --> EP0
    User --> EP1
```

## STRIDE Threats

### Spoofing

#### TM-S-001: Unauthenticated mcp tool (mcp): (dynamic — registered from registry.tools)

**Risk:** MEDIUM (severity × confidence = 4.25)
**Location:** `packages/darnit/src/darnit/server/factory.py:149`
**Source:** `tree_sitter_structural` — query `python.entry.mcp_tool_imperative`

No authentication decorator was found on this endpoint. If the endpoint handles sensitive actions, it may be accessible to unauthenticated callers. Verify whether authentication is enforced at a different layer (middleware, reverse proxy, MCP client credential check).

```
     139 |     server = FastMCP(server_name)
     140 | 
     141 |     # Register each tool
     142 |     registered_count = 0
     143 |     for name, spec in registry.tools.items():
     144 |         try:
     145 |             handler = registry.load_handler(spec, framework_name=framework_name)
     146 |             # Inject TOML config into handler if parameters are defined
     147 |             if spec.parameters:
     148 |                 handler = _bind_tool_config(handler, spec.parameters)
>>>  149 |             server.add_tool(handler, name=name, description=spec.description)
     150 |             registered_count += 1
     151 |             logger.debug(f"Registered tool: {name}")
     152 |         except (ImportError, AttributeError, ValueError) as e:
     153 |             logger.warning(f"Failed to load tool '{name}': {e}")
     154 |             continue
     155 | 
     156 |     logger.info(
     157 |         f"Created MCP server '{server_name}' with {registered_count} tools"
     158 |     )
     159 | 
```

#### TM-S-002: Unauthenticated mcp tool (mcp): (dynamic — registered from registry.tools)

**Risk:** MEDIUM (severity × confidence = 4.25)
**Location:** `packages/darnit/src/darnit/server/factory.py:195`
**Source:** `tree_sitter_structural` — query `python.entry.mcp_tool_imperative`

No authentication decorator was found on this endpoint. If the endpoint handles sensitive actions, it may be accessible to unauthenticated callers. Verify whether authentication is enforced at a different layer (middleware, reverse proxy, MCP client credential check).

```
     185 | 
     186 |     registry = ToolRegistry.from_toml(config)
     187 |     server = FastMCP(server_name)
     188 | 
     189 |     for name, spec in registry.tools.items():
     190 |         try:
     191 |             handler = registry.load_handler(spec, framework_name=framework_name)
     192 |             # Inject TOML config into handler if parameters are defined
     193 |             if spec.parameters:
     194 |                 handler = _bind_tool_config(handler, spec.parameters)
>>>  195 |             server.add_tool(handler, name=name, description=spec.description)
     196 |         except (ImportError, AttributeError, ValueError) as e:
     197 |             logger.warning(f"Failed to load tool '{name}': {e}")
     198 | 
     199 |     return server
```

### Tampering

#### TM-T-001: Potential command injection via subprocess.run

**Risk:** HIGH (severity × confidence = 5.40)
**Location:** `packages/darnit/src/darnit/core/adapters.py:231`
**Source:** `tree_sitter_structural` — query `python.sink.dangerous_attr`

[subprocess/dynamic] Entire command built dynamically — highest injection risk without taint confirmation. Command argument is populated from configuration/dict lookup within the same function scope. Opengrep taint analysis will lift confirmed cases to high confidence.

```
     221 |             # Add any extra config
     222 |             for key, value in config.items():
     223 |                 if isinstance(value, bool):
     224 |                     if value:
     225 |                         cmd.append(f"--{key}")
     226 |                 else:
     227 |                     cmd.extend([f"--{key}", str(value)])
     228 | 
     229 |             logger.debug(f"Running command: {' '.join(cmd)}")
     230 | 
>>>  231 |             result = subprocess.run(
     232 |                 cmd,
     233 |                 capture_output=True,
     234 |                 text=True,
     235 |                 timeout=self._timeout,
     236 |             )
     237 | 
     238 |             if self._output_format == "json":
     239 |                 try:
     240 |                     output = json.loads(result.stdout)
     241 |                     return CheckResult(
```

#### TM-T-002: Potential command injection via subprocess.run

**Risk:** HIGH (severity × confidence = 5.40)
**Location:** `packages/darnit/src/darnit/sieve/builtin_handlers.py:137`
**Source:** `tree_sitter_structural` — query `python.sink.dangerous_attr`

[subprocess/dynamic] Entire command built dynamically — highest injection risk without taint confirmation. Command argument is populated from configuration/dict lookup within the same function scope. Opengrep taint analysis will lift confirmed cases to high confidence.

```
     127 |     for arg in command:
     128 |         for var, val in substitutions.items():
     129 |             arg = arg.replace(var, val)
     130 |         resolved_cmd.append(arg)
     131 | 
     132 |     # Build environment
     133 |     env = os.environ.copy()
     134 |     env.update(env_extra)
     135 | 
     136 |     try:
>>>  137 |         proc = subprocess.run(
     138 |             resolved_cmd,
     139 |             capture_output=True,
     140 |             text=True,
     141 |             timeout=timeout,
     142 |             cwd=cwd,
     143 |             env=env,
     144 |         )
     145 |     except subprocess.TimeoutExpired:
     146 |         return HandlerResult(
     147 |             status=HandlerResultStatus.ERROR,
```

#### TM-T-003: Potential command injection via subprocess.run

**Risk:** HIGH (severity × confidence = 5.40)
**Location:** `packages/darnit-plugins/src/darnit_plugins/adapters/kusari.py:253`
**Source:** `tree_sitter_structural` — query `python.sink.dangerous_attr`

[subprocess/dynamic] Entire command built dynamically — highest injection risk without taint confirmation. Command argument is populated from configuration/dict lookup within the same function scope. Opengrep taint analysis will lift confirmed cases to high confidence.

```
     243 | 
     244 |         # Add optional URL overrides
     245 |         if config.get("console_url"):
     246 |             cmd.extend(["--console-url", config["console_url"]])
     247 |         if config.get("platform_url"):
     248 |             cmd.extend(["--platform-url", config["platform_url"]])
     249 | 
     250 |         logger.debug(f"Running Kusari command: {' '.join(cmd)}")
     251 | 
     252 |         try:
>>>  253 |             result = subprocess.run(
     254 |                 cmd,
     255 |                 capture_output=True,
     256 |                 text=True,
     257 |                 timeout=self._timeout,
     258 |             )
     259 | 
     260 |             # Parse the output based on format and control type
     261 |             return self._parse_result(
     262 |                 control_id=control_id,
     263 |                 returncode=result.returncode,
```

#### TM-T-004: Potential command injection via subprocess.run

**Risk:** HIGH (severity × confidence = 4.80)
**Location:** `packages/darnit-baseline/src/darnit_baseline/threat_model/opengrep_runner.py:131`
**Source:** `tree_sitter_structural` — query `python.sink.dangerous_attr`

[subprocess/dynamic] Entire command built dynamically — highest injection risk without taint confirmation. Opengrep taint analysis will lift confirmed cases to high confidence.

```
     121 |         "--timeout-threshold",
     122 |         "3",
     123 |         "--config",
     124 |         str(rules_dir),
     125 |         str(target),
     126 |     ]
     127 |     env = {**os.environ, "SEMGREP_SEND_METRICS": "off"}
     128 | 
     129 |     start = time.perf_counter()
     130 |     try:
>>>  131 |         proc = subprocess.run(  # noqa: S603 - trusted binary, known args
     132 |             argv,
     133 |             capture_output=True,
     134 |             text=True,
     135 |             timeout=timeout_s,
     136 |             env=env,
     137 |             check=False,
     138 |         )
     139 |     except subprocess.TimeoutExpired:
     140 |         reason = f"{binary_name} timed out after {timeout_s}s"
     141 |         logger.warning("opengrep degraded: %s", reason)
```

#### TM-T-005: Potential command injection via subprocess.run

**Risk:** HIGH (severity × confidence = 4.80)
**Location:** `packages/darnit/src/darnit/server/tools/git_operations.py:382`
**Source:** `tree_sitter_structural` — query `python.sink.dangerous_attr`

[subprocess/dynamic] Entire command built dynamically — highest injection risk without taint confirmation. Opengrep taint analysis will lift confirmed cases to high confidence.

```
     372 | *Generated by darnit compliance server*
     373 | """
     374 | 
     375 |         # Build gh pr create command
     376 |         cmd = ["gh", "pr", "create", "--title", title, "--body", body]
     377 |         if base_branch:
     378 |             cmd.extend(["--base", base_branch])
     379 |         if draft:
     380 |             cmd.append("--draft")
     381 | 
>>>  382 |         result = subprocess.run(
     383 |             cmd,
     384 |             cwd=resolved_path,
     385 |             capture_output=True,
     386 |             text=True
     387 |         )
     388 | 
     389 |         if result.returncode != 0:
     390 |             error_msg = result.stderr.strip()
     391 |             if "already exists" in error_msg.lower():
     392 |                 # PR already exists, try to get URL
```

#### TM-T-006: Potential command injection via subprocess.run

**Risk:** MEDIUM (severity × confidence = 2.40)
**Location:** `docs/examples/python-framework/example_framework/implementation.py:400`
**Source:** `tree_sitter_structural` — query `python.sink.dangerous_attr`

[subprocess/parameterized] Command list contains variable arguments that may originate from external input. Opengrep taint analysis will lift confirmed cases to high confidence.

```
     390 |         message="No dependency scanning configuration found",
     391 |         level=3,
     392 |         domain="VM",
     393 |         details={"searched": scanning_patterns},
     394 |     )
     395 | 
     396 | 
     397 | def check_sbom_compliance(local_path: str) -> CheckResult:
     398 |     """Check EXAMPLE-VM-02: SBOM compliance using external tool."""
     399 |     try:
>>>  400 |         result = subprocess.run(
     401 |             ["kusari", "repo", "scan", local_path, "HEAD"],
     402 |             capture_output=True,
     403 |             text=True,
     404 |             timeout=120,
     405 |         )
     406 | 
     407 |         if result.returncode == 0:
     408 |             return CheckResult(
     409 |                 id="EXAMPLE-VM-02",
     410 |                 name="SBOMCompliance",
```

#### TM-T-007: Potential command injection via subprocess.run

**Risk:** MEDIUM (severity × confidence = 2.40)
**Location:** `docs/examples/python-framework/example_framework/implementation.py:603`
**Source:** `tree_sitter_structural` — query `python.sink.dangerous_attr`

[subprocess/parameterized] Command list contains variable arguments that may originate from external input. Opengrep taint analysis will lift confirmed cases to high confidence.

```
     593 |         "allow_force_pushes": False,
     594 |         "allow_deletions": False,
     595 |     }
     596 | 
     597 |     endpoint = f"/repos/{owner}/{repo}/branches/{branch}/protection"
     598 | 
     599 |     if dry_run:
     600 |         return f"Would call: PUT {endpoint}\nPayload: {json.dumps(payload, indent=2)}"
     601 | 
     602 |     try:
>>>  603 |         result = subprocess.run(
     604 |             ["gh", "api", "-X", "PUT", endpoint, "--input", "-"],
     605 |             input=json.dumps(payload),
     606 |             capture_output=True,
     607 |             text=True,
     608 |             timeout=30,
     609 |         )
     610 | 
     611 |         if result.returncode == 0:
     612 |             return f"Branch protection enabled for {branch}"
     613 |         else:
```

#### TM-T-008: Potential command injection via subprocess.run

**Risk:** MEDIUM (severity × confidence = 2.40)
**Location:** `scripts/create-example-test-repo.py:142`
**Source:** `tree_sitter_structural` — query `python.sink.dangerous_attr`

[subprocess/parameterized] Command list contains variable arguments that may originate from external input. Opengrep taint analysis will lift confirmed cases to high confidence.

```
     132 |     (repo_path / "CLAUDE.md").write_text(claude_md)
     133 | 
     134 |     # -- Initialize git -------------------------------------------------------
     135 |     try:
     136 |         subprocess.run(
     137 |             ["git", "init"], cwd=repo_path, capture_output=True, check=True
     138 |         )
     139 |         subprocess.run(
     140 |             ["git", "add", "."], cwd=repo_path, capture_output=True, check=True
     141 |         )
>>>  142 |         subprocess.run(
     143 |             [
     144 |                 "git",
     145 |                 "commit",
     146 |                 "-m",
     147 |                 "Initial commit - intentionally non-compliant\n\n"
     148 |                 "This repository is designed for testing Project Hygiene Standard\n"
     149 |                 "compliance. It intentionally fails all 8 PH controls.",
     150 |             ],
     151 |             cwd=repo_path,
     152 |             capture_output=True,
```

#### TM-T-009: Potential command injection via subprocess.run

**Risk:** MEDIUM (severity × confidence = 2.40)
**Location:** `scripts/create-example-test-repo.py:308`
**Source:** `tree_sitter_structural` — query `python.sink.dangerous_attr`

[subprocess/parameterized] Command list contains variable arguments that may originate from external input. Opengrep taint analysis will lift confirmed cases to high confidence.

```
     298 |             ["gh", "api", "user", "--jq", ".login"],
     299 |             capture_output=True,
     300 |             text=True,
     301 |         )
     302 |         github_org = result.stdout.strip()
     303 |         print(f"\033[1;33mUsing GitHub user: {github_org}\033[0m")
     304 | 
     305 |     print(f"\033[0;32mCreating GitHub repository: {github_org}/{repo_name}\033[0m")
     306 | 
     307 |     try:
>>>  308 |         subprocess.run(
     309 |             [
     310 |                 "gh",
     311 |                 "repo",
     312 |                 "create",
     313 |                 f"{github_org}/{repo_name}",
     314 |                 "--public",
     315 |                 "--source",
     316 |                 str(repo_path),
     317 |                 "--remote",
     318 |                 "origin",
```

#### TM-T-010: Potential command injection via subprocess.run

**Risk:** MEDIUM (severity × confidence = 2.40)
**Location:** `packages/darnit-baseline/src/darnit_baseline/threat_model/ts_generators.py:123`
**Source:** `tree_sitter_structural` — query `python.sink.dangerous_attr`

[subprocess/parameterized] Command list contains variable arguments that may originate from external input. Opengrep taint analysis will lift confirmed cases to high confidence.

```
     113 | # ---------------------------------------------------------------------------
     114 | 
     115 | 
     116 | def _repo_display_name(repo_path: str) -> str:
     117 |     """Derive a safe display name for the repository.
     118 | 
     119 |     Tries git remote URL first (``owner/repo``), then falls back to the
     120 |     directory basename.  Never leaks an absolute local path.
     121 |     """
     122 |     try:
>>>  123 |         proc = subprocess.run(  # noqa: S603,S607
     124 |             ["git", "-C", repo_path, "remote", "get-url", "origin"],
     125 |             capture_output=True,
     126 |             text=True,
     127 |             timeout=5,
     128 |         )
     129 |         if proc.returncode == 0:
     130 |             url = proc.stdout.strip()
     131 |             # SSH: git@github.com:owner/repo.git  or  HTTPS: …/owner/repo.git
     132 |             m = re.search(r"[:/]([^/:]+/[^/]+?)(?:\.git)?$", url)
     133 |             if m:
```

#### TM-T-011: Potential command injection via subprocess.run

**Risk:** MEDIUM (severity × confidence = 2.40)
**Location:** `packages/darnit-baseline/src/darnit_baseline/threat_model/opengrep_runner.py:64`
**Source:** `tree_sitter_structural` — query `python.sink.dangerous_attr`

[subprocess/parameterized] Command list contains variable arguments that may originate from external input. Opengrep taint analysis will lift confirmed cases to high confidence.

```
      54 |     """
      55 |     for candidate in ("opengrep", "semgrep"):
      56 |         path = shutil.which(candidate)
      57 |         if path:
      58 |             return path, candidate
      59 |     return None
      60 | 
      61 | 
      62 | def _capture_version(binary: str) -> str | None:
      63 |     try:
>>>   64 |         proc = subprocess.run(  # noqa: S603 - trusted binary, fixed args
      65 |             [binary, "--version"],
      66 |             capture_output=True,
      67 |             text=True,
      68 |             timeout=5,
      69 |             check=False,
      70 |         )
      71 |         if proc.returncode == 0:
      72 |             return proc.stdout.strip()
      73 |     except (subprocess.TimeoutExpired, OSError) as e:
      74 |         logger.debug("failed to capture %s version: %s", binary, e)
```

#### TM-T-012: Potential command injection via subprocess.run

**Risk:** MEDIUM (severity × confidence = 2.40)
**Location:** `packages/darnit/src/darnit/tools/audit_org.py:62`
**Source:** `tree_sitter_structural` — query `python.sink.dangerous_attr`

[subprocess/parameterized] Command list contains variable arguments that may originate from external input. Opengrep taint analysis will lift confirmed cases to high confidence.

```
      52 |         )
      53 |         if result.returncode != 0:
      54 |             return [], "gh CLI is not authenticated. Run 'gh auth login' first."
      55 |     except FileNotFoundError:
      56 |         return [], "gh CLI is required for org-wide audits but was not found."
      57 |     except subprocess.TimeoutExpired:
      58 |         return [], "gh CLI timed out checking auth status."
      59 | 
      60 |     # Enumerate repos
      61 |     try:
>>>   62 |         result = subprocess.run(
      63 |             [
      64 |                 "gh", "repo", "list", owner,
      65 |                 "--json", "name,isArchived",
      66 |                 "--limit", "500",
      67 |             ],
      68 |             capture_output=True,
      69 |             text=True,
      70 |             timeout=60,
      71 |         )
      72 |         if result.returncode != 0:
```

#### TM-T-013: Potential command injection via subprocess.run

**Risk:** MEDIUM (severity × confidence = 2.40)
**Location:** `packages/darnit/src/darnit/tools/audit_org.py:113`
**Source:** `tree_sitter_structural` — query `python.sink.dangerous_attr`

[subprocess/parameterized] Command list contains variable arguments that may originate from external input. Opengrep taint analysis will lift confirmed cases to high confidence.

```
     103 | 
     104 |     Args:
     105 |         owner: GitHub org or user
     106 |         repo: Repository name
     107 |         target_dir: Directory to clone into
     108 | 
     109 |     Returns:
     110 |         True if clone succeeded, False otherwise
     111 |     """
     112 |     try:
>>>  113 |         result = subprocess.run(
     114 |             ["gh", "repo", "clone", f"{owner}/{repo}", target_dir, "--", "--depth", "1"],
     115 |             capture_output=True,
     116 |             text=True,
     117 |             timeout=120,
     118 |         )
     119 |         if result.returncode != 0:
     120 |             logger.warning(
     121 |                 "Failed to clone %s/%s: %s", owner, repo, result.stderr.strip()
     122 |             )
     123 |             return False
```

#### TM-T-014: Potential command injection via subprocess.run

**Risk:** MEDIUM (severity × confidence = 2.40)
**Location:** `packages/darnit/src/darnit/context/auto_detect.py:518`
**Source:** `tree_sitter_structural` — query `python.sink.dangerous_attr`

[subprocess/parameterized] Command list contains variable arguments that may originate from external input. Opengrep taint analysis will lift confirmed cases to high confidence.

```
     508 | 
     509 | 
     510 | # ---------------------------------------------------------------------------
     511 | # Internal helpers
     512 | # ---------------------------------------------------------------------------
     513 | 
     514 | 
     515 | def _get_remote_url(remote_name: str, cwd: str) -> str | None:
     516 |     """Get the URL of a named git remote."""
     517 |     try:
>>>  518 |         result = subprocess.run(
     519 |             ["git", "remote", "get-url", remote_name],
     520 |             capture_output=True,
     521 |             text=True,
     522 |             cwd=cwd,
     523 |             timeout=5,
     524 |         )
     525 |         if result.returncode == 0:
     526 |             return result.stdout.strip()
     527 |     except (subprocess.SubprocessError, FileNotFoundError, OSError):
     528 |         pass
```

#### TM-T-015: Potential command injection via subprocess.run

**Risk:** MEDIUM (severity × confidence = 2.40)
**Location:** `packages/darnit/src/darnit/core/utils.py:27`
**Source:** `tree_sitter_structural` — query `python.sink.dangerous_attr`

[subprocess/parameterized] Command list contains variable arguments that may originate from external input. Opengrep taint analysis will lift confirmed cases to high confidence.

```
      17 | )
      18 | 
      19 | 
      20 | def gh_api(endpoint: str) -> dict[str, Any]:
      21 |     """Execute a GitHub API call using the gh CLI.
      22 | 
      23 |     Raises:
      24 |         RuntimeError: If the API call fails or returns invalid JSON.
      25 |     """
      26 |     try:
>>>   27 |         result = subprocess.run(
      28 |             ["gh", "api", endpoint],
      29 |             capture_output=True,
      30 |             text=True
      31 |         )
      32 |     except FileNotFoundError:
      33 |         raise RuntimeError(_GH_CLI_MISSING_MESSAGE) from None
      34 | 
      35 |     if result.returncode != 0:
      36 |         error_msg = result.stderr.strip() or "Unknown error"
      37 |         raise RuntimeError(f"gh api failed: {error_msg}")
```

#### TM-T-016: Potential command injection via subprocess.run

**Risk:** MEDIUM (severity × confidence = 2.40)
**Location:** `packages/darnit/src/darnit/core/utils.py:99`
**Source:** `tree_sitter_structural` — query `python.sink.dangerous_attr`

[subprocess/parameterized] Command list contains variable arguments that may originate from external input. Opengrep taint analysis will lift confirmed cases to high confidence.

```
      89 |                 f"Note: When using MCP tools, '.' resolves to the MCP server's directory, "
      90 |                 f"not your current working directory. Please provide an absolute path instead."
      91 |             )
      92 |         return abs_path, f"Path is not a git repository (no .git directory): {abs_path}"
      93 | 
      94 |     # If local_path is "." and we have expected owner/repo, do extra validation
      95 |     if local_path == "." and expected_owner and expected_repo:
      96 |         dir_name = os.path.basename(abs_path)
      97 |         if dir_name.lower() != expected_repo.lower():
      98 |             try:
>>>   99 |                 result = subprocess.run(
     100 |                     ["git", "-C", abs_path, "remote", "get-url", "origin"],
     101 |                     capture_output=True, text=True, timeout=5
     102 |                 )
     103 |                 if result.returncode == 0:
     104 |                     remote_url = result.stdout.strip()
     105 |                     match = re.search(r'[:/]([^/:]+)/([^/]+?)(?:\.git)?$', remote_url)
     106 |                     if match:
     107 |                         detected_owner, detected_repo = match.groups()
     108 |                         if detected_owner.lower() != expected_owner.lower() or detected_repo.lower() != expected_repo.lower():
     109 |                             return abs_path, (
```

#### TM-T-017: Potential command injection via subprocess.run

**Risk:** MEDIUM (severity × confidence = 2.40)
**Location:** `packages/darnit/src/darnit/core/utils.py:161`
**Source:** `tree_sitter_structural` — query `python.sink.dangerous_attr`

[subprocess/parameterized] Command list contains variable arguments that may originate from external input. Opengrep taint analysis will lift confirmed cases to high confidence.

```
     151 |                     f"Solution: Use an absolute path:\n"
     152 |                     f"  local_path=\"/path/to/{expected_repo}\""
     153 |                 )
     154 | 
     155 |     return abs_path, None
     156 | 
     157 | 
     158 | def _get_remote_url(remote_name: str, cwd: str) -> str | None:
     159 |     """Get the URL of a named git remote."""
     160 |     try:
>>>  161 |         result = subprocess.run(
     162 |             ["git", "remote", "get-url", remote_name],
     163 |             capture_output=True,
     164 |             text=True,
     165 |             cwd=cwd,
     166 |             timeout=5,
     167 |         )
     168 |         if result.returncode == 0:
     169 |             return result.stdout.strip()
     170 |     except (subprocess.SubprocessError, FileNotFoundError):
     171 |         pass
```

#### TM-T-018: Potential command injection via subprocess.run

**Risk:** MEDIUM (severity × confidence = 2.40)
**Location:** `packages/darnit/src/darnit/core/utils.py:367`
**Source:** `tree_sitter_structural` — query `python.sink.dangerous_attr`

[subprocess/parameterized] Command list contains variable arguments that may originate from external input. Opengrep taint analysis will lift confirmed cases to high confidence.

```
     357 | 
     358 | 
     359 | def make_result(control_id: str, status: str, details: str, level: int = 1) -> dict[str, Any]:
     360 |     """Create a standardized result dictionary."""
     361 |     return {"id": control_id, "status": status, "details": details, "level": level}
     362 | 
     363 | 
     364 | def get_git_commit(local_path: str) -> str | None:
     365 |     """Get the current git commit SHA."""
     366 |     try:
>>>  367 |         result = subprocess.run(
     368 |             ["git", "-C", local_path, "rev-parse", "HEAD"],
     369 |             capture_output=True,
     370 |             text=True,
     371 |             timeout=10
     372 |         )
     373 |         if result.returncode == 0:
     374 |             return result.stdout.strip()
     375 |     except subprocess.TimeoutExpired:
     376 |         logger.warning(f"git rev-parse timed out for {local_path}")
     377 |     except (FileNotFoundError, OSError, subprocess.SubprocessError) as e:
```

#### TM-T-019: Potential command injection via subprocess.run

**Risk:** MEDIUM (severity × confidence = 2.40)
**Location:** `packages/darnit/src/darnit/core/utils.py:385`
**Source:** `tree_sitter_structural` — query `python.sink.dangerous_attr`

[subprocess/parameterized] Command list contains variable arguments that may originate from external input. Opengrep taint analysis will lift confirmed cases to high confidence.

```
     375 |     except subprocess.TimeoutExpired:
     376 |         logger.warning(f"git rev-parse timed out for {local_path}")
     377 |     except (FileNotFoundError, OSError, subprocess.SubprocessError) as e:
     378 |         logger.debug(f"git rev-parse failed: {type(e).__name__}")
     379 |     return None
     380 | 
     381 | 
     382 | def get_git_ref(local_path: str) -> str | None:
     383 |     """Get the current git branch/ref."""
     384 |     try:
>>>  385 |         result = subprocess.run(
     386 |             ["git", "-C", local_path, "rev-parse", "--abbrev-ref", "HEAD"],
     387 |             capture_output=True,
     388 |             text=True,
     389 |             timeout=10
     390 |         )
     391 |         if result.returncode == 0:
     392 |             ref = result.stdout.strip()
     393 |             if ref != "HEAD":
     394 |                 return ref
     395 |         # Try to get tag
```

#### TM-T-020: Potential command injection via subprocess.run

**Risk:** MEDIUM (severity × confidence = 2.40)
**Location:** `packages/darnit/src/darnit/core/utils.py:396`
**Source:** `tree_sitter_structural` — query `python.sink.dangerous_attr`

[subprocess/parameterized] Command list contains variable arguments that may originate from external input. Opengrep taint analysis will lift confirmed cases to high confidence.

```
     386 |             ["git", "-C", local_path, "rev-parse", "--abbrev-ref", "HEAD"],
     387 |             capture_output=True,
     388 |             text=True,
     389 |             timeout=10
     390 |         )
     391 |         if result.returncode == 0:
     392 |             ref = result.stdout.strip()
     393 |             if ref != "HEAD":
     394 |                 return ref
     395 |         # Try to get tag
>>>  396 |         result = subprocess.run(
     397 |             ["git", "-C", local_path, "describe", "--tags", "--exact-match"],
     398 |             capture_output=True,
     399 |             text=True,
     400 |             timeout=10
     401 |         )
     402 |         if result.returncode == 0:
     403 |             return result.stdout.strip()
     404 |     except subprocess.TimeoutExpired:
     405 |         logger.warning(f"git ref command timed out for {local_path}")
     406 |     except (FileNotFoundError, OSError, subprocess.SubprocessError) as e:
```

#### TM-T-021: Potential command injection via subprocess.run

**Risk:** MEDIUM (severity × confidence = 2.40)
**Location:** `packages/darnit/src/darnit/core/adapters.py:354`
**Source:** `tree_sitter_structural` — query `python.sink.dangerous_attr`

[subprocess/parameterized] Command list contains variable arguments that may originate from external input. Opengrep taint analysis will lift confirmed cases to high confidence.

```
     344 |                 "REPO": repo or "",
     345 |                 "LOCAL_PATH": local_path or ".",
     346 |             }
     347 | 
     348 |             # Add config as env vars
     349 |             for key, value in config.items():
     350 |                 env[f"CONFIG_{key.upper()}"] = str(value)
     351 | 
     352 |             logger.debug(f"Running script: {self._script_path}")
     353 | 
>>>  354 |             result = subprocess.run(
     355 |                 [self._script_path],
     356 |                 capture_output=True,
     357 |                 text=True,
     358 |                 timeout=self._timeout,
     359 |                 env={**dict(_os.environ), **env},
     360 |             )
     361 | 
     362 |             if self._output_format == "json":
     363 |                 try:
     364 |                     output = json.loads(result.stdout)
```

#### TM-T-022: Potential command injection via subprocess.run

**Risk:** MEDIUM (severity × confidence = 2.40)
**Location:** `packages/darnit/src/darnit/server/tools/test_repository.py:141`
**Source:** `tree_sitter_structural` — query `python.sink.dangerous_attr`

[subprocess/parameterized] Command list contains variable arguments that may originate from external input. Opengrep taint analysis will lift confirmed cases to high confidence.

```
     131 |                 # Get org if not specified
     132 |                 if not github_org:
     133 |                     result = subprocess.run(
     134 |                         ["gh", "api", "user", "--jq", ".login"],
     135 |                         capture_output=True,
     136 |                         text=True
     137 |                     )
     138 |                     github_org = result.stdout.strip()
     139 | 
     140 |                 # Create GitHub repo
>>>  141 |                 subprocess.run(
     142 |                     [
     143 |                         "gh", "repo", "create", f"{github_org}/{repo_name}",
     144 |                         "--public",
     145 |                         "--source", repo_path,
     146 |                         "--remote", "origin",
     147 |                         "--description", "OpenSSF Baseline test repo - intentionally non-compliant",
     148 |                         "--push"
     149 |                     ],
     150 |                     capture_output=True,
     151 |                     check=True
```

#### TM-T-023: Potential command injection via subprocess.run

**Risk:** MEDIUM (severity × confidence = 2.40)
**Location:** `packages/darnit/src/darnit/server/tools/git_operations.py:45`
**Source:** `tree_sitter_structural` — query `python.sink.dangerous_attr`

[subprocess/parameterized] Command list contains variable arguments that may originate from external input. Opengrep taint analysis will lift confirmed cases to high confidence.

```
      35 |                 ["git", "rev-parse", "--abbrev-ref", "HEAD"],
      36 |                 cwd=resolved_path,
      37 |                 capture_output=True,
      38 |                 text=True
      39 |             )
      40 |             if result.returncode != 0:
      41 |                 return "❌ Error: Not a git repository or git not available"
      42 |             base_branch = result.stdout.strip()
      43 | 
      44 |         # Check if branch already exists
>>>   45 |         result = subprocess.run(
      46 |             ["git", "rev-parse", "--verify", branch_name],
      47 |             cwd=resolved_path,
      48 |             capture_output=True,
      49 |             text=True
      50 |         )
      51 |         if result.returncode == 0:
      52 |             # Branch exists, check it out (stash dirty files if needed)
      53 |             result = subprocess.run(
      54 |                 ["git", "checkout", branch_name],
      55 |                 cwd=resolved_path,
```

#### TM-T-024: Potential command injection via subprocess.run

**Risk:** MEDIUM (severity × confidence = 2.40)
**Location:** `packages/darnit/src/darnit/server/tools/git_operations.py:53`
**Source:** `tree_sitter_structural` — query `python.sink.dangerous_attr`

[subprocess/parameterized] Command list contains variable arguments that may originate from external input. Opengrep taint analysis will lift confirmed cases to high confidence.

```
      43 | 
      44 |         # Check if branch already exists
      45 |         result = subprocess.run(
      46 |             ["git", "rev-parse", "--verify", branch_name],
      47 |             cwd=resolved_path,
      48 |             capture_output=True,
      49 |             text=True
      50 |         )
      51 |         if result.returncode == 0:
      52 |             # Branch exists, check it out (stash dirty files if needed)
>>>   53 |             result = subprocess.run(
      54 |                 ["git", "checkout", branch_name],
      55 |                 cwd=resolved_path,
      56 |                 capture_output=True,
      57 |                 text=True
      58 |             )
      59 |             if result.returncode != 0:
      60 |                 if "local changes" in result.stderr or "would be overwritten" in result.stderr:
      61 |                     stash_result = subprocess.run(
      62 |                         ["git", "stash", "--include-untracked"],
      63 |                         cwd=resolved_path, capture_output=True, text=True,
```

#### TM-T-025: Potential command injection via subprocess.run

**Risk:** MEDIUM (severity × confidence = 2.40)
**Location:** `packages/darnit/src/darnit/server/tools/git_operations.py:68`
**Source:** `tree_sitter_structural` — query `python.sink.dangerous_attr`

[subprocess/parameterized] Command list contains variable arguments that may originate from external input. Opengrep taint analysis will lift confirmed cases to high confidence.

```
      58 |             )
      59 |             if result.returncode != 0:
      60 |                 if "local changes" in result.stderr or "would be overwritten" in result.stderr:
      61 |                     stash_result = subprocess.run(
      62 |                         ["git", "stash", "--include-untracked"],
      63 |                         cwd=resolved_path, capture_output=True, text=True,
      64 |                     )
      65 |                     if stash_result.returncode != 0:
      66 |                         return f"❌ Error stashing changes: {stash_result.stderr.strip()}"
      67 | 
>>>   68 |                     checkout_result = subprocess.run(
      69 |                         ["git", "checkout", branch_name],
      70 |                         cwd=resolved_path, capture_output=True, text=True,
      71 |                     )
      72 |                     if checkout_result.returncode != 0:
      73 |                         subprocess.run(["git", "stash", "pop"], cwd=resolved_path,
      74 |                                        capture_output=True, text=True)
      75 |                         return f"❌ Error checking out branch: {checkout_result.stderr.strip()}"
      76 | 
      77 |                     pop_result = subprocess.run(
      78 |                         ["git", "stash", "pop"],
```

#### TM-T-026: Potential command injection via subprocess.run

**Risk:** MEDIUM (severity × confidence = 2.40)
**Location:** `packages/darnit/src/darnit/server/tools/git_operations.py:98`
**Source:** `tree_sitter_structural` — query `python.sink.dangerous_attr`

[subprocess/parameterized] Command list contains variable arguments that may originate from external input. Opengrep taint analysis will lift confirmed cases to high confidence.

```
      88 | 
      89 |             return f"""✅ Switched to existing branch '{branch_name}'
      90 | 
      91 | **Next steps:**
      92 | 1. Apply remediations: `remediate_audit_findings(local_path="{resolved_path}", dry_run=False)`
      93 | 2. Commit changes: `commit_remediation_changes(local_path="{resolved_path}")`
      94 | 3. Create PR: `create_remediation_pr(local_path="{resolved_path}")`
      95 | """
      96 | 
      97 |         # Create and checkout new branch (preserves dirty working tree)
>>>   98 |         result = subprocess.run(
      99 |             ["git", "checkout", "-b", branch_name],
     100 |             cwd=resolved_path,
     101 |             capture_output=True,
     102 |             text=True
     103 |         )
     104 |         if result.returncode != 0:
     105 |             return f"❌ Error creating branch: {result.stderr.strip()}"
     106 | 
     107 |         return f"""✅ Created and switched to branch '{branch_name}'
     108 | 
```

#### TM-T-027: Potential command injection via subprocess.run

**Risk:** MEDIUM (severity × confidence = 2.40)
**Location:** `packages/darnit/src/darnit/server/tools/git_operations.py:209`
**Source:** `tree_sitter_structural` — query `python.sink.dangerous_attr`

[subprocess/parameterized] Command list contains variable arguments that may originate from external input. Opengrep taint analysis will lift confirmed cases to high confidence.

```
     199 |                 message = f"chore(security): add {items} for compliance"
     200 |             else:
     201 |                 message = "chore(security): apply compliance remediations"
     202 | 
     203 |         # Add trailer
     204 |         full_message = f"""{message}
     205 | 
     206 | Applied via darnit compliance server."""
     207 | 
     208 |         # Commit
>>>  209 |         result = subprocess.run(
     210 |             ["git", "commit", "-m", full_message],
     211 |             cwd=resolved_path,
     212 |             capture_output=True,
     213 |             text=True
     214 |         )
     215 |         if result.returncode != 0:
     216 |             error_msg = result.stderr.strip()
     217 |             if "nothing to commit" in error_msg.lower():
     218 |                 return "ℹ️ No changes to commit."
     219 |             return f"❌ Error committing: {error_msg}"
```

#### TM-T-028: Potential command injection via subprocess.run

**Risk:** MEDIUM (severity × confidence = 2.40)
**Location:** `packages/darnit/src/darnit/server/tools/git_operations.py:295`
**Source:** `tree_sitter_structural` — query `python.sink.dangerous_attr`

[subprocess/parameterized] Command list contains variable arguments that may originate from external input. Opengrep taint analysis will lift confirmed cases to high confidence.

```
     285 |         current_branch = result.stdout.strip()
     286 | 
     287 |         if current_branch in ["main", "master"]:
     288 |             return f"""❌ Error: Cannot create PR from '{current_branch}' branch.
     289 | 
     290 | Create a remediation branch first:
     291 | `create_remediation_branch(local_path="{resolved_path}")`
     292 | """
     293 | 
     294 |         # Push branch to remote
>>>  295 |         result = subprocess.run(
     296 |             ["git", "push", "-u", "origin", current_branch],
     297 |             cwd=resolved_path,
     298 |             capture_output=True,
     299 |             text=True
     300 |         )
     301 |         if result.returncode != 0:
     302 |             error_msg = result.stderr.strip()
     303 |             if "already exists" not in error_msg.lower() and "up-to-date" not in error_msg.lower():
     304 |                 return f"❌ Error pushing branch: {error_msg}"
     305 | 
```

#### TM-T-029: Potential command injection via subprocess.run

**Risk:** MEDIUM (severity × confidence = 2.40)
**Location:** `packages/darnit/src/darnit/remediation/github.py:268`
**Source:** `tree_sitter_structural` — query `python.sink.dangerous_attr`

[subprocess/parameterized] Command list contains variable arguments that may originate from external input. Opengrep taint analysis will lift confirmed cases to high confidence.

```
     258 | - OSPS-AC-03.02: Branch deletion prevented
     259 | - OSPS-QA-07.01: {"Peer review required" if require_pull_request and required_approvals >= 1 else "⚠️ NOT SATISFIED (no peer review requirement)"}
     260 | 
     261 | **To apply:** Run again with `dry_run=False`
     262 | """
     263 | 
     264 |     # IMPORTANT: Use --input - to pass JSON body via stdin
     265 |     # This avoids shell escaping issues with -f flags that cause
     266 |     # "is not an object" errors from GitHub's API
     267 |     try:
>>>  268 |         result = subprocess.run(
     269 |             [
     270 |                 "gh", "api",
     271 |                 "-X", "PUT",
     272 |                 endpoint,
     273 |                 "-H", "Accept: application/vnd.github+json",
     274 |                 "--input", "-"
     275 |             ],
     276 |             input=config_json,
     277 |             capture_output=True,
     278 |             text=True,
```

#### Low-risk findings (50)

| # | Title | Location | Score |
|---|-------|----------|-------|
| TM-T-030 | Potential command injection via subprocess.run | `docs/examples/python-framework/example_framework/implementation.py:317` | 0.20 |
| TM-T-031 | Potential command injection via subprocess.run | `scripts/create-example-test-repo.py:136` | 0.20 |
| TM-T-032 | Potential command injection via subprocess.run | `scripts/create-example-test-repo.py:139` | 0.20 |
| TM-T-033 | Potential command injection via subprocess.run | `scripts/create-example-test-repo.py:280` | 0.20 |
| TM-T-034 | Potential command injection via subprocess.run | `scripts/create-example-test-repo.py:297` | 0.20 |
| TM-T-035 | Potential command injection via subprocess.run | `scripts/create-example-test-repo.py:329` | 0.20 |
| TM-T-036 | Potential command injection via subprocess.run | `packages/darnit-baseline/src/darnit_baseline/tools.py:1307` | 0.20 |
| TM-T-037 | Potential command injection via subprocess.run | `packages/darnit-baseline/src/darnit_baseline/attestation/git.py:24` | 0.20 |
| TM-T-038 | Potential command injection via subprocess.run | `packages/darnit-baseline/src/darnit_baseline/attestation/git.py:48` | 0.20 |
| TM-T-039 | Potential command injection via subprocess.run | `packages/darnit-baseline/src/darnit_baseline/attestation/git.py:60` | 0.20 |
| TM-T-040 | Potential command injection via subprocess.run | `packages/darnit-baseline/src/darnit_baseline/remediation/scanner.py:481` | 0.20 |
| TM-T-041 | Potential command injection via subprocess.run | `packages/darnit/src/darnit/cli.py:652` | 0.20 |
| TM-T-042 | Potential command injection via subprocess.run | `packages/darnit/src/darnit/tools/audit_org.py:47` | 0.20 |
| TM-T-043 | Potential command injection via subprocess.run | `packages/darnit/src/darnit/tools/audit_org.py:416` | 0.20 |
| TM-T-044 | Potential command injection via subprocess.run | `packages/darnit/src/darnit/context/dot_project_org.py:82` | 0.20 |
| TM-T-045 | Potential command injection via subprocess.run | `packages/darnit/src/darnit/context/dot_project_org.py:99` | 0.20 |
| TM-T-046 | Potential command injection via subprocess.run | `packages/darnit/src/darnit/context/dot_project_org.py:120` | 0.20 |
| TM-T-047 | Potential command injection via subprocess.run | `packages/darnit/src/darnit/context/sieve.py:394` | 0.20 |
| TM-T-048 | Potential command injection via subprocess.run | `packages/darnit/src/darnit/context/sieve.py:637` | 0.20 |
| TM-T-049 | Potential command injection via subprocess.run | `packages/darnit/src/darnit/context/detectors.py:11` | 0.20 |
| TM-T-050 | Potential command injection via subprocess.run | `packages/darnit/src/darnit/core/utils.py:272` | 0.20 |
| TM-T-051 | Potential command injection via subprocess.run | `packages/darnit/src/darnit/core/audit_cache.py:62` | 0.20 |
| TM-T-052 | Potential command injection via subprocess.run | `packages/darnit/src/darnit/core/audit_cache.py:79` | 0.20 |
| TM-T-053 | Potential command injection via subprocess.run | `packages/darnit/src/darnit/server/tools/test_repository.py:83` | 0.20 |
| TM-T-054 | Potential command injection via subprocess.run | `packages/darnit/src/darnit/server/tools/test_repository.py:89` | 0.20 |
| TM-T-055 | Potential command injection via subprocess.run | `packages/darnit/src/darnit/server/tools/test_repository.py:95` | 0.20 |
| TM-T-056 | Potential command injection via subprocess.run | `packages/darnit/src/darnit/server/tools/test_repository.py:123` | 0.20 |
| TM-T-057 | Potential command injection via subprocess.run | `packages/darnit/src/darnit/server/tools/test_repository.py:133` | 0.20 |
| TM-T-058 | Potential command injection via subprocess.run | `packages/darnit/src/darnit/server/tools/test_repository.py:157` | 0.20 |
| TM-T-059 | Potential command injection via subprocess.run | `packages/darnit/src/darnit/server/tools/git_operations.py:34` | 0.20 |
| TM-T-060 | Potential command injection via subprocess.run | `packages/darnit/src/darnit/server/tools/git_operations.py:61` | 0.20 |
| TM-T-061 | Potential command injection via subprocess.run | `packages/darnit/src/darnit/server/tools/git_operations.py:73` | 0.20 |
| TM-T-062 | Potential command injection via subprocess.run | `packages/darnit/src/darnit/server/tools/git_operations.py:77` | 0.20 |
| TM-T-063 | Potential command injection via subprocess.run | `packages/darnit/src/darnit/server/tools/git_operations.py:82` | 0.20 |
| TM-T-064 | Potential command injection via subprocess.run | `packages/darnit/src/darnit/server/tools/git_operations.py:84` | 0.20 |
| TM-T-065 | Potential command injection via subprocess.run | `packages/darnit/src/darnit/server/tools/git_operations.py:144` | 0.20 |
| TM-T-066 | Potential command injection via subprocess.run | `packages/darnit/src/darnit/server/tools/git_operations.py:168` | 0.20 |
| TM-T-067 | Potential command injection via subprocess.run | `packages/darnit/src/darnit/server/tools/git_operations.py:222` | 0.20 |
| TM-T-068 | Potential command injection via subprocess.run | `packages/darnit/src/darnit/server/tools/git_operations.py:277` | 0.20 |
| TM-T-069 | Potential command injection via subprocess.run | `packages/darnit/src/darnit/server/tools/git_operations.py:308` | 0.20 |
| TM-T-070 | Potential command injection via subprocess.run | `packages/darnit/src/darnit/server/tools/git_operations.py:318` | 0.20 |
| TM-T-071 | Potential command injection via subprocess.run | `packages/darnit/src/darnit/server/tools/git_operations.py:393` | 0.20 |
| TM-T-072 | Potential command injection via subprocess.run | `packages/darnit/src/darnit/server/tools/git_operations.py:442` | 0.20 |
| TM-T-073 | Potential command injection via subprocess.run | `packages/darnit/src/darnit/server/tools/git_operations.py:453` | 0.20 |
| TM-T-074 | Potential command injection via subprocess.run | `packages/darnit/src/darnit/server/tools/git_operations.py:464` | 0.20 |
| TM-T-075 | Potential command injection via subprocess.run | `packages/darnit/src/darnit/server/tools/git_operations.py:475` | 0.20 |
| TM-T-076 | Potential command injection via subprocess.run | `packages/darnit/src/darnit/remediation/helpers.py:93` | 0.20 |
| TM-T-077 | Potential command injection via subprocess.run | `packages/darnit-gittuf/src/darnit_gittuf/handlers.py:28` | 0.20 |
| TM-T-078 | Potential command injection via subprocess.run | `packages/darnit-gittuf/src/darnit_gittuf/handlers.py:90` | 0.20 |
| TM-T-079 | Potential command injection via subprocess.run | `packages/darnit-gittuf/src/darnit_gittuf/handlers.py:102` | 0.20 |

### Repudiation

No threats identified in this category.

### Information Disclosure

#### TM-I-001: File open with variable path: filepath

**Risk:** MEDIUM (severity × confidence = 2.00)
**Location:** `docs/examples/python-framework/example_framework/implementation.py:175`
**Source:** `tree_sitter_structural` — query `python.info_disc.open_call`

``open(filepath)`` uses a variable path. If the path originates from user input without validation, this enables path traversal attacks (reading arbitrary files).

```
     165 |         "private_key": r"-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----",
     166 |         "api_token": r"(api[_-]?key|api[_-]?token|access[_-]?token)\s*[=:]\s*['\"][a-zA-Z0-9]{20,}",
     167 |     }
     168 | 
     169 |     code_extensions = ["*.py", "*.js", "*.ts", "*.go", "*.java"]
     170 |     secrets_found = []
     171 | 
     172 |     for ext in code_extensions:
     173 |         for filepath in glob.glob(os.path.join(local_path, "**", ext), recursive=True):
     174 |             try:
>>>  175 |                 with open(filepath, encoding="utf-8", errors="ignore") as f:
     176 |                     content = f.read()
     177 |                 for pattern_name, pattern in secret_patterns.items():
     178 |                     if re.search(pattern, content):
     179 |                         secrets_found.append({
     180 |                             "file": filepath,
     181 |                             "pattern": pattern_name,
     182 |                         })
     183 |             except OSError:
     184 |                 continue
     185 | 
```

#### TM-I-002: File open with variable path: filepath

**Risk:** MEDIUM (severity × confidence = 2.00)
**Location:** `docs/examples/python-framework/example_framework/implementation.py:495`
**Source:** `tree_sitter_structural` — query `python.info_disc.open_call`

``open(filepath)`` uses a variable path. If the path originates from user input without validation, this enables path traversal attacks (reading arbitrary files).

```
     485 | """
     486 | 
     487 |     filepath = os.path.join(local_path, "README.md")
     488 | 
     489 |     if dry_run:
     490 |         return f"Would create: {filepath}"
     491 | 
     492 |     if os.path.exists(filepath):
     493 |         return f"File already exists: {filepath}"
     494 | 
>>>  495 |     with open(filepath, "w") as f:
     496 |         f.write(content)
     497 | 
     498 |     return f"Created: {filepath}"
     499 | 
     500 | 
     501 | def create_changelog(
     502 |     local_path: str,
     503 |     dry_run: bool = True,
     504 | ) -> str:
     505 |     """Create CHANGELOG.md file."""
```

#### TM-I-003: File open with variable path: filepath

**Risk:** MEDIUM (severity × confidence = 2.00)
**Location:** `docs/examples/python-framework/example_framework/implementation.py:540`
**Source:** `tree_sitter_structural` — query `python.info_disc.open_call`

``open(filepath)`` uses a variable path. If the path originates from user input without validation, this enables path traversal attacks (reading arbitrary files).

```
     530 | """
     531 | 
     532 |     filepath = os.path.join(local_path, "CHANGELOG.md")
     533 | 
     534 |     if dry_run:
     535 |         return f"Would create: {filepath}"
     536 | 
     537 |     if os.path.exists(filepath):
     538 |         return f"File already exists: {filepath}"
     539 | 
>>>  540 |     with open(filepath, "w") as f:
     541 |         f.write(content)
     542 | 
     543 |     return f"Created: {filepath}"
     544 | 
     545 | 
     546 | def create_codeowners(
     547 |     local_path: str,
     548 |     owner: str,
     549 |     dry_run: bool = True,
     550 | ) -> str:
```

#### TM-I-004: File open with variable path: filepath

**Risk:** MEDIUM (severity × confidence = 2.00)
**Location:** `docs/examples/python-framework/example_framework/implementation.py:571`
**Source:** `tree_sitter_structural` — query `python.info_disc.open_call`

``open(filepath)`` uses a variable path. If the path originates from user input without validation, this enables path traversal attacks (reading arbitrary files).

```
     561 | """
     562 | 
     563 |     filepath = os.path.join(local_path, "CODEOWNERS")
     564 | 
     565 |     if dry_run:
     566 |         return f"Would create: {filepath}"
     567 | 
     568 |     if os.path.exists(filepath):
     569 |         return f"File already exists: {filepath}"
     570 | 
>>>  571 |     with open(filepath, "w") as f:
     572 |         f.write(content)
     573 | 
     574 |     return f"Created: {filepath}"
     575 | 
     576 | 
     577 | def enable_branch_protection(
     578 |     owner: str,
     579 |     repo: str,
     580 |     branch: str,
     581 |     dry_run: bool = True,
```

#### TM-I-005: File open with variable path: TOML_PATH

**Risk:** MEDIUM (severity × confidence = 2.00)
**Location:** `scripts/validate_sync.py:58`
**Source:** `tree_sitter_structural` — query `python.info_disc.open_call`

``open(TOML_PATH)`` uses a variable path. If the path originates from user input without validation, this enables path traversal attacks (reading arbitrary files).

```
      48 | 
      49 |     Returns:
      50 |         ValidationResult with pass/fail status
      51 |     """
      52 |     try:
      53 |         # Try to load the TOML using the framework's own loader
      54 |         import tomllib
      55 | 
      56 |         from darnit.config.framework_schema import FrameworkConfig
      57 | 
>>>   58 |         with open(TOML_PATH, "rb") as f:
      59 |             toml_data = tomllib.load(f)
      60 | 
      61 |         # Attempt to parse with Pydantic model
      62 |         config = FrameworkConfig(**toml_data)
      63 | 
      64 |         # Basic validation checks
      65 |         errors = []
      66 | 
      67 |         if not config.metadata.name:
      68 |             errors.append("metadata.name is required")
```

#### TM-I-006: File open with variable path: toml_path

**Risk:** MEDIUM (severity × confidence = 2.00)
**Location:** `packages/darnit-baseline/src/darnit_baseline/implementation.py:103`
**Source:** `tree_sitter_structural` — query `python.info_disc.open_call`

``open(toml_path)`` uses a variable path. If the path originates from user input without validation, this enables path traversal attacks (reading arbitrary files).

```
      93 |         (safe, requires_api, handler types).
      94 |         """
      95 |         registry: dict[str, Any] = {}
      96 |         try:
      97 |             import tomllib
      98 | 
      99 |             toml_path = self.get_framework_config_path()
     100 |             if not toml_path or not toml_path.exists():
     101 |                 return registry
     102 | 
>>>  103 |             with open(toml_path, "rb") as f:
     104 |                 data = tomllib.load(f)
     105 | 
     106 |             from darnit.config.framework_schema import FrameworkConfig
     107 | 
     108 |             fw = FrameworkConfig(**data)
     109 |             for cid, control in fw.controls.items():
     110 |                 if control.remediation and control.remediation.handlers:
     111 |                     handler_types = [h.handler for h in control.remediation.handlers]
     112 |                     registry[cid] = {
     113 |                         "description": control.description or cid,
```

#### TM-I-007: File open with variable path: full_path

**Risk:** MEDIUM (severity × confidence = 2.00)
**Location:** `packages/darnit-baseline/src/darnit_baseline/threat_model/remediation.py:296`
**Source:** `tree_sitter_structural` — query `python.info_disc.open_call`

``open(full_path)`` uses a variable path. If the path originates from user input without validation, this enables path traversal attacks (reading arbitrary files).

```
     286 |     if content is None:
     287 |         logger.info(
     288 |             "ts_pipeline did not produce content (%s); falling back to template",
     289 |             ts_output.failure_reason,
     290 |         )
     291 |     else:
     292 |         # Short-circuit: skip legacy _run_dynamic_analysis entirely. The new
     293 |         # generator's output is what users actually see.
     294 |         try:
     295 |             os.makedirs(os.path.dirname(full_path) or ".", exist_ok=True)
>>>  296 |             with open(full_path, "w", encoding="utf-8") as f:
     297 |                 f.write(content)
     298 |         except OSError as e:
     299 |             return HandlerResult(
     300 |                 status=HandlerResultStatus.ERROR,
     301 |                 message=f"Failed to write threat model: {e}",
     302 |                 evidence={
     303 |                     "path": path,
     304 |                     "error": str(e),
     305 |                     **ts_evidence,
     306 |                 },
```

#### TM-I-008: File open with variable path: full_path

**Risk:** MEDIUM (severity × confidence = 2.00)
**Location:** `packages/darnit-baseline/src/darnit_baseline/threat_model/remediation.py:351`
**Source:** `tree_sitter_structural` — query `python.info_disc.open_call`

``open(full_path)`` uses a variable path. If the path originates from user input without validation, this enables path traversal attacks (reading arbitrary files).

```
     341 |             ),
     342 |             evidence={
     343 |                 "path": path,
     344 |                 "error": ts_output.failure_reason or "unknown",
     345 |                 **ts_evidence,
     346 |             },
     347 |         )
     348 | 
     349 |     try:
     350 |         os.makedirs(os.path.dirname(full_path) or ".", exist_ok=True)
>>>  351 |         with open(full_path, "w", encoding="utf-8") as f:
     352 |             f.write(fallback_content)
     353 |     except OSError as write_err:
     354 |         return HandlerResult(
     355 |             status=HandlerResultStatus.ERROR,
     356 |             message=f"Failed to write fallback template: {write_err}",
     357 |             evidence={
     358 |                 "path": path,
     359 |                 "error": str(write_err),
     360 |                 **ts_evidence,
     361 |             },
```

#### TM-I-009: File open with variable path: path

**Risk:** MEDIUM (severity × confidence = 2.00)
**Location:** `packages/darnit-baseline/src/darnit_baseline/threat_model/dependencies.py:192`
**Source:** `tree_sitter_structural` — query `python.info_disc.open_call`

``open(path)`` uses a variable path. If the path originates from user input without validation, this enables path traversal attacks (reading arbitrary files).

```
     182 |     try:
     183 |         content = _read_file(path)
     184 |     except OSError:
     185 |         return
     186 |     for match in re.finditer(r"^\s*(\S+)\s+v", content, re.MULTILINE):
     187 |         module = match.group(1).split("/")[-1]
     188 |         _add_matches(module, declared)
     189 | 
     190 | 
     191 | def _read_file(path: str) -> str:
>>>  192 |     with open(path, errors="ignore") as f:
     193 |         return f.read()
     194 | 
     195 | 
     196 | __all__ = ["parse_dependency_manifests"]
```

#### TM-I-010: File open with variable path: output_path

**Risk:** MEDIUM (severity × confidence = 2.00)
**Location:** `packages/darnit-baseline/src/darnit_baseline/attestation/generator.py:134`
**Source:** `tree_sitter_structural` — query `python.info_disc.open_call`

``open(output_path)`` uses a variable path. If the path originates from user input without validation, this enables path traversal attacks (reading arbitrary files).

```
     124 |     # Determine output file path
     125 |     if not output_path:
     126 |         extension = ".sigstore.json" if sign else ".intoto.json"
     127 |         filename = f"{audit_result.repo}-baseline-attestation{extension}"
     128 |         save_dir = output_dir if output_dir else audit_result.local_path
     129 |         output_path = os.path.join(save_dir, filename)
     130 | 
     131 |     # Save the attestation
     132 |     try:
     133 |         os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
>>>  134 |         with open(output_path, 'w') as f:
     135 |             f.write(output)
     136 |         return f"✅ Attestation saved to: {output_path}\n\n{output}"
     137 |     except OSError as e:
     138 |         return json.dumps({
     139 |             "error": f"Failed to write to {output_path}: {e}",
     140 |             "attestation": json.loads(output)
     141 |         }, indent=2)
     142 | 
     143 | 
     144 | __all__ = [
```

#### TM-I-011: File open with variable path: toml_path

**Risk:** MEDIUM (severity × confidence = 2.00)
**Location:** `packages/darnit-baseline/src/darnit_baseline/remediation/orchestrator.py:132`
**Source:** `tree_sitter_structural` — query `python.info_disc.open_call`

``open(toml_path)`` uses a variable path. If the path originates from user input without validation, this enables path traversal attacks (reading arbitrary files).

```
     122 |         import tomllib
     123 | 
     124 |         # Use the package's get_framework_path() function
     125 |         from darnit_baseline import get_framework_path
     126 |         toml_path = get_framework_path()
     127 | 
     128 |         if not toml_path.exists():
     129 |             logger.debug(f"Framework TOML not found at {toml_path}")
     130 |             return None
     131 | 
>>>  132 |         with open(toml_path, "rb") as f:
     133 |             data = tomllib.load(f)
     134 | 
     135 |         _cached_framework = FrameworkConfig(**data)
     136 |         logger.debug(f"Loaded framework config from {toml_path}")
     137 |         return _cached_framework
     138 | 
     139 |     except OSError as e:
     140 |         logger.debug(f"Failed to load framework TOML: {e}")
     141 |         return None
     142 |     except (ValueError, TypeError, KeyError) as e:
```

#### TM-I-012: File open with variable path: project_yaml

**Risk:** MEDIUM (severity × confidence = 2.00)
**Location:** `packages/darnit-baseline/src/darnit_baseline/remediation/orchestrator.py:510`
**Source:** `tree_sitter_structural` — query `python.info_disc.open_call`

``open(project_yaml)`` uses a variable path. If the path originates from user input without validation, this enables path traversal attacks (reading arbitrary files).

```
     500 |             scan_values = flatten_scan_context(scan_ctx)
     501 |         except Exception:
     502 |             pass  # Repo scanning is best-effort
     503 | 
     504 |         # Load .project/project.yaml for ${project.*} substitution
     505 |         project_values: dict[str, Any] = {}
     506 |         try:
     507 |             import yaml
     508 |             project_yaml = os.path.join(local_path, ".project", "project.yaml")
     509 |             if os.path.isfile(project_yaml):
>>>  510 |                 with open(project_yaml, encoding="utf-8") as f:
     511 |                     raw = yaml.safe_load(f) or {}
     512 |                 # Flatten nested keys: {security: {contact: "x"}} -> {"security.contact": "x"}
     513 |                 def _flatten(d: dict, prefix: str = "") -> dict[str, str]:
     514 |                     out: dict[str, str] = {}
     515 |                     for k, v in d.items():
     516 |                         key = f"{prefix}{k}" if not prefix else f"{prefix}.{k}"
     517 |                         if isinstance(v, dict):
     518 |                             out.update(_flatten(v, key))
     519 |                         elif v is not None:
     520 |                             out[key] = str(v) if not isinstance(v, list) else " ".join(str(i) for i in v)
```

#### TM-I-013: File open with variable path: self.project_yaml

**Risk:** MEDIUM (severity × confidence = 2.00)
**Location:** `packages/darnit/src/darnit/context/dot_project.py:348`
**Source:** `tree_sitter_structural` — query `python.info_disc.open_call`

``open(self.project_yaml)`` uses a variable path. If the path originates from user input without validation, this enables path traversal attacks (reading arbitrary files).

```
     338 |             logger.debug("No .project/project.yaml found at %s", self.repo_path)
     339 |             return ProjectConfig()
     340 | 
     341 |         try:
     342 |             # Use ruamel.yaml for round-trip preservation
     343 |             from ruamel.yaml import YAML
     344 | 
     345 |             yaml = YAML()
     346 |             yaml.preserve_quotes = True
     347 | 
>>>  348 |             with open(self.project_yaml) as f:
     349 |                 data = yaml.load(f)
     350 | 
     351 |             if data is None:
     352 |                 data = {}
     353 | 
     354 |             config = self._parse_config(data)
     355 |             config._source_path = self.project_yaml
     356 | 
     357 |             # Also check for maintainers.yaml
     358 |             if self.maintainers_yaml.exists():
```

#### TM-I-014: File open with variable path: self.maintainers_yaml

**Risk:** MEDIUM (severity × confidence = 2.00)
**Location:** `packages/darnit/src/darnit/context/dot_project.py:389`
**Source:** `tree_sitter_structural` — query `python.info_disc.open_call`

``open(self.maintainers_yaml)`` uses a variable path. If the path originates from user input without validation, this enables path traversal attacks (reading arbitrary files).

```
     379 |         """Read maintainers from maintainers.yaml into config.
     380 | 
     381 |         Populates both the flat maintainers list (handles) and structured
     382 |         fields (maintainer_entries, maintainer_teams, maintainer_org,
     383 |         maintainer_project_id) when available.
     384 |         """
     385 |         try:
     386 |             from ruamel.yaml import YAML
     387 | 
     388 |             yaml = YAML()
>>>  389 |             with open(self.maintainers_yaml) as f:
     390 |                 data = yaml.load(f)
     391 | 
     392 |             if data is None:
     393 |                 return
     394 | 
     395 |             # Format 1: Plain list of strings or dicts
     396 |             if isinstance(data, list):
     397 |                 handles, entries = self._extract_maintainer_entries(data)
     398 |                 if handles:
     399 |                     config.maintainers = handles
```

#### TM-I-015: File open with variable path: self.project_yaml

**Risk:** MEDIUM (severity × confidence = 2.00)
**Location:** `packages/darnit/src/darnit/context/dot_project.py:849`
**Source:** `tree_sitter_structural` — query `python.info_disc.open_call`

``open(self.project_yaml)`` uses a variable path. If the path originates from user input without validation, this enables path traversal attacks (reading arbitrary files).

```
     839 |             writer.update({"security": {"policy": {"path": "SECURITY.md"}}})
     840 |         """
     841 |         from ruamel.yaml import YAML
     842 | 
     843 |         yaml = YAML()
     844 |         yaml.preserve_quotes = True
     845 |         yaml.indent(mapping=2, sequence=4, offset=2)
     846 | 
     847 |         # Read existing content or create new
     848 |         if self.project_yaml.exists():
>>>  849 |             with open(self.project_yaml) as f:
     850 |                 data = yaml.load(f)
     851 |             if data is None:
     852 |                 data = {}
     853 |         else:
     854 |             # Create directory and new file
     855 |             self.project_dir.mkdir(parents=True, exist_ok=True)
     856 |             data = {"schema_version": DOT_PROJECT_SPEC_VERSION}
     857 | 
     858 |         # Apply updates recursively
     859 |         self._deep_update(data, updates)
```

#### TM-I-016: File open with variable path: self.project_yaml

**Risk:** MEDIUM (severity × confidence = 2.00)
**Location:** `packages/darnit/src/darnit/context/dot_project.py:862`
**Source:** `tree_sitter_structural` — query `python.info_disc.open_call`

``open(self.project_yaml)`` uses a variable path. If the path originates from user input without validation, this enables path traversal attacks (reading arbitrary files).

```
     852 |                 data = {}
     853 |         else:
     854 |             # Create directory and new file
     855 |             self.project_dir.mkdir(parents=True, exist_ok=True)
     856 |             data = {"schema_version": DOT_PROJECT_SPEC_VERSION}
     857 | 
     858 |         # Apply updates recursively
     859 |         self._deep_update(data, updates)
     860 | 
     861 |         # Write back
>>>  862 |         with open(self.project_yaml, "w") as f:
     863 |             yaml.dump(data, f)
     864 | 
     865 |         logger.info("Updated .project/project.yaml")
     866 | 
     867 |     def _deep_update(self, target: dict, updates: dict) -> None:
     868 |         """Recursively update nested dictionaries."""
     869 |         for key, value in updates.items():
     870 |             if isinstance(value, dict) and isinstance(target.get(key), dict):
     871 |                 self._deep_update(target[key], value)
     872 |             else:
```

#### TM-I-017: File open with variable path: cache_path

**Risk:** MEDIUM (severity × confidence = 2.00)
**Location:** `packages/darnit/src/darnit/core/verification.py:221`
**Source:** `tree_sitter_structural` — query `python.info_disc.open_call`

``open(cache_path)`` uses a variable path. If the path originates from user input without validation, this enables path traversal attacks (reading arbitrary files).

```
     211 | 
     212 |         Returns:
     213 |             Cached VerificationResult or None if not cached/expired
     214 |         """
     215 |         cache_path = self._cache_path(package_name, version)
     216 | 
     217 |         if not cache_path.exists():
     218 |             return None
     219 | 
     220 |         try:
>>>  221 |             with open(cache_path) as f:
     222 |                 data = json.load(f)
     223 | 
     224 |             # Check expiration
     225 |             cached_time = data.get("cached_at", 0)
     226 |             if time.time() - cached_time > self.ttl:
     227 |                 logger.debug(f"Cache expired for {package_name}:{version}")
     228 |                 return None
     229 | 
     230 |             # Reconstruct AttestationInfo if present
     231 |             attestation = None
```

#### TM-I-018: File open with variable path: cache_path

**Risk:** MEDIUM (severity × confidence = 2.00)
**Location:** `packages/darnit/src/darnit/core/verification.py:296`
**Source:** `tree_sitter_structural` — query `python.info_disc.open_call`

``open(cache_path)`` uses a variable path. If the path originates from user input without validation, this enables path traversal attacks (reading arbitrary files).

```
     286 |                 "publisher_repo": result.publisher_repo,
     287 |                 "trusted": result.trusted,
     288 |                 "attestation": attestation_data,
     289 |                 "error": result.error,
     290 |                 "warning": result.warning,
     291 |                 "cached_at": time.time(),
     292 |                 "package": package_name,
     293 |                 "version": version,
     294 |             }
     295 | 
>>>  296 |             with open(cache_path, "w") as f:
     297 |                 json.dump(data, f)
     298 | 
     299 |             logger.debug(f"Cached verification result for {package_name}:{version}")
     300 |         except OSError as e:
     301 |             logger.warning(f"Could not cache verification result: {e}")
     302 | 
     303 | 
     304 | class PluginVerifier:
     305 |     """Sigstore-based plugin verifier.
     306 | 
```

#### TM-I-019: File open with variable path: filepath

**Risk:** MEDIUM (severity × confidence = 2.00)
**Location:** `packages/darnit/src/darnit/core/utils.py:337`
**Source:** `tree_sitter_structural` — query `python.info_disc.open_call`

``open(filepath)`` uses a variable path. If the path originates from user input without validation, this enables path traversal attacks (reading arbitrary files).

```
     327 |         if matches:
     328 |             return True
     329 |     return False
     330 | 
     331 | 
     332 | def file_contains(local_path: str, filename_patterns: list[str], content_pattern: str) -> bool:
     333 |     """Check if any matching file contains the content pattern."""
     334 |     for pattern in filename_patterns:
     335 |         for filepath in glob_module.glob(os.path.join(local_path, pattern), recursive=True):
     336 |             try:
>>>  337 |                 with open(filepath, encoding='utf-8', errors='ignore') as f:
     338 |                     if re.search(content_pattern, f.read(), re.IGNORECASE):
     339 |                         return True
     340 |             except OSError as e:
     341 |                 logger.debug(f"Could not read {filepath}: {type(e).__name__}")
     342 |                 continue
     343 |     return False
     344 | 
     345 | 
     346 | def read_file(local_path: str, filename: str) -> str | None:
     347 |     """Read a file's contents, returning None if not found."""
```

#### TM-I-020: File open with variable path: filepath

**Risk:** MEDIUM (severity × confidence = 2.00)
**Location:** `packages/darnit/src/darnit/core/utils.py:351`
**Source:** `tree_sitter_structural` — query `python.info_disc.open_call`

``open(filepath)`` uses a variable path. If the path originates from user input without validation, this enables path traversal attacks (reading arbitrary files).

```
     341 |                 logger.debug(f"Could not read {filepath}: {type(e).__name__}")
     342 |                 continue
     343 |     return False
     344 | 
     345 | 
     346 | def read_file(local_path: str, filename: str) -> str | None:
     347 |     """Read a file's contents, returning None if not found."""
     348 |     filepath = os.path.join(local_path, filename)
     349 |     if os.path.exists(filepath):
     350 |         try:
>>>  351 |             with open(filepath, encoding='utf-8', errors='ignore') as f:
     352 |                 return f.read()
     353 |         except OSError as e:
     354 |             logger.debug(f"Could not read {filepath}: {type(e).__name__}")
     355 |             return None
     356 |     return None
     357 | 
     358 | 
     359 | def make_result(control_id: str, status: str, details: str, level: int = 1) -> dict[str, Any]:
     360 |     """Create a standardized result dictionary."""
     361 |     return {"id": control_id, "status": status, "details": details, "level": level}
```

#### TM-I-021: File open with variable path: cache_path

**Risk:** MEDIUM (severity × confidence = 2.00)
**Location:** `packages/darnit/src/darnit/core/audit_cache.py:170`
**Source:** `tree_sitter_structural` — query `python.info_disc.open_call`

``open(cache_path)`` uses a variable path. If the path originates from user input without validation, this enables path traversal attacks (reading arbitrary files).

```
     160 |     callers should fall back to running a fresh audit.
     161 |     """
     162 |     cache_path = _get_cache_dir(local_path) / CACHE_FILENAME
     163 | 
     164 |     if not cache_path.is_file():
     165 |         logger.debug("No audit cache file at %s", cache_path)
     166 |         return None
     167 | 
     168 |     # Parse JSON
     169 |     try:
>>>  170 |         with open(cache_path) as f:
     171 |             data = json.load(f)
     172 |     except (json.JSONDecodeError, OSError) as exc:
     173 |         logger.debug("Corrupt or unreadable audit cache: %s", exc)
     174 |         return None
     175 | 
     176 |     if not isinstance(data, dict):
     177 |         logger.debug("Audit cache is not a JSON object")
     178 |         return None
     179 | 
     180 |     # Version check
```

#### TM-I-022: File open with variable path: full_path

**Risk:** MEDIUM (severity × confidence = 2.00)
**Location:** `packages/darnit/src/darnit/config/discovery.py:82`
**Source:** `tree_sitter_structural` — query `python.info_disc.open_call`

``open(full_path)`` uses a variable path. If the path originates from user input without validation, this enables path traversal attacks (reading arbitrary files).

```
      72 |         for f in os.listdir(github_workflows):
      73 |             if f.endswith(('.yml', '.yaml')):
      74 |                 workflows.append(f".github/workflows/{f}")
      75 | 
      76 |         config.workflows = workflows
      77 | 
      78 |         # Detect specific workflow capabilities
      79 |         for workflow_path in workflows:
      80 |             full_path = os.path.join(local_path, workflow_path)
      81 |             try:
>>>   82 |                 with open(full_path, encoding='utf-8') as f:
      83 |                     content = f.read()
      84 | 
      85 |                 # Detect testing
      86 |                 if re.search(r'(npm test|pytest|cargo test|go test|jest|mocha)', content, re.IGNORECASE):
      87 |                     if workflow_path not in config.testing:
      88 |                         config.testing.append(workflow_path)
      89 | 
      90 |                 # Detect code quality
      91 |                 if re.search(r'(eslint|flake8|pylint|rubocop|clippy|golangci)', content, re.IGNORECASE):
      92 |                     if workflow_path not in config.code_quality:
```

#### TM-I-023: File open with variable path: pkg_path

**Risk:** MEDIUM (severity × confidence = 2.00)
**Location:** `packages/darnit/src/darnit/config/discovery.py:144`
**Source:** `tree_sitter_structural` — query `python.info_disc.open_call`

``open(pkg_path)`` uses a variable path. If the path originates from user input without validation, this enables path traversal attacks (reading arbitrary files).

```
     134 |     Args:
     135 |         local_path: Path to the repository
     136 | 
     137 |     Returns:
     138 |         Discovered project name or None
     139 |     """
     140 |     # Try package.json
     141 |     try:
     142 |         pkg_path = os.path.join(local_path, "package.json")
     143 |         if os.path.exists(pkg_path):
>>>  144 |             with open(pkg_path) as f:
     145 |                 data = json.load(f)
     146 |                 if "name" in data:
     147 |                     return data["name"]
     148 |     except (OSError, json.JSONDecodeError):
     149 |         pass
     150 | 
     151 |     # Try pyproject.toml
     152 |     try:
     153 |         import tomllib
     154 |         pyproj_path = os.path.join(local_path, "pyproject.toml")
```

#### TM-I-024: File open with variable path: pyproj_path

**Risk:** MEDIUM (severity × confidence = 2.00)
**Location:** `packages/darnit/src/darnit/config/discovery.py:156`
**Source:** `tree_sitter_structural` — query `python.info_disc.open_call`

``open(pyproj_path)`` uses a variable path. If the path originates from user input without validation, this enables path traversal attacks (reading arbitrary files).

```
     146 |                 if "name" in data:
     147 |                     return data["name"]
     148 |     except (OSError, json.JSONDecodeError):
     149 |         pass
     150 | 
     151 |     # Try pyproject.toml
     152 |     try:
     153 |         import tomllib
     154 |         pyproj_path = os.path.join(local_path, "pyproject.toml")
     155 |         if os.path.exists(pyproj_path):
>>>  156 |             with open(pyproj_path, 'rb') as f:
     157 |                 data = tomllib.load(f)
     158 |                 if "project" in data and "name" in data["project"]:
     159 |                     return data["project"]["name"]
     160 |     except (OSError, ImportError):
     161 |         pass
     162 | 
     163 |     # Try Cargo.toml
     164 |     try:
     165 |         import tomllib
     166 |         cargo_path = os.path.join(local_path, "Cargo.toml")
```

#### TM-I-025: File open with variable path: cargo_path

**Risk:** MEDIUM (severity × confidence = 2.00)
**Location:** `packages/darnit/src/darnit/config/discovery.py:168`
**Source:** `tree_sitter_structural` — query `python.info_disc.open_call`

``open(cargo_path)`` uses a variable path. If the path originates from user input without validation, this enables path traversal attacks (reading arbitrary files).

```
     158 |                 if "project" in data and "name" in data["project"]:
     159 |                     return data["project"]["name"]
     160 |     except (OSError, ImportError):
     161 |         pass
     162 | 
     163 |     # Try Cargo.toml
     164 |     try:
     165 |         import tomllib
     166 |         cargo_path = os.path.join(local_path, "Cargo.toml")
     167 |         if os.path.exists(cargo_path):
>>>  168 |             with open(cargo_path, 'rb') as f:
     169 |                 data = tomllib.load(f)
     170 |                 if "package" in data and "name" in data["package"]:
     171 |                     return data["package"]["name"]
     172 |     except (OSError, ImportError):
     173 |         pass
     174 | 
     175 |     # Try go.mod
     176 |     try:
     177 |         go_mod_path = os.path.join(local_path, "go.mod")
     178 |         if os.path.exists(go_mod_path):
```

#### TM-I-026: File open with variable path: go_mod_path

**Risk:** MEDIUM (severity × confidence = 2.00)
**Location:** `packages/darnit/src/darnit/config/discovery.py:179`
**Source:** `tree_sitter_structural` — query `python.info_disc.open_call`

``open(go_mod_path)`` uses a variable path. If the path originates from user input without validation, this enables path traversal attacks (reading arbitrary files).

```
     169 |                 data = tomllib.load(f)
     170 |                 if "package" in data and "name" in data["package"]:
     171 |                     return data["package"]["name"]
     172 |     except (OSError, ImportError):
     173 |         pass
     174 | 
     175 |     # Try go.mod
     176 |     try:
     177 |         go_mod_path = os.path.join(local_path, "go.mod")
     178 |         if os.path.exists(go_mod_path):
>>>  179 |             with open(go_mod_path) as f:
     180 |                 first_line = f.readline().strip()
     181 |                 if first_line.startswith("module "):
     182 |                     module_path = first_line[7:].strip()
     183 |                     # Return last part of module path
     184 |                     return module_path.split("/")[-1]
     185 |     except OSError:
     186 |         pass
     187 | 
     188 |     # Fall back to directory name
     189 |     return os.path.basename(os.path.abspath(local_path))
```

#### TM-I-027: File open with variable path: path

**Risk:** MEDIUM (severity × confidence = 2.00)
**Location:** `packages/darnit/src/darnit/config/loader.py:137`
**Source:** `tree_sitter_structural` — query `python.info_disc.open_call`

``open(path)`` uses a variable path. If the path originates from user input without validation, this enables path traversal attacks (reading arbitrary files).

```
     127 | CleanDumper.add_representer(str, _str_representer)
     128 | 
     129 | 
     130 | # =============================================================================
     131 | # Loading Functions
     132 | # =============================================================================
     133 | 
     134 | def _load_yaml_file(path: str) -> dict[str, Any] | None:
     135 |     """Load a YAML file and return its contents."""
     136 |     try:
>>>  137 |         with open(path, encoding='utf-8') as f:
     138 |             data = yaml.safe_load(f)
     139 |         return data if data else None
     140 |     except (yaml.YAMLError, OSError) as e:
     141 |         logger.debug(f"Failed to load {path}: {e}")
     142 |         return None
     143 | 
     144 | 
     145 | def load_project_config(local_path: str) -> ProjectConfig | None:
     146 |     """Load project configuration from .project/ directory.
     147 | 
```

#### TM-I-028: File open with variable path: path

**Risk:** MEDIUM (severity × confidence = 2.00)
**Location:** `packages/darnit/src/darnit/config/loader.py:234`
**Source:** `tree_sitter_structural` — query `python.info_disc.open_call`

``open(path)`` uses a variable path. If the path originates from user input without validation, this enables path traversal attacks (reading arbitrary files).

```
     224 |                 # Unknown field -> default extension file
     225 |                 if default_ext.filename not in extension_files:
     226 |                     extension_files[default_ext.filename] = {}
     227 |                 extension_files[default_ext.filename][key] = value
     228 | 
     229 |     return project_data, extension_files
     230 | 
     231 | 
     232 | def _write_yaml_file(path: str, data: dict[str, Any], header_lines: list[str]) -> None:
     233 |     """Write data to a YAML file with header comments."""
>>>  234 |     with open(path, 'w', encoding='utf-8') as f:
     235 |         for line in header_lines:
     236 |             f.write(f"# {line}\n")
     237 |         f.write("\n")
     238 | 
     239 |         yaml.dump(
     240 |             data,
     241 |             f,
     242 |             Dumper=CleanDumper,
     243 |             default_flow_style=False,
     244 |             sort_keys=False,
```

#### TM-I-029: File open with variable path: path

**Risk:** MEDIUM (severity × confidence = 2.00)
**Location:** `packages/darnit/src/darnit/config/merger.py:425`
**Source:** `tree_sitter_structural` — query `python.info_disc.open_call`

``open(path)`` uses a variable path. If the path originates from user input without validation, this enables path traversal attacks (reading arbitrary files).

```
     415 |     Returns:
     416 |         Parsed FrameworkConfig
     417 | 
     418 |     Raises:
     419 |         FileNotFoundError: If file doesn't exist
     420 |         ValueError: If file is invalid
     421 |     """
     422 |     if not path.exists():
     423 |         raise FileNotFoundError(f"Framework config not found: {path}")
     424 | 
>>>  425 |     with open(path, "rb") as f:
     426 |         data = tomllib.load(f)
     427 | 
     428 |     return FrameworkConfig(**data)
     429 | 
     430 | 
     431 | def load_user_config(repo_path: Path) -> UserConfig | None:
     432 |     """Load user configuration from repository.
     433 | 
     434 |     Searches for .baseline.toml in the repository root.
     435 | 
```

#### TM-I-030: File open with variable path: config_path

**Risk:** MEDIUM (severity × confidence = 2.00)
**Location:** `packages/darnit/src/darnit/config/merger.py:447`
**Source:** `tree_sitter_structural` — query `python.info_disc.open_call`

``open(config_path)`` uses a variable path. If the path originates from user input without validation, this enables path traversal attacks (reading arbitrary files).

```
     437 |         repo_path: Path to repository
     438 | 
     439 |     Returns:
     440 |         Parsed UserConfig or None if not found
     441 |     """
     442 |     config_path = Path(repo_path) / ".baseline.toml"
     443 | 
     444 |     if not config_path.exists():
     445 |         return None
     446 | 
>>>  447 |     with open(config_path, "rb") as f:
     448 |         data = tomllib.load(f)
     449 | 
     450 |     return UserConfig(**data)
     451 | 
     452 | 
     453 | def load_effective_config(
     454 |     framework_path: Path,
     455 |     repo_path: Path | None = None,
     456 | ) -> EffectiveConfig:
     457 |     """Load and merge framework and user configurations.
```

#### TM-I-031: File open with variable path: config_path

**Risk:** MEDIUM (severity × confidence = 2.00)
**Location:** `packages/darnit/src/darnit/server/factory.py:122`
**Source:** `tree_sitter_structural` — query `python.info_disc.open_call`

``open(config_path)`` uses a variable path. If the path originates from user input without validation, this enables path traversal attacks (reading arbitrary files).

```
     112 |     try:
     113 |         import tomllib
     114 |     except ImportError:
     115 |         import tomli as tomllib  # type: ignore[import-not-found]
     116 | 
     117 |     config_path = Path(config_path)
     118 |     if not config_path.exists():
     119 |         raise FileNotFoundError(f"Config file not found: {config_path}")
     120 | 
     121 |     # Load TOML config
>>>  122 |     with open(config_path, "rb") as f:
     123 |         config = tomllib.load(f)
     124 | 
     125 |     # Extract server name
     126 |     mcp_config = config.get("mcp", {})
     127 |     server_name = mcp_config.get("name", "darnit")
     128 | 
     129 |     # Register handlers from implementation before loading tools
     130 |     # This enables short name resolution for handler references
     131 |     _register_implementation_handlers(config)
     132 | 
```

#### TM-I-032: File open with variable path: os.path.join(repo_path, "package.json")

**Risk:** MEDIUM (severity × confidence = 2.00)
**Location:** `packages/darnit/src/darnit/server/tools/test_repository.py:58`
**Source:** `tree_sitter_structural` — query `python.info_disc.open_call`

``open(os.path.join(repo_path, "package.json"))`` uses a variable path. If the path originates from user input without validation, this enables path traversal attacks (reading arbitrary files).

```
      48 |   "version": "0.0.1",
      49 |   "main": "src/index.js",
      50 |   "scripts": {
      51 |     "start": "node src/index.js"
      52 |   },
      53 |   "dependencies": {
      54 |     "chalk": "^4.1.2"
      55 |   }
      56 | }
      57 | """
>>>   58 |     with open(os.path.join(repo_path, "package.json"), "w") as f:
      59 |         f.write(package_json)
      60 | 
      61 |     # Create src/index.js
      62 |     index_js = """const chalk = require('chalk');
      63 | 
      64 | console.log(chalk.green('Hello from baseline-test!'));
      65 | console.log(chalk.yellow('This repo intentionally has no security controls.'));
      66 | console.log('');
      67 | console.log('Run an OpenSSF Baseline audit to see what is missing:');
      68 | console.log(chalk.cyan('  audit_openssf_baseline(local_path=".")'));
```

#### TM-I-033: File open with variable path: os.path.join(repo_path, "src", "index.js")

**Risk:** MEDIUM (severity × confidence = 2.00)
**Location:** `packages/darnit/src/darnit/server/tools/test_repository.py:70`
**Source:** `tree_sitter_structural` — query `python.info_disc.open_call`

``open(os.path.join(repo_path, "src", "index.js"))`` uses a variable path. If the path originates from user input without validation, this enables path traversal attacks (reading arbitrary files).

```
      60 | 
      61 |     # Create src/index.js
      62 |     index_js = """const chalk = require('chalk');
      63 | 
      64 | console.log(chalk.green('Hello from baseline-test!'));
      65 | console.log(chalk.yellow('This repo intentionally has no security controls.'));
      66 | console.log('');
      67 | console.log('Run an OpenSSF Baseline audit to see what is missing:');
      68 | console.log(chalk.cyan('  audit_openssf_baseline(local_path=".")'));
      69 | """
>>>   70 |     with open(os.path.join(repo_path, "src", "index.js"), "w") as f:
      71 |         f.write(index_js)
      72 | 
      73 |     # Create minimal .gitignore (intentionally missing security exclusions)
      74 |     gitignore = """# Intentionally minimal .gitignore for testing
      75 | # This is MISSING important security exclusions!
      76 | node_modules/
      77 | """
      78 |     with open(os.path.join(repo_path, ".gitignore"), "w") as f:
      79 |         f.write(gitignore)
      80 | 
```

#### TM-I-034: File open with variable path: os.path.join(repo_path, ".gitignore")

**Risk:** MEDIUM (severity × confidence = 2.00)
**Location:** `packages/darnit/src/darnit/server/tools/test_repository.py:78`
**Source:** `tree_sitter_structural` — query `python.info_disc.open_call`

``open(os.path.join(repo_path, ".gitignore"))`` uses a variable path. If the path originates from user input without validation, this enables path traversal attacks (reading arbitrary files).

```
      68 | console.log(chalk.cyan('  audit_openssf_baseline(local_path=".")'));
      69 | """
      70 |     with open(os.path.join(repo_path, "src", "index.js"), "w") as f:
      71 |         f.write(index_js)
      72 | 
      73 |     # Create minimal .gitignore (intentionally missing security exclusions)
      74 |     gitignore = """# Intentionally minimal .gitignore for testing
      75 | # This is MISSING important security exclusions!
      76 | node_modules/
      77 | """
>>>   78 |     with open(os.path.join(repo_path, ".gitignore"), "w") as f:
      79 |         f.write(gitignore)
      80 | 
      81 |     # Initialize git
      82 |     try:
      83 |         subprocess.run(
      84 |             ["git", "init"],
      85 |             cwd=repo_path,
      86 |             capture_output=True,
      87 |             check=True
      88 |         )
```

#### TM-I-035: File open with variable path: fpath

**Risk:** MEDIUM (severity × confidence = 2.00)
**Location:** `packages/darnit/src/darnit/sieve/builtin_handlers.py:395`
**Source:** `tree_sitter_structural` — query `python.info_disc.open_call`

``open(fpath)`` uses a variable path. If the path originates from user input without validation, this enables path traversal attacks (reading arbitrary files).

```
     385 |     patterns: dict[str, str],
     386 |     min_matches: int,
     387 |     pass_if_any: bool,
     388 | ) -> HandlerResult:
     389 |     """Match patterns across files and return a result."""
     390 |     all_results: list[dict[str, Any]] = []
     391 |     any_match = False
     392 | 
     393 |     for fpath in file_paths:
     394 |         try:
>>>  395 |             with open(fpath, encoding="utf-8", errors="ignore") as f:
     396 |                 content = f.read()
     397 |         except OSError:
     398 |             continue
     399 | 
     400 |         for pname, pregex in patterns.items():
     401 |             matches = re.findall(pregex, content, re.MULTILINE | re.IGNORECASE)
     402 |             match_count = len(matches)
     403 |             matched = match_count >= min_matches
     404 | 
     405 |             all_results.append({
```

#### TM-I-036: File open with variable path: full

**Risk:** MEDIUM (severity × confidence = 2.00)
**Location:** `packages/darnit/src/darnit/sieve/builtin_handlers.py:486`
**Source:** `tree_sitter_structural` — query `python.info_disc.open_call`

``open(full)`` uses a variable path. If the path originates from user input without validation, this enables path traversal attacks (reading arbitrary files).

```
     476 |     files_to_include = config.get("files_to_include", [])
     477 |     file_contents: dict[str, str] = {}
     478 |     for f in files_to_include[:5]:
     479 |         resolved = f
     480 |         if f == "$FOUND_FILE":
     481 |             resolved = context.gathered_evidence.get("found_file", "")
     482 |         if not resolved:
     483 |             continue
     484 |         full = os.path.join(context.local_path, resolved) if not os.path.isabs(resolved) else resolved
     485 |         try:
>>>  486 |             with open(full, encoding="utf-8", errors="ignore") as fh:
     487 |                 rel = os.path.relpath(full, context.local_path)
     488 |                 file_contents[rel] = fh.read()[:10000]
     489 |         except OSError:
     490 |             pass
     491 | 
     492 |     return HandlerResult(
     493 |         status=HandlerResultStatus.INCONCLUSIVE,
     494 |         message="LLM consultation requested",
     495 |         details={
     496 |             "consultation_request": {
```

#### TM-I-037: File open with variable path: full_path

**Risk:** MEDIUM (severity × confidence = 2.00)
**Location:** `packages/darnit/src/darnit/sieve/builtin_handlers.py:565`
**Source:** `tree_sitter_structural` — query `python.info_disc.open_call`

``open(full_path)`` uses a variable path. If the path originates from user input without validation, this enables path traversal attacks (reading arbitrary files).

```
     555 |     if not content:
     556 |         # Template resolution would happen at a higher level
     557 |         return HandlerResult(
     558 |             status=HandlerResultStatus.ERROR,
     559 |             message=f"No content or template for file creation: {path}",
     560 |             evidence={"path": path},
     561 |         )
     562 | 
     563 |     try:
     564 |         os.makedirs(os.path.dirname(full_path), exist_ok=True)
>>>  565 |         with open(full_path, "w", encoding="utf-8") as f:
     566 |             f.write(content)
     567 |     except OSError as e:
     568 |         return HandlerResult(
     569 |             status=HandlerResultStatus.ERROR,
     570 |             message=f"Failed to create file: {e}",
     571 |             evidence={"path": path, "error": str(e)},
     572 |         )
     573 | 
     574 |     return HandlerResult(
     575 |         status=HandlerResultStatus.PASS,
```

#### TM-I-038: File open with variable path: filepath

**Risk:** MEDIUM (severity × confidence = 2.00)
**Location:** `packages/darnit/src/darnit/sieve/builtin_handlers.py:677`
**Source:** `tree_sitter_structural` — query `python.info_disc.open_call`

``open(filepath)`` uses a variable path. If the path originates from user input without validation, this enables path traversal attacks (reading arbitrary files).

```
     667 |             message=f"No files matched pattern: {files_pattern}",
     668 |             evidence={"pattern": files_pattern},
     669 |         )
     670 | 
     671 |     import re
     672 | 
     673 |     modified = []
     674 |     skipped = []
     675 |     for filepath in matched_files:
     676 |         try:
>>>  677 |             with open(filepath, encoding="utf-8") as f:
     678 |                 content = f.read()
     679 |         except OSError:
     680 |             continue
     681 | 
     682 |         # Skip if key already exists at the top level (not indented)
     683 |         if re.search(rf"^{re.escape(key)}\s*:", content, re.MULTILINE):
     684 |             skipped.append(os.path.relpath(filepath, context.local_path))
     685 |             continue
     686 | 
     687 |         # Find insertion point: after the insert_after key's block
```

#### TM-I-039: File open with variable path: filepath

**Risk:** MEDIUM (severity × confidence = 2.00)
**Location:** `packages/darnit/src/darnit/sieve/builtin_handlers.py:711`
**Source:** `tree_sitter_structural` — query `python.info_disc.open_call`

``open(filepath)`` uses a variable path. If the path originates from user input without validation, this enables path traversal attacks (reading arbitrary files).

```
     701 |                     insert_idx = i + 1
     702 |                     break
     703 |         else:
     704 |             if in_target_block:
     705 |                 insert_idx = len(lines)
     706 | 
     707 |         injection = f"\n{key}: {value}\n"
     708 |         lines.insert(insert_idx, injection.rstrip())
     709 | 
     710 |         try:
>>>  711 |             with open(filepath, "w", encoding="utf-8") as f:
     712 |                 f.write("\n".join(lines))
     713 |             modified.append(os.path.relpath(filepath, context.local_path))
     714 |         except OSError:
     715 |             continue
     716 | 
     717 |     if not modified:
     718 |         return HandlerResult(
     719 |             status=HandlerResultStatus.PASS,
     720 |             message=f"All {len(skipped)} file(s) already have '{key}:'",
     721 |             evidence={"skipped": skipped},
```

#### TM-I-040: File open with variable path: filepath

**Risk:** MEDIUM (severity × confidence = 2.00)
**Location:** `packages/darnit/src/darnit/remediation/github.py:53`
**Source:** `tree_sitter_structural` — query `python.info_disc.open_call`

``open(filepath)`` uses a variable path. If the path originates from user input without validation, this enables path traversal attacks (reading arbitrary files).

```
      43 |     except OSError as e:
      44 |         logger.debug(f"Cannot read workflow directory: {e}")
      45 |         return checks
      46 | 
      47 |     for filename in filenames:
      48 |         if not filename.endswith(('.yml', '.yaml')):
      49 |             continue
      50 | 
      51 |         filepath = os.path.join(workflow_dir, filename)
      52 |         try:
>>>   53 |             with open(filepath, encoding='utf-8') as f:
      54 |                 content = f.read()
      55 | 
      56 |             workflow = yaml.safe_load(content)
      57 |             if workflow and isinstance(workflow, dict):
      58 |                 workflow_name = workflow.get('name', filename.replace('.yml', '').replace('.yaml', ''))
      59 |                 jobs = workflow.get('jobs', {})
      60 | 
      61 |                 for job_id, job_config in jobs.items():
      62 |                     if isinstance(job_config, dict):
      63 |                         job_name = job_config.get('name', job_id)
```

#### TM-I-041: File open with variable path: path

**Risk:** MEDIUM (severity × confidence = 2.00)
**Location:** `packages/darnit/src/darnit/remediation/helpers.py:53`
**Source:** `tree_sitter_structural` — query `python.info_disc.open_call`

``open(path)`` uses a variable path. If the path originates from user input without validation, this enables path traversal attacks (reading arbitrary files).

```
      43 |     """Safely write content to a file.
      44 | 
      45 |     Args:
      46 |         path: File path to write
      47 |         content: Content to write
      48 | 
      49 |     Returns:
      50 |         Tuple of (success: bool, message: str)
      51 |     """
      52 |     try:
>>>   53 |         with open(path, 'w') as f:
      54 |             f.write(content)
      55 |         return True, f"Successfully wrote {path}"
      56 |     except OSError as e:
      57 |         return False, f"Failed to write {path}: {str(e)}"
      58 | 
      59 | 
      60 | def check_file_exists(local_path: str, *patterns: str) -> list[str]:
      61 |     """Check which of the given file patterns exist.
      62 | 
      63 |     Args:
```

#### TM-I-042: File open with variable path: template_path

**Risk:** MEDIUM (severity × confidence = 2.00)
**Location:** `packages/darnit/src/darnit/remediation/executor.py:364`
**Source:** `tree_sitter_structural` — query `python.info_disc.open_call`

``open(template_path)`` uses a variable path. If the path originates from user input without validation, this enables path traversal attacks (reading arbitrary files).

```
     354 |             # framework_path is available.
     355 |             template_path = template.file
     356 |             if not os.path.isabs(template_path):
     357 |                 if self._framework_path:
     358 |                     base_dir = os.path.dirname(self._framework_path)
     359 |                 else:
     360 |                     base_dir = self.local_path
     361 |                 template_path = os.path.join(base_dir, template_path)
     362 | 
     363 |             try:
>>>  364 |                 with open(template_path) as f:
     365 |                     return f.read()
     366 |             except OSError as e:
     367 |                 logger.warning(f"Failed to read template file {template_path}: {e}")
     368 |                 return None
     369 | 
     370 |         return None
     371 | 
     372 |     def execute(
     373 |         self,
     374 |         control_id: str,
```

#### TM-I-043: File open with variable path: toml_path

**Risk:** MEDIUM (severity × confidence = 2.00)
**Location:** `packages/darnit-example/src/darnit_example/tools.py:89`
**Source:** `tree_sitter_structural` — query `python.info_disc.open_call`

``open(toml_path)`` uses a variable path. If the path originates from user input without validation, this enables path traversal attacks (reading arbitrary files).

```
      79 |     impl = get_implementation("example-hygiene")
      80 |     if not impl:
      81 |         msg = "example-hygiene implementation not found"
      82 |         raise RuntimeError(msg)
      83 | 
      84 |     toml_path = impl.get_framework_config_path()
      85 |     if not toml_path or not toml_path.exists():
      86 |         msg = f"Framework TOML not found: {toml_path}"
      87 |         raise RuntimeError(msg)
      88 | 
>>>   89 |     with open(toml_path, "rb") as f:
      90 |         raw = tomllib.load(f)
      91 | 
      92 |     return FrameworkConfig(**raw)
      93 | 
      94 | 
      95 | # =============================================================================
      96 | # Audit tool
      97 | # =============================================================================
      98 | 
      99 | 
```

#### TM-I-044: File open with variable path: filepath

**Risk:** MEDIUM (severity × confidence = 2.00)
**Location:** `packages/darnit-example/src/darnit_example/handlers.py:35`
**Source:** `tree_sitter_structural` — query `python.info_disc.open_call`

``open(filepath)`` uses a variable path. If the path originates from user input without validation, this enables path traversal attacks (reading arbitrary files).

```
      25 | 
      26 |     Returns PASS if the README has at least one paragraph of text (>20 chars)
      27 |     beyond just the title line.
      28 |     """
      29 |     readme_names = config.get("readme_names", ["README.md", "README", "README.rst", "README.txt"])
      30 | 
      31 |     for name in readme_names:
      32 |         filepath = os.path.join(context.local_path, name)
      33 |         if os.path.exists(filepath):
      34 |             try:
>>>   35 |                 with open(filepath, encoding="utf-8", errors="ignore") as f:
      36 |                     content = f.read()
      37 |             except OSError:
      38 |                 continue
      39 | 
      40 |             # Strip the title line (first heading) and check remaining content
      41 |             lines = content.strip().splitlines()
      42 |             non_title_lines = []
      43 |             for line in lines:
      44 |                 stripped = line.strip()
      45 |                 if stripped.startswith("#") or stripped == "" or re.match(r"^[=\-]+$", stripped):
```

#### TM-I-045: File open with variable path: readme_path

**Risk:** MEDIUM (severity × confidence = 2.00)
**Location:** `packages/darnit-example/src/darnit_example/handlers.py:85`
**Source:** `tree_sitter_structural` — query `python.info_disc.open_call`

``open(readme_path)`` uses a variable path. If the path originates from user input without validation, this enables path traversal attacks (reading arbitrary files).

```
      75 |     Returns PASS if at least 2 sections are found.
      76 |     """
      77 |     readme_path = os.path.join(context.local_path, "README.md")
      78 |     if not os.path.exists(readme_path):
      79 |         return HandlerResult(
      80 |             status=HandlerResultStatus.INCONCLUSIVE,
      81 |             message="No README.md to analyze",
      82 |         )
      83 | 
      84 |     try:
>>>   85 |         with open(readme_path, encoding="utf-8", errors="ignore") as f:
      86 |             content = f.read().lower()
      87 |     except OSError:
      88 |         return HandlerResult(
      89 |             status=HandlerResultStatus.INCONCLUSIVE,
      90 |             message="Could not read README.md",
      91 |         )
      92 | 
      93 |     sections = config.get("sections", ["install", "usage", "getting started", "contributing", "license"])
      94 |     sections_found = [s for s in sections if s in content]
      95 | 
```

### Denial of Service

#### Low-risk findings (43)

| # | Title | Location | Score |
|---|-------|----------|-------|
| TM-D-001 | No timeout on subprocess.run() | `scripts/create-example-test-repo.py:136` | 1.80 |
| TM-D-002 | No timeout on subprocess.run() | `scripts/create-example-test-repo.py:139` | 1.80 |
| TM-D-003 | No timeout on subprocess.run() | `scripts/create-example-test-repo.py:142` | 1.80 |
| TM-D-004 | No timeout on subprocess.run() | `scripts/create-example-test-repo.py:280` | 1.80 |
| TM-D-005 | No timeout on subprocess.run() | `scripts/create-example-test-repo.py:297` | 1.80 |
| TM-D-006 | No timeout on subprocess.run() | `scripts/create-example-test-repo.py:308` | 1.80 |
| TM-D-007 | No timeout on subprocess.run() | `scripts/create-example-test-repo.py:329` | 1.80 |
| TM-D-008 | No timeout on subprocess.run() | `packages/darnit-baseline/src/darnit_baseline/attestation/git.py:24` | 1.80 |
| TM-D-009 | No timeout on subprocess.run() | `packages/darnit-baseline/src/darnit_baseline/attestation/git.py:48` | 1.80 |
| TM-D-010 | No timeout on subprocess.run() | `packages/darnit-baseline/src/darnit_baseline/attestation/git.py:60` | 1.80 |
| TM-D-011 | No timeout on subprocess.run() | `packages/darnit/src/darnit/core/utils.py:27` | 1.80 |
| TM-D-012 | No timeout on subprocess.run() | `packages/darnit/src/darnit/server/tools/test_repository.py:83` | 1.80 |
| TM-D-013 | No timeout on subprocess.run() | `packages/darnit/src/darnit/server/tools/test_repository.py:89` | 1.80 |
| TM-D-014 | No timeout on subprocess.run() | `packages/darnit/src/darnit/server/tools/test_repository.py:95` | 1.80 |
| TM-D-015 | No timeout on subprocess.run() | `packages/darnit/src/darnit/server/tools/test_repository.py:123` | 1.80 |
| TM-D-016 | No timeout on subprocess.run() | `packages/darnit/src/darnit/server/tools/test_repository.py:133` | 1.80 |
| TM-D-017 | No timeout on subprocess.run() | `packages/darnit/src/darnit/server/tools/test_repository.py:141` | 1.80 |
| TM-D-018 | No timeout on subprocess.run() | `packages/darnit/src/darnit/server/tools/test_repository.py:157` | 1.80 |
| TM-D-019 | No timeout on subprocess.run() | `packages/darnit/src/darnit/server/tools/git_operations.py:34` | 1.80 |
| TM-D-020 | No timeout on subprocess.run() | `packages/darnit/src/darnit/server/tools/git_operations.py:45` | 1.80 |
| TM-D-021 | No timeout on subprocess.run() | `packages/darnit/src/darnit/server/tools/git_operations.py:53` | 1.80 |
| TM-D-022 | No timeout on subprocess.run() | `packages/darnit/src/darnit/server/tools/git_operations.py:61` | 1.80 |
| TM-D-023 | No timeout on subprocess.run() | `packages/darnit/src/darnit/server/tools/git_operations.py:68` | 1.80 |
| TM-D-024 | No timeout on subprocess.run() | `packages/darnit/src/darnit/server/tools/git_operations.py:73` | 1.80 |
| TM-D-025 | No timeout on subprocess.run() | `packages/darnit/src/darnit/server/tools/git_operations.py:77` | 1.80 |
| TM-D-026 | No timeout on subprocess.run() | `packages/darnit/src/darnit/server/tools/git_operations.py:82` | 1.80 |
| TM-D-027 | No timeout on subprocess.run() | `packages/darnit/src/darnit/server/tools/git_operations.py:84` | 1.80 |
| TM-D-028 | No timeout on subprocess.run() | `packages/darnit/src/darnit/server/tools/git_operations.py:98` | 1.80 |
| TM-D-029 | No timeout on subprocess.run() | `packages/darnit/src/darnit/server/tools/git_operations.py:144` | 1.80 |
| TM-D-030 | No timeout on subprocess.run() | `packages/darnit/src/darnit/server/tools/git_operations.py:168` | 1.80 |
| TM-D-031 | No timeout on subprocess.run() | `packages/darnit/src/darnit/server/tools/git_operations.py:209` | 1.80 |
| TM-D-032 | No timeout on subprocess.run() | `packages/darnit/src/darnit/server/tools/git_operations.py:222` | 1.80 |
| TM-D-033 | No timeout on subprocess.run() | `packages/darnit/src/darnit/server/tools/git_operations.py:277` | 1.80 |
| TM-D-034 | No timeout on subprocess.run() | `packages/darnit/src/darnit/server/tools/git_operations.py:295` | 1.80 |
| TM-D-035 | No timeout on subprocess.run() | `packages/darnit/src/darnit/server/tools/git_operations.py:308` | 1.80 |
| TM-D-036 | No timeout on subprocess.run() | `packages/darnit/src/darnit/server/tools/git_operations.py:318` | 1.80 |
| TM-D-037 | No timeout on subprocess.run() | `packages/darnit/src/darnit/server/tools/git_operations.py:382` | 1.80 |
| TM-D-038 | No timeout on subprocess.run() | `packages/darnit/src/darnit/server/tools/git_operations.py:393` | 1.80 |
| TM-D-039 | No timeout on subprocess.run() | `packages/darnit/src/darnit/server/tools/git_operations.py:442` | 1.80 |
| TM-D-040 | No timeout on subprocess.run() | `packages/darnit/src/darnit/server/tools/git_operations.py:453` | 1.80 |
| TM-D-041 | No timeout on subprocess.run() | `packages/darnit/src/darnit/server/tools/git_operations.py:464` | 1.80 |
| TM-D-042 | No timeout on subprocess.run() | `packages/darnit/src/darnit/server/tools/git_operations.py:475` | 1.80 |
| TM-D-043 | No timeout on subprocess.run() | `packages/darnit/src/darnit/remediation/helpers.py:93` | 1.80 |

### Elevation of Privilege

#### TM-E-001: Dynamic import via importlib.import_module(module_path)

**Risk:** MEDIUM (severity × confidence = 3.50)
**Location:** `packages/darnit/src/darnit/core/registry.py:821`
**Source:** `tree_sitter_structural` — query `python.eop.dynamic_import_attr`

Dynamic imports allow loading arbitrary modules at runtime. If the module name originates from untrusted input, an attacker can achieve arbitrary code execution.

```
     811 | 
     812 |         # Security: Validate module path against allowlist to prevent arbitrary code loading
     813 |         if not any(module_path.startswith(prefix) for prefix in self.ALLOWED_MODULE_PREFIXES):
     814 |             logger.error(
     815 |                 f"Adapter {name}: module '{module_path}' not in allowed prefixes. "
     816 |                 f"Allowed: {self.ALLOWED_MODULE_PREFIXES}"
     817 |             )
     818 |             return None
     819 | 
     820 |         try:
>>>  821 |             module = importlib.import_module(module_path)
     822 |             adapter_class = getattr(module, class_name)
     823 |             return adapter_class()
     824 | 
     825 |         except ImportError as e:
     826 |             logger.error(f"Failed to import adapter {name}: {e}")
     827 |             return None
     828 |         except AttributeError as e:
     829 |             logger.error(f"Adapter {name}: class {class_name} not found: {e}")
     830 |             return None
     831 | 
```

#### TM-E-002: Dynamic import via importlib.import_module(module_path)

**Risk:** MEDIUM (severity × confidence = 3.50)
**Location:** `packages/darnit/src/darnit/core/handlers.py:237`
**Source:** `tree_sitter_structural` — query `python.eop.dynamic_import_attr`

Dynamic imports allow loading arbitrary modules at runtime. If the module name originates from untrusted input, an attacker can achieve arbitrary code execution.

```
     227 |             module_path, func_name = path.rsplit(":", 1)
     228 | 
     229 |             # Validate module path against allowlist to prevent arbitrary imports
     230 |             if not any(module_path.startswith(prefix) for prefix in self.ALLOWED_MODULE_PREFIXES):
     231 |                 logger.warning(
     232 |                     f"Module path '{module_path}' not in allowed prefixes: "
     233 |                     f"{self.ALLOWED_MODULE_PREFIXES}"
     234 |                 )
     235 |                 return None
     236 | 
>>>  237 |             module = importlib.import_module(module_path)
     238 |             return getattr(module, func_name, None)
     239 |         except (ValueError, ImportError, AttributeError) as e:
     240 |             logger.warning(f"Failed to load handler from path '{path}': {e}")
     241 |             return None
     242 | 
     243 |     # =========================================================================
     244 |     # Pass Registration
     245 |     # =========================================================================
     246 | 
     247 |     def register_pass(
```

#### TM-E-003: Dynamic import via importlib.import_module(module_path)

**Risk:** MEDIUM (severity × confidence = 3.50)
**Location:** `packages/darnit/src/darnit/core/adapters.py:666`
**Source:** `tree_sitter_structural` — query `python.eop.dynamic_import_attr`

Dynamic imports allow loading arbitrary modules at runtime. If the module name originates from untrusted input, an attacker can achieve arbitrary code execution.

```
     656 | 
     657 |         # Security: Validate module path against allowlist to prevent arbitrary code loading
     658 |         if not any(module_path.startswith(prefix) for prefix in self.ALLOWED_MODULE_PREFIXES):
     659 |             logger.error(
     660 |                 f"Adapter {name}: module '{module_path}' not in allowed prefixes. "
     661 |                 f"Allowed: {self.ALLOWED_MODULE_PREFIXES}"
     662 |             )
     663 |             return None
     664 | 
     665 |         try:
>>>  666 |             module = importlib.import_module(module_path)
     667 |             adapter_class = getattr(module, class_name)
     668 | 
     669 |             if not issubclass(adapter_class, expected_type):
     670 |                 logger.error(
     671 |                     f"Adapter {name}: {class_name} is not a {expected_type.__name__}"
     672 |                 )
     673 |                 return None
     674 | 
     675 |             return adapter_class()
     676 | 
```

#### TM-E-004: Dynamic import via importlib.import_module(module_path)

**Risk:** MEDIUM (severity × confidence = 3.50)
**Location:** `packages/darnit/src/darnit/server/registry.py:151`
**Source:** `tree_sitter_structural` — query `python.eop.dynamic_import_attr`

Dynamic imports allow loading arbitrary modules at runtime. If the module name originates from untrusted input, an attacker can achieve arbitrary code execution.

```
     141 |                 return handler
     142 | 
     143 |             raise ValueError(
     144 |                 f"Handler '{spec.handler}' not found in registry. "
     145 |                 "Either register it via register_handlers() or use "
     146 |                 "full module path 'module.path:function_name'"
     147 |             )
     148 | 
     149 |         # Full module path format
     150 |         module_path, func_name = spec.handler.rsplit(":", 1)
>>>  151 |         module = importlib.import_module(module_path)
     152 |         return getattr(module, func_name)
     153 | 
     154 |     def _load_builtin(
     155 |         self, spec: ToolSpec, framework_name: str | None
     156 |     ) -> Callable[..., Any]:
     157 |         """Load a built-in tool and bind it to a framework.
     158 | 
     159 |         Built-in tools receive the framework name as a bound parameter
     160 |         so they know which TOML config to load.
     161 | 
```

## Attack Chains

No compound attack paths identified.

## Recommendations Summary

### Immediate Actions (Critical / High)

1. **Potential command injection via subprocess.run** — `packages/darnit/src/darnit/core/adapters.py:231`
2. **Potential command injection via subprocess.run** — `packages/darnit/src/darnit/sieve/builtin_handlers.py:137`
3. **Potential command injection via subprocess.run** — `packages/darnit-plugins/src/darnit_plugins/adapters/kusari.py:253`
4. **Potential command injection via subprocess.run** — `packages/darnit-baseline/src/darnit_baseline/threat_model/opengrep_runner.py:131`
5. **Potential command injection via subprocess.run** — `packages/darnit/src/darnit/server/tools/git_operations.py:382`

### Short-term Actions (Medium)

1. **Unauthenticated mcp tool (mcp): (dynamic — registered from registry.tools)** — `packages/darnit/src/darnit/server/factory.py:149`
2. **Unauthenticated mcp tool (mcp): (dynamic — registered from registry.tools)** — `packages/darnit/src/darnit/server/factory.py:195`
3. **Dynamic import via importlib.import_module(module_path)** — `packages/darnit/src/darnit/core/registry.py:821`
4. **Dynamic import via importlib.import_module(module_path)** — `packages/darnit/src/darnit/core/handlers.py:237`
5. **Dynamic import via importlib.import_module(module_path)** — `packages/darnit/src/darnit/core/adapters.py:666`
6. **Dynamic import via importlib.import_module(module_path)** — `packages/darnit/src/darnit/server/registry.py:151`
7. **Potential command injection via subprocess.run** — `docs/examples/python-framework/example_framework/implementation.py:400`
8. **Potential command injection via subprocess.run** — `docs/examples/python-framework/example_framework/implementation.py:603`
9. **Potential command injection via subprocess.run** — `scripts/create-example-test-repo.py:142`
10. **Potential command injection via subprocess.run** — `scripts/create-example-test-repo.py:308`
11. **Potential command injection via subprocess.run** — `packages/darnit-baseline/src/darnit_baseline/threat_model/ts_generators.py:123`
12. **Potential command injection via subprocess.run** — `packages/darnit-baseline/src/darnit_baseline/threat_model/opengrep_runner.py:64`
13. **Potential command injection via subprocess.run** — `packages/darnit/src/darnit/tools/audit_org.py:62`
14. **Potential command injection via subprocess.run** — `packages/darnit/src/darnit/tools/audit_org.py:113`
15. **Potential command injection via subprocess.run** — `packages/darnit/src/darnit/context/auto_detect.py:518`
16. **Potential command injection via subprocess.run** — `packages/darnit/src/darnit/core/utils.py:27`
17. **Potential command injection via subprocess.run** — `packages/darnit/src/darnit/core/utils.py:99`
18. **Potential command injection via subprocess.run** — `packages/darnit/src/darnit/core/utils.py:161`
19. **Potential command injection via subprocess.run** — `packages/darnit/src/darnit/core/utils.py:367`
20. **Potential command injection via subprocess.run** — `packages/darnit/src/darnit/core/utils.py:385`
21. **Potential command injection via subprocess.run** — `packages/darnit/src/darnit/core/utils.py:396`
22. **Potential command injection via subprocess.run** — `packages/darnit/src/darnit/core/adapters.py:354`
23. **Potential command injection via subprocess.run** — `packages/darnit/src/darnit/server/tools/test_repository.py:141`
24. **Potential command injection via subprocess.run** — `packages/darnit/src/darnit/server/tools/git_operations.py:45`
25. **Potential command injection via subprocess.run** — `packages/darnit/src/darnit/server/tools/git_operations.py:53`
26. **Potential command injection via subprocess.run** — `packages/darnit/src/darnit/server/tools/git_operations.py:68`
27. **Potential command injection via subprocess.run** — `packages/darnit/src/darnit/server/tools/git_operations.py:98`
28. **Potential command injection via subprocess.run** — `packages/darnit/src/darnit/server/tools/git_operations.py:209`
29. **Potential command injection via subprocess.run** — `packages/darnit/src/darnit/server/tools/git_operations.py:295`
30. **Potential command injection via subprocess.run** — `packages/darnit/src/darnit/remediation/github.py:268`
31. **File open with variable path: filepath** — `docs/examples/python-framework/example_framework/implementation.py:175`
32. **File open with variable path: filepath** — `docs/examples/python-framework/example_framework/implementation.py:495`
33. **File open with variable path: filepath** — `docs/examples/python-framework/example_framework/implementation.py:540`
34. **File open with variable path: filepath** — `docs/examples/python-framework/example_framework/implementation.py:571`
35. **File open with variable path: TOML_PATH** — `scripts/validate_sync.py:58`
36. **File open with variable path: toml_path** — `packages/darnit-baseline/src/darnit_baseline/implementation.py:103`
37. **File open with variable path: full_path** — `packages/darnit-baseline/src/darnit_baseline/threat_model/remediation.py:296`
38. **File open with variable path: full_path** — `packages/darnit-baseline/src/darnit_baseline/threat_model/remediation.py:351`
39. **File open with variable path: path** — `packages/darnit-baseline/src/darnit_baseline/threat_model/dependencies.py:192`
40. **File open with variable path: output_path** — `packages/darnit-baseline/src/darnit_baseline/attestation/generator.py:134`
41. **File open with variable path: toml_path** — `packages/darnit-baseline/src/darnit_baseline/remediation/orchestrator.py:132`
42. **File open with variable path: project_yaml** — `packages/darnit-baseline/src/darnit_baseline/remediation/orchestrator.py:510`
43. **File open with variable path: self.project_yaml** — `packages/darnit/src/darnit/context/dot_project.py:348`
44. **File open with variable path: self.maintainers_yaml** — `packages/darnit/src/darnit/context/dot_project.py:389`
45. **File open with variable path: self.project_yaml** — `packages/darnit/src/darnit/context/dot_project.py:849`
46. **File open with variable path: self.project_yaml** — `packages/darnit/src/darnit/context/dot_project.py:862`
47. **File open with variable path: cache_path** — `packages/darnit/src/darnit/core/verification.py:221`
48. **File open with variable path: cache_path** — `packages/darnit/src/darnit/core/verification.py:296`
49. **File open with variable path: filepath** — `packages/darnit/src/darnit/core/utils.py:337`
50. **File open with variable path: filepath** — `packages/darnit/src/darnit/core/utils.py:351`
51. **File open with variable path: cache_path** — `packages/darnit/src/darnit/core/audit_cache.py:170`
52. **File open with variable path: full_path** — `packages/darnit/src/darnit/config/discovery.py:82`
53. **File open with variable path: pkg_path** — `packages/darnit/src/darnit/config/discovery.py:144`
54. **File open with variable path: pyproj_path** — `packages/darnit/src/darnit/config/discovery.py:156`
55. **File open with variable path: cargo_path** — `packages/darnit/src/darnit/config/discovery.py:168`
56. **File open with variable path: go_mod_path** — `packages/darnit/src/darnit/config/discovery.py:179`
57. **File open with variable path: path** — `packages/darnit/src/darnit/config/loader.py:137`
58. **File open with variable path: path** — `packages/darnit/src/darnit/config/loader.py:234`
59. **File open with variable path: path** — `packages/darnit/src/darnit/config/merger.py:425`
60. **File open with variable path: config_path** — `packages/darnit/src/darnit/config/merger.py:447`
61. **File open with variable path: config_path** — `packages/darnit/src/darnit/server/factory.py:122`
62. **File open with variable path: os.path.join(repo_path, "package.json")** — `packages/darnit/src/darnit/server/tools/test_repository.py:58`
63. **File open with variable path: os.path.join(repo_path, "src", "index.js")** — `packages/darnit/src/darnit/server/tools/test_repository.py:70`
64. **File open with variable path: os.path.join(repo_path, ".gitignore")** — `packages/darnit/src/darnit/server/tools/test_repository.py:78`
65. **File open with variable path: fpath** — `packages/darnit/src/darnit/sieve/builtin_handlers.py:395`
66. **File open with variable path: full** — `packages/darnit/src/darnit/sieve/builtin_handlers.py:486`
67. **File open with variable path: full_path** — `packages/darnit/src/darnit/sieve/builtin_handlers.py:565`
68. **File open with variable path: filepath** — `packages/darnit/src/darnit/sieve/builtin_handlers.py:677`
69. **File open with variable path: filepath** — `packages/darnit/src/darnit/sieve/builtin_handlers.py:711`
70. **File open with variable path: filepath** — `packages/darnit/src/darnit/remediation/github.py:53`
71. **File open with variable path: path** — `packages/darnit/src/darnit/remediation/helpers.py:53`
72. **File open with variable path: template_path** — `packages/darnit/src/darnit/remediation/executor.py:364`
73. **File open with variable path: toml_path** — `packages/darnit-example/src/darnit_example/tools.py:89`
74. **File open with variable path: filepath** — `packages/darnit-example/src/darnit_example/handlers.py:35`
75. **File open with variable path: readme_path** — `packages/darnit-example/src/darnit_example/handlers.py:85`

## Verification Prompts

<!-- darnit:verification-prompt-block -->

**For the calling agent (Claude via MCP):** this draft was produced by the darnit tree-sitter discovery pipeline. Before committing, follow these steps for each finding listed above:

1. Read the embedded code snippet. The line prefixed with `>>>` is the anchor line for the finding.
2. Ask: does the code at this location plausibly exhibit the described threat? If not, remove the finding entirely from the committed file.
3. For findings you keep, refine the narrative with project-specific details where helpful (which caller reaches this sink, what data flows through it, etc.).
4. Preserve the STRIDE category headings even when their content changes. Downstream consumers parse H2 headers from this document.
5. Preserve this `darnit:verification-prompt-block` section — it marks the draft as having gone through review. Once every finding has been verified or removed, commit the file through the normal `darnit-remediate` skill flow.

*Findings marked with Risk LOW are rendered in a compact summary table. Without taint analysis, many LOW and MEDIUM findings may be noise — verify against the code snippets before acting on them.*

<!-- /darnit:verification-prompt-block -->

## Limitations

- Scanned **173** in-scope files (python=129, yaml=44).
- Skipped **48** vendor/build directories and **364** files in unsupported languages.
- Opengrep taint analysis: available.

*This is a threat-modeling aid, not an exhaustive vulnerability scan. Full dynamic and cross-function taint analysis is out of scope for darnit; use Kusari Inspector or an equivalent SAST tool for deeper coverage.*

