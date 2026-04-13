"""Fixture — subprocess calls with hardcoded list arguments.

Expected discovery:
- ZERO subprocess findings. Every call here uses a literal list of string
  literals as the first argument, so the ``_subprocess_call_is_clearly_safe``
  filter should drop them all.

- The ``subprocess.run(cmd)`` variant uses a variable and therefore STAYS
  as a finding — we cannot rule out a bad caller without taint analysis.

- The ``shell=True`` variant STAYS as a finding even with a literal string,
  because shell=True is a structural smell.
"""

import subprocess


def safe_literal_list() -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", "status", "--porcelain"], capture_output=True, text=True
    )


def safe_run_check_output() -> bytes:
    return subprocess.check_output(["ls", "-la", "/tmp"])


def unsafe_variable_cmd(cmd: list[str]) -> subprocess.CompletedProcess:
    # Variable cmd — stays as a finding (we can't rule out tainted input)
    return subprocess.run(cmd, capture_output=True)


def unsafe_shell_true() -> subprocess.CompletedProcess:
    # shell=True with a hardcoded string is still flagged — the shape is a smell
    return subprocess.run("echo hello", shell=True, capture_output=True)
