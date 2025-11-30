# darnit

Generic compliance audit framework with plugin architecture.

## Overview

**darnit** is the core framework that provides:

- **Plugin System**: Discover and load compliance implementations via Python entry points
- **Configuration Management**: `.project.yaml` for project metadata and file locations
- **Progressive Verification**: "Sieve" model for efficient compliance checking
- **Attestation Generation**: Create cryptographically signed in-toto attestations
- **Threat Modeling**: Built-in STRIDE analysis
- **Remediation Framework**: Auto-fix infrastructure for compliance gaps
- **MCP Server Tools**: Ready-to-use tools for AI assistant integration

## Installation

```bash
pip install darnit
```

For attestation support:
```bash
pip install darnit[attestation]
```

## Usage

### Discover Implementations

```python
from darnit.core.discovery import discover_implementations

# Discover all installed compliance implementations
implementations = discover_implementations()

# Get a specific implementation
baseline = implementations.get("openssf-baseline")
```

### Configuration Management

```python
from darnit.config.loader import load_project_config, save_project_config
from darnit.config.discovery import discover_files

# Discover existing documentation files
discovered = discover_files("/path/to/repo")

# Load project configuration
config = load_project_config("/path/to/repo")
```

### Generate Attestations

```python
from darnit.attestation import generate_attestation_from_results

# Generate a signed attestation
attestation = generate_attestation_from_results(
    audit_result=result,
    sign=True
)
```

## Creating Implementations

To create a new compliance implementation:

1. Create a package with entry point `darnit.implementations`
2. Implement the `ComplianceImplementation` protocol
3. Register controls and checks

```toml
# pyproject.toml
[project.entry-points."darnit.implementations"]
my-standard = "my_package:register"
```

```python
# my_package/__init__.py
def register():
    from .implementation import MyImplementation
    return MyImplementation()
```

See [darnit-baseline](../darnit-baseline) for a complete example.

## Package Structure

```
darnit/
├── core/           # Plugin system, models, discovery
├── config/         # Project configuration (.project.yaml)
├── sieve/          # Progressive verification pipeline
├── attestation/    # in-toto attestation generation
├── threat_model/   # STRIDE threat modeling
├── remediation/    # Auto-fix framework
├── server/         # MCP server tool implementations
└── tools/          # MCP tool helpers and utilities
```

## License

Apache-2.0
