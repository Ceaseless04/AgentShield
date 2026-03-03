# AgentShield

AgentShield is a lightweight Python SDK (v0.1.4) that provides a secure middleware
layer between AI agents and developer resources such as repositories,
file systems, APIs, and tools.

Its purpose is to prevent accidental leakage of sensitive data (API keys,
passwords, tokens, etc.) while still allowing agents to perform useful
work.

## Features

* **SecureFS** – safe file reader that scans and redacts secrets.
* **SecretScanner** – regex/entropy-based detection engine.
* **Redactor** – replaces detected secrets with placeholders.
* **OutputGuard** – inspects agent outputs and blocks or redacts leaks.
* **Policy** – YAML-driven configuration for allowed/blocked types.

## Getting Started

Install via pip (when released) or add the package to your project.

```bash
pip install agentshield-api
```

*If you’re just trying the library out against a test index, you can
install from TestPyPI with:*

```bash
pip install -i https://test.pypi.org/simple agentshield-api
```

Note that the distribution on PyPI is named **agentshield-api** (not
`agentshield`) to avoid collisions with other projects.
```python
from agentshield import SecureFS, OutputGuard

fs = SecureFS()
safe_content = fs.read_file("config.env")

guard = OutputGuard()
clean_output = guard.inspect("some text containing secret=abc123")
```

### Running the test suite

A small pytest-based test suite lives under `tests/`.  After installing
requirements (`PyYAML`, `pytest`), run:

```bash
python -m pytest -q
```

You should see five tests covering core functionality.

### Extending detection

The :class:`agentshield.secret_scanner.SecretScanner` class ships with a
set of common regexes (API keys, tokens, AWS formats, JWTs, etc.).  If
you need to recognise additional secrets, simply:

```python
from agentshield.secret_scanner import SecretScanner
import re

scanner = SecretScanner()
scanner.register_pattern("MY_SECRET", re.compile(r"mysecret=\S+"))
```

Patterns are applied in the order they are registered, and you can also
provide a custom list during initialization.

## Custom policy

By default the library loads a YAML file named `default_policy.yaml` from the
`policies/` directory in the package.  You can override this behaviour by
suppling your own `Policy` instance:

```python
from agentshield import SecureFS, Policy

policy = Policy(allowed=["ENV_VAR"], blocked=["API_KEY"], block_mode="error")
fs = SecureFS(policy=policy)
``` 

Or create your own YAML file and load it:

```python
p = Policy.load_from_file("/path/to/my_policy.yaml")
guard = OutputGuard(policy=p)
```

The configuration schema is simple:

```yaml
allowed:
  - ENV_VAR
blocked:
  - API_KEY
block_mode: redact  # or error or warn
```

This makes it easy to adapt AgentShield to your project’s risk profile.

## Project Structure

```
agentshield/
  __init__.py
  secure_fs.py
  secret_scanner.py
  redactor.py
  output_guard.py
  policy.py
policies/
  default_policy.yaml
examples/
  example_usage.py
tests/
  test_*.py
pyproject.toml
requirements.txt
README.md
LICENSE
```

## License

This project is open source under the Apache license.
