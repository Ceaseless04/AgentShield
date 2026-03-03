# AgentShield

AgentShield is a lightweight Python SDK (v0.1.1) that provides a secure middleware
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

Install via pip (when released) or add the package to your project:

```bash
pip install agentshield
```

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
README.md
LICENSE
```

## License

This project is open source under the Apache license.
🛡️ AgentShield is a zero-trust security layer that lets AI agents safely access repositories, tools, and APIs without exposing secrets or proprietary data.
