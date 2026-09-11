# Contributing to CCRH

CCRH is a defensive, reconnaissance-first tool for cryptography CTF work. Contributions should preserve the default safety boundary: scanning must not execute challenge code, make network requests, or modify challenge files.

## Development

```bash
python3 -m unittest discover -v
python3 -m compileall -q ccrh tests
python3 -m pip install -e .
ccrh scan ./challenge -o report.json -m report.md
```

New analyzers should be deterministic, bounded, evidence-linked, and covered by a focused test. If an analyzer uses an optional external tool, detect it explicitly and keep the built-in fallback usable.

## Pull requests

Explain the crypto technique, its computational bound, expected evidence, and false-positive behavior. Do not include private challenge flags, credentials, or destructive proof-of-concept payloads.
