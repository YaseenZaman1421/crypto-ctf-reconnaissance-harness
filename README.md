# Crypto-CTF Reconnaissance Harness (CCRH)

CCRH is a reconnaissance-first toolkit for cryptography CTF challenges.

The first milestone inventories challenge files, extracts crypto-related clues, ranks likely attack paths, and produces evidence-backed JSON or Markdown reports. The upstream projects below remain implementation references, not runtime dependencies.

## Quick start

```bash
python3 -m ccrh.cli scan ./challenge -o report.json -m report.md
```

Or, after installation:

```bash
python3 -m pip install -e .
ccrh scan ./challenge -o report.json -m report.md
```

Reports include file size, type, SHA-256, extracted parameter assignments, line-level clues, and ranked attack paths. The scanner is dependency-free and uses conservative text heuristics. It never imports or executes challenge code.

## Bounded solver analysis

The scanner also performs safe, bounded checks for:

- RSA low-exponent roots, perfect-square moduli, shared factors, explicit `p × q` consistency, and trial factorization.
- Hex/Base64 printable layers.
- Single-byte and repeating-key XOR candidates.

Control trial division explicitly when needed:

```bash
ccrh scan ./challenge --trial-factor-bound 10000000
```

The report records detected solver capabilities (`python`, `sage`, and `z3`). SageMath and Z3 are capability signals for future adapters; the current release does not execute challenge code or invoke external solvers automatically.

## Reference projects

- CtfCryptoTool
- CTF Kit
- CTF-Crypto-Toolkit
- CyberChef
- RsaCtfTool
- xortool

Reference projects are kept separate while licenses, dependencies, and reusable components are reviewed.
