# CCRH usage guide

## Install from source

```bash
python3 -m pip install .
```

For a user-local executable:

```bash
python3 -m pip install --user .
```

For an isolated environment, use `pipx install .` when pipx is available.

## Scan a challenge

```bash
ccrh scan ./challenge --output reports/challenge.json --markdown reports/challenge.md
```

The scanner reads files as data. It ignores common metadata/dependency directories, does not import challenge modules, and does not execute scripts.

## Computation bounds

Trial factorization is capped at one million by default:

```bash
ccrh scan ./challenge --trial-factor-bound 10000000
```

Increase this only for trusted, bounded workloads. The report records the selected findings and evidence, not just a yes/no conclusion.

## Report sections

- `files`: relative path, size, kind, SHA-256, and whether text was readable.
- `clues`: line-level crypto indicators.
- `parameters`: statically extracted assignments.
- `ranked_attacks`: heuristic attack areas.
- `findings`: bounded solver results with severity and evidence.
- `capabilities`: detected local solver backends.
