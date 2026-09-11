import json
from pathlib import Path
from typing import Any


def report_data(root: str, files: list[dict[str, Any]], clues: list[dict[str, Any]], parameters: list[dict[str, Any]], attacks: list[dict[str, Any]]) -> dict[str, Any]:
    return {"schema_version": 1, "root": root, "files": files, "clues": clues, "parameters": parameters, "ranked_attacks": attacks}


def write_json(report: dict[str, Any], destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")


def render_markdown(report: dict[str, Any]) -> str:
    lines = ["# CCRH reconnaissance report", "", f"Root: `{report['root']}`", "", "## Files", ""]
    lines.extend(f"- `{item['path']}` ({item['size']} bytes, `{item['suffix'] or 'no extension'}`)" for item in report["files"])
    lines += ["", "## Extracted parameters", ""]
    lines.extend(f"- `{item['name']}` from `{item['path']}:{item['line']}`: `{item['value']}`" for item in report["parameters"])
    lines += ["", "## Ranked attack paths", ""]
    lines.extend(f"- **{attack['kind']}** (score {attack['score']}): {attack['recommendation']}" for attack in report["ranked_attacks"])
    lines += ["", "## Evidence", ""]
    lines.extend(f"- `{clue['path']}:{clue['line']}` — **{clue['kind']}**: `{clue['evidence']}`" for clue in report["clues"])
    return "\n".join(lines) + "\n"
