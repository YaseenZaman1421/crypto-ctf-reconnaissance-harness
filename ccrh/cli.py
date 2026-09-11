import argparse
from pathlib import Path

from ccrh.analysis.ranker import rank_attacks
from ccrh.analysis.solvers import analyze, finding_dicts
from ccrh.inventory.scanner import inventory
from ccrh.parsers.crypto import extract_clues, extract_parameters, parameter_dict
from ccrh.reporting.render import render_markdown, report_data, write_json


def scan(root: Path, output: Path | None, markdown: Path | None) -> int:
    records = inventory(root)
    clues = [clue for record in records for clue in extract_clues(record)]
    parameters = [parameter for record in records for parameter in extract_parameters(record)]
    findings = finding_dicts(analyze(parameters))
    report = report_data(
        str(root.resolve()),
        [{"path": r.path, "size": r.size, "suffix": r.suffix, "sha256": r.sha256, "kind": r.kind, "text_read": r.text is not None} for r in records],
        [{"kind": c.kind, "value": c.value, "path": c.path, "line": c.line, "evidence": c.evidence} for c in clues],
        parameter_dict(parameters),
        rank_attacks(clues, [parameter.name for parameter in parameters]),
        findings,
    )
    if output:
        write_json(report, output)
    if markdown:
        markdown.parent.mkdir(parents=True, exist_ok=True)
        markdown.write_text(render_markdown(report), encoding="utf-8")
    print(f"Scanned {len(records)} files; found {len(clues)} crypto clues.")
    if report["ranked_attacks"]:
        print("Likely attack areas: " + ", ".join(item["kind"] for item in report["ranked_attacks"]))
    print(f"Computational findings: {len(findings)}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(prog="ccrh", description="Reconnaissance-first crypto CTF helper")
    subparsers = parser.add_subparsers(dest="command", required=True)
    scan_parser = subparsers.add_parser("scan", help="inventory a challenge directory and rank crypto clues")
    scan_parser.add_argument("root", type=Path)
    scan_parser.add_argument("--output", "-o", type=Path, help="write a JSON report")
    scan_parser.add_argument("--markdown", "-m", type=Path, help="write a Markdown report")
    args = parser.parse_args()
    return scan(args.root, args.output, args.markdown) if args.command == "scan" else 2


if __name__ == "__main__":
    raise SystemExit(main())
