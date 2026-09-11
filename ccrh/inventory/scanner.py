import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

DEFAULT_IGNORED_DIRS = {".git", ".venv", "venv", "__pycache__", "node_modules"}


@dataclass(frozen=True)
class FileRecord:
    path: str
    size: int
    suffix: str
    text: str | None
    sha256: str
    kind: str


def iter_files(root: Path, ignored_dirs: set[str] | None = None) -> Iterator[Path]:
    ignored = DEFAULT_IGNORED_DIRS | (ignored_dirs or set())
    for path in sorted(root.rglob("*")):
        if path.is_file() and not any(part in ignored for part in path.parts):
            yield path


def read_text(path: Path, max_bytes: int = 2_000_000) -> str | None:
    try:
        if path.stat().st_size > max_bytes:
            return None
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None


def classify(path: Path, text: str | None) -> str:
    if text is not None:
        return "text"
    if path.suffix.lower() in {".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp"}:
        return "image"
    if path.suffix.lower() in {".zip", ".tar", ".gz", ".7z", ".rar"}:
        return "archive"
    return "binary"


def inventory(root: Path) -> list[FileRecord]:
    root = root.resolve()
    records: list[FileRecord] = []
    for path in iter_files(root):
        data = path.read_bytes()
        text = read_text(path)
        records.append(FileRecord(str(path.relative_to(root)), len(data), path.suffix.lower(), text, hashlib.sha256(data).hexdigest(), classify(path, text)))
    return records
