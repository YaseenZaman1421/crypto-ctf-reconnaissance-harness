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
        if path.is_symlink():
            continue
        if path.is_file() and not any(part in ignored for part in path.parts):
            yield path


def read_text(path: Path, max_bytes: int = 2_000_000) -> str | None:
    try:
        if path.stat().st_size > max_bytes:
            return None
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None


def sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(chunk_size), b""):
            digest.update(chunk)
    return digest.hexdigest()


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
    if not root.is_dir():
        raise ValueError(f"scan root is not a directory: {root}")
    records: list[FileRecord] = []
    for path in iter_files(root):
        try:
            size = path.stat().st_size
            text = read_text(path)
            digest = sha256_file(path)
        except OSError:
            continue
        records.append(FileRecord(str(path.relative_to(root)), size, path.suffix.lower(), text, digest, classify(path, text)))
    return records
