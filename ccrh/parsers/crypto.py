import re
from dataclasses import dataclass
from typing import Any

from ccrh.inventory.scanner import FileRecord


@dataclass(frozen=True)
class Clue:
    kind: str
    value: str
    path: str
    line: int
    evidence: str


@dataclass(frozen=True)
class Parameter:
    name: str
    value: str
    path: str
    line: int
    evidence: str


PATTERNS = {
    "rsa": re.compile(r"\b(?:rsa|modulus|public_key|private_key|\b(?:e|d|p|q)\s*=)", re.I),
    "aes": re.compile(r"\b(?:aes|rijndael|cbc|gcm|ecb|iv|nonce)\b", re.I),
    "xor": re.compile(r"\b(?:xor|repeating.?key|single.?byte)\b|\^", re.I),
    "hash": re.compile(r"\b(?:md5|sha(?:1|224|256|384|512)?|blake2|hashlib)\b", re.I),
    "encoding": re.compile(r"\b(?:base64|base32|hex|hexlify|unhexlify|url.?encode)\b", re.I),
    "number_theory": re.compile(r"\b(?:prime|factor|gcd|crt|fermat|pohlig|discrete.?log)\b", re.I),
}


def extract_clues(record: FileRecord) -> list[Clue]:
    if record.text is None:
        return []
    clues = []
    for line_number, line in enumerate(record.text.splitlines(), 1):
        sample = line.strip()
        if not sample:
            continue
        for kind, pattern in PATTERNS.items():
            match = pattern.search(sample)
            if match:
                clues.append(Clue(kind, match.group(0), record.path, line_number, sample[:240]))
    return clues


PARAMETER_PATTERN = re.compile(
    r"\b(?P<name>modulus|public_key|private_key|ciphertext|plaintext|message|nonce|iv|key|n|e|d|p|q|c)\b\s*[:=]\s*(?P<value>[^,;#\n]+)",
    re.I,
)


def extract_parameters(record: FileRecord) -> list[Parameter]:
    if record.text is None:
        return []
    parameters: list[Parameter] = []
    for line_number, line in enumerate(record.text.splitlines(), 1):
        for match in PARAMETER_PATTERN.finditer(line):
            value = match.group("value").strip().strip("'\"")
            if value:
                parameters.append(Parameter(match.group("name").lower(), value[:500], record.path, line_number, line.strip()[:240]))
    return parameters


def parameter_dict(parameters: list[Parameter]) -> list[dict[str, Any]]:
    return [{"name": item.name, "value": item.value, "path": item.path, "line": item.line, "evidence": item.evidence} for item in parameters]
