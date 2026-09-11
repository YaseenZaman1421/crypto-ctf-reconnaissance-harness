import base64
import binascii
import math
import shutil
import string
from dataclasses import dataclass

from ccrh.parsers.crypto import Parameter


@dataclass(frozen=True)
class Finding:
    category: str
    severity: str
    title: str
    detail: str
    evidence: list[str]


def _integer(value: str) -> int | None:
    cleaned = value.strip().replace("_", "")
    try:
        return int(cleaned, 0)
    except ValueError:
        try:
            return int(cleaned)
        except ValueError:
            return None


def _integer_parameters(parameters: list[Parameter], names: set[str]) -> list[tuple[Parameter, int]]:
    return [(parameter, value) for parameter in parameters if parameter.name in names and (value := _integer(parameter.value)) is not None]


def _iroot(value: int, degree: int) -> tuple[int, bool]:
    if value < 0:
        return 0, False
    low, high = 0, 1
    while high**degree <= value:
        high *= 2
    while low + 1 < high:
        middle = (low + high) // 2
        if middle**degree <= value:
            low = middle
        else:
            high = middle
    return low, low**degree == value


def _printable_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    return sum(chr(byte) in string.printable for byte in data) / len(data)


def _decode_text(value: str) -> list[tuple[str, bytes]]:
    candidates: list[tuple[str, bytes]] = []
    compact = "".join(value.split())
    if len(compact) % 2 == 0:
        try:
            candidates.append(("hex", bytes.fromhex(compact)))
        except ValueError:
            pass
    try:
        decoded = base64.b64decode(compact, validate=True)
        if decoded:
            candidates.append(("base64", decoded))
    except (ValueError, binascii.Error):
        pass
    return candidates


def analyze_parameters(parameters: list[Parameter]) -> list[Finding]:
    findings: list[Finding] = []
    ns = _integer_parameters(parameters, {"n", "modulus"})
    es = _integer_parameters(parameters, {"e"})
    cs = _integer_parameters(parameters, {"c", "ciphertext"})

    for n_parameter, n in ns:
        if n > 1 and math.isqrt(n) ** 2 == n:
            findings.append(Finding("rsa", "high", "RSA modulus is a perfect square", "The modulus has an integer square root and can be factored immediately.", [f"{n_parameter.path}:{n_parameter.line}"]))
    for e_parameter, e in es:
        if e in {3, 5, 7}:
            findings.append(Finding("rsa", "medium", "Small RSA public exponent", f"The public exponent is e={e}; inspect for an unpadded low-exponent attack.", [f"{e_parameter.path}:{e_parameter.line}"]))
    for e_parameter, e in es:
        for c_parameter, c in cs:
            if e <= 15:
                root, exact = _iroot(c, e)
                if exact:
                    findings.append(Finding("rsa", "critical", "Exact low-exponent RSA root found", f"ciphertext is an exact {e}-th power; recovered plaintext integer is {root}.", [f"{e_parameter.path}:{e_parameter.line}", f"{c_parameter.path}:{c_parameter.line}"]))

    for index, (first_parameter, first) in enumerate(ns):
        for second_parameter, second in ns[index + 1 :]:
            shared = math.gcd(first, second)
            if 1 < shared < min(first, second):
                findings.append(Finding("rsa", "critical", "RSA moduli share a factor", f"gcd(n1, n2) = {shared}; both moduli are factorable with the shared prime.", [f"{first_parameter.path}:{first_parameter.line}", f"{second_parameter.path}:{second_parameter.line}"]))
    return findings


def factor_small(value: int, bound: int = 1_000_000) -> tuple[int, int] | None:
    """Find a factor using bounded trial division; never runs beyond the configured bound."""
    if bound < 1 or bound > 100_000_000:
        raise ValueError("trial factor bound must be between 1 and 100000000")
    if value < 4:
        return None
    if value % 2 == 0:
        return 2, value // 2
    limit = min(math.isqrt(value), bound)
    candidate = 3
    while candidate <= limit:
        if value % candidate == 0:
            return candidate, value // candidate
        candidate += 2
    return None


def analyze_factorization(parameters: list[Parameter], bound: int) -> list[Finding]:
    findings: list[Finding] = []
    for parameter, value in _integer_parameters(parameters, {"n", "modulus"}):
        factors = factor_small(value, bound)
        if factors and factors[0] != factors[1]:
            findings.append(Finding("rsa", "high", "RSA modulus factored within bound", f"Found factors {factors[0]} and {factors[1]} using trial division capped at {bound:,}.", [f"{parameter.path}:{parameter.line}"]))
    return findings


def analyze_rsa_consistency(parameters: list[Parameter]) -> list[Finding]:
    findings: list[Finding] = []
    values = {name: _integer_parameters(parameters, {name}) for name in {"n", "p", "q"}}
    for n_parameter, n in values["n"]:
        for p_parameter, p in values["p"]:
            for q_parameter, q in values["q"]:
                if p * q == n:
                    findings.append(Finding("rsa", "high", "RSA factors explicitly reconstruct modulus", f"p × q equals n ({n}).", [f"{n_parameter.path}:{n_parameter.line}", f"{p_parameter.path}:{p_parameter.line}", f"{q_parameter.path}:{q_parameter.line}"]))
    return findings


def analyze_encodings(parameters: list[Parameter]) -> list[Finding]:
    findings: list[Finding] = []
    for parameter in parameters:
        for encoding, decoded in _decode_text(parameter.value):
            if _printable_ratio(decoded) >= 0.85 and len(decoded) >= 4:
                preview = decoded[:80].decode("utf-8", errors="replace")
                findings.append(Finding("encoding", "low", f"Printable {encoding} layer detected", f"{parameter.name} decodes as {encoding} to printable text: {preview!r}.", [f"{parameter.path}:{parameter.line}"]))
    return findings


def analyze_xor(parameters: list[Parameter]) -> list[Finding]:
    findings: list[Finding] = []
    ciphertexts = [parameter for parameter in parameters if parameter.name in {"ciphertext", "ct", "data"}]
    for parameter in ciphertexts:
        decoded = _decode_text(parameter.value)
        for encoding, ciphertext in decoded:
            if not 4 <= len(ciphertext) <= 4096:
                continue
            candidates = []
            for key in range(256):
                plaintext = bytes(byte ^ key for byte in ciphertext)
                score = _printable_ratio(plaintext)
                if score >= 0.92:
                    candidates.append((score, key, plaintext[:80]))
            candidates.sort(reverse=True)
            if candidates:
                score, key, preview = candidates[0]
                text = preview.decode("utf-8", errors="replace")
                findings.append(Finding("xor", "medium", "Printable single-byte XOR candidate", f"{encoding} ciphertext has a {score:.0%} printable candidate with key 0x{key:02x}: {text!r}.", [f"{parameter.path}:{parameter.line}"]))
    return findings


def _xor_score(data: bytes) -> float:
    common = b" etaoinshrdluETAOINSHRDLU{}_\n\r"
    if not data:
        return 0.0
    printable = _printable_ratio(data)
    common_ratio = sum(byte in common for byte in data) / len(data)
    return printable * 0.7 + common_ratio * 0.3


def analyze_repeating_xor(parameters: list[Parameter]) -> list[Finding]:
    findings: list[Finding] = []
    for parameter in [item for item in parameters if item.name in {"ciphertext", "ct", "data"}]:
        decoded = _decode_text(parameter.value)
        for encoding, ciphertext in decoded:
            if not 8 <= len(ciphertext) <= 4096:
                continue
            candidates: list[tuple[float, int, bytes]] = []
            for key_size in range(2, min(40, len(ciphertext) // 2) + 1):
                key = bytearray()
                for offset in range(key_size):
                    column = ciphertext[offset::key_size]
                    key.append(max(range(256), key=lambda byte: _xor_score(bytes(value ^ byte for value in column))))
                plaintext = bytes(value ^ key[index % key_size] for index, value in enumerate(ciphertext))
                candidates.append((_xor_score(plaintext), key_size, plaintext[:80]))
            if candidates:
                score, key_size, preview = max(candidates)
                if score >= 0.68:
                    text = preview.decode("utf-8", errors="replace")
                    findings.append(Finding("xor", "medium", "Repeating-key XOR candidate", f"{encoding} ciphertext favors key length {key_size}; scored plaintext preview: {text!r}.", [f"{parameter.path}:{parameter.line}"]))
    return findings


def capabilities() -> dict[str, bool]:
    return {"python": True, "sage": shutil.which("sage") is not None, "z3": shutil.which("z3") is not None}


def analyze(parameters: list[Parameter], trial_factor_bound: int = 1_000_000) -> list[Finding]:
    return analyze_parameters(parameters) + analyze_factorization(parameters, trial_factor_bound) + analyze_rsa_consistency(parameters) + analyze_encodings(parameters) + analyze_xor(parameters) + analyze_repeating_xor(parameters)


def finding_dicts(findings: list[Finding]) -> list[dict[str, object]]:
    return [{"category": item.category, "severity": item.severity, "title": item.title, "detail": item.detail, "evidence": item.evidence} for item in findings]
