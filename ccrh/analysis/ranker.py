from collections import Counter

from ccrh.parsers.crypto import Clue

ATTACKS = {
    "rsa": "Inspect RSA parameters for weak primes, leaked CRT values, small exponents, or factorable modulus.",
    "aes": "Inspect mode, IV/nonce reuse, padding, key derivation, and known-plaintext opportunities.",
    "xor": "Test key length, repeating-key structure, known plaintext, and single-byte candidates.",
    "hash": "Identify the exact hash and test encoding, truncation, reuse, and likely password material.",
    "encoding": "Normalize layers of hex/base encodings before attempting cryptanalysis.",
    "number_theory": "Check factorization, gcd relationships, CRT structure, and discrete-log assumptions.",
}


def rank_attacks(clues: list[Clue], parameter_names: list[str] | None = None) -> list[dict[str, object]]:
    counts = Counter(clue.kind for clue in clues)
    names = set(parameter_names or [])
    if {"n", "e"}.issubset(names) or "modulus" in names:
        counts["rsa"] += 2
    if {"ciphertext", "key"}.issubset(names):
        counts["xor"] += 1
    return [{"kind": kind, "score": count, "recommendation": ATTACKS[kind]} for kind, count in counts.most_common()]
