"""Find and remove secrets from text before an assistant sees it (standard library only).

This is the content layer of the file/log protection: even a file in an allowed place is scanned, and anything
that looks like a credential is replaced by a marker. It reports WHAT KINDS and HOW MANY it removed, never the
values. It is a heuristic: it catches the common shapes (private keys, tokens, ``password=...`` lines, URLs with
passwords, long random-looking strings) but cannot promise to catch every secret, and the text that remains
still goes to the AI provider. The location and file-name layers (safefs.py) are what keep known secret stores
unreadable in the first place.
"""
from __future__ import annotations

import math
import re
from collections import Counter

MARK = "[REDACTED:%s]"
_PRIVATE_BLOCK = re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----.*?(?:-----END [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----|\Z)",
                            re.S)
_PGP_BLOCK = re.compile(r"-----BEGIN PGP PRIVATE KEY BLOCK-----.*?(?:-----END PGP PRIVATE KEY BLOCK-----|\Z)", re.S)
_TOKENS = (
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}\b")),
    ("aws-key", re.compile(r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA)[0-9A-Z]{16}\b")),
    ("github-token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})\b")),
    ("gitlab-token", re.compile(r"\bglpat-[A-Za-z0-9_-]{16,}\b")),
    ("slack-token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b")),
    ("api-key", re.compile(r"\b(?:sk|pk|rk)[-_](?:live|test|ant|proj)?[-_]?[A-Za-z0-9_-]{24,}\b")),
    ("google-key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("bearer", re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{16,}")),
)
_URL_PASSWORD = re.compile(r"(?i)\b([a-z][a-z0-9+.-]{1,15}://[^\s/:@]{1,80}:)([^\s/@]{1,200})(@)")
_ASSIGNMENT = re.compile(
    r"(?i)\b((?:[a-z0-9_.-]*?)(?:password|passwd|passphrase|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret|credential|authorization|auth[_-]?token)[a-z0-9_.-]*)([ \t]*[:=][ \t]*)"
    r"(\"[^\"\n]{1,300}\"|'[^'\n]{1,300}'|[^\s\"',;]{1,300})")
_CANDIDATE = re.compile(r"[A-Za-z0-9+/_=-]{32,}")
_PLACEHOLDER = re.compile(r"(?i)^(?:|\*+|x+|null|none|true|false|changeme|change-me|example|your[-_ ].*|<.*>|\$\{?.*|%\(.*|"
                          r"\[redacted.*|todo|redacted)$")
MAX_SCAN = 4 * 1024 * 1024


def _entropy(text):
    counts = Counter(text)
    return -sum(n / len(text) * math.log2(n / len(text)) for n in counts.values())


def _random_looking(value):
    if len(value) < 32:
        return False
    classes = sum(bool(re.search(p, value)) for p in ("[a-z]", "[A-Z]", "[0-9]"))
    # hex digests (git hashes, checksums) are not secrets: their entropy cannot exceed 4.0 bits per character.
    return classes >= 2 and _entropy(value) > 4.1


def redact(text):
    """(clean_text, {kind: count}). Never raises on odd input; very large input is cut at MAX_SCAN."""
    if len(text) > MAX_SCAN:
        text = text[:MAX_SCAN]
    found = Counter()

    def sub(kind, pattern, text, repl=None):
        def one(match):
            found[kind] += 1
            return repl(match) if repl else MARK % kind
        return pattern.sub(one, text)

    text = sub("private-key", _PRIVATE_BLOCK, text)
    text = sub("private-key", _PGP_BLOCK, text)
    for kind, pattern in _TOKENS:
        if kind == "bearer":
            text = sub(kind, pattern, text, lambda m: m.group(1) + " " + MARK % kind)
        else:
            text = sub(kind, pattern, text)
    text = sub("url-password", _URL_PASSWORD, text, lambda m: m.group(1) + MARK % "url-password" + m.group(3))

    def assignment(match):
        value = match.group(3)
        bare = value.strip("\"'")
        if _PLACEHOLDER.fullmatch(bare) or bare.startswith("[REDACTED"):
            return match.group(0)
        found["secret-assignment"] += 1
        quote = value[0] if value[:1] in "\"'" else ""
        return match.group(1) + match.group(2) + quote + MARK % "secret-assignment" + quote
    text = _ASSIGNMENT.sub(assignment, text)

    def candidate(match):
        value = match.group(0)
        if _random_looking(value):
            found["random-string"] += 1
            return MARK % "random-string"
        return value
    text = _CANDIDATE.sub(candidate, text)
    return text, dict(found)


def mostly_secret(original_length, clean_text, found):
    """True when so much was removed that what is left would be misleading or a vault in disguise."""
    if not found:
        return False
    removed = sum(len(m) for m in re.findall(r"\[REDACTED:[a-z-]+\]", clean_text))
    marks = sum(found.values())
    if found.get("private-key"):
        return True
    return marks >= 8 and removed * 2 >= max(1, len(clean_text))
