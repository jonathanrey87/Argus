"""Conservative OWASP MASVS v2.1 mapping helpers."""

from __future__ import annotations

import re
from typing import Any

MASVS_VERSION = "2.1.0"
CONTROL_PATTERN = re.compile(r"\bMASVS-[A-Z]+-\d+\b")
GROUP_KEYWORDS = {
    "MASVS-STORAGE": ("storage", "stored", "logging", "cache", "keychain"),
    "MASVS-CRYPTO": ("crypto", "cipher", "random", "hash", "encryption"),
    "MASVS-AUTH": ("authentication", "authorization", "session", "biometric"),
    "MASVS-NETWORK": (
        "network",
        "cleartext",
        "certificate",
        "tls",
        "transport",
    ),
    "MASVS-PLATFORM": (
        "webview",
        "intent",
        "exported",
        "deep link",
        "clipboard",
        "screenshot",
        "ipc",
    ),
    "MASVS-CODE": ("injection", "deserialization", "memory", "dependency"),
    "MASVS-RESILIENCE": (
        "root",
        "debug",
        "emulator",
        "obfuscat",
        "tamper",
        "hook",
        "binary",
    ),
    "MASVS-PRIVACY": (
        "privacy",
        "tracker",
        "identifier",
        "location",
        "contacts",
    ),
}


def exact_controls(value: Any) -> list[str]:
    """Extract only explicit MASVS control IDs from upstream metadata."""
    return sorted(set(CONTROL_PATTERN.findall(str(value).upper())))


def infer_group(*values: Any) -> list[str]:
    """Infer at most one broad MASVS group without claiming control coverage."""
    text = " ".join(str(value) for value in values).casefold()
    for group, keywords in GROUP_KEYWORDS.items():
        if any(keyword in text for keyword in keywords):
            return [group]
    return []
