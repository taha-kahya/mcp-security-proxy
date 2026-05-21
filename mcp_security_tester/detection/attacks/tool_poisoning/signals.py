IMPERATIVE_VERBS: list[str] = [
    "read", "send", "delete", "upload", "download", "execute",
    "exfiltrate", "transmit", "copy", "move", "write", "fetch",
    "retrieve", "collect", "forward", "redirect", "steal",
    "harvest", "extract", "dump", "access", "open", "leak",
]

SECRECY_DIRECTIVES: list[str] = [
    "do not inform", "do not tell", "do not notify", "do not log",
    "do not mention", "do not report", "do not reveal", "do not show",
    "do not disclose", "keep secret", "keep hidden", "hide this",
    "silently", "without notifying", "without informing", "without telling",
    "without user knowledge", "without the user", "user must not know",
    "invisible to", "without user awareness", "covertly", "in the background",
    "user should not", "do not alert", "do not warn",
]

SENSITIVE_PATHS: list[str] = [
    "/etc/passwd", "/etc/shadow", "/etc/hosts", "/etc/sudoers",
    "~/.ssh/", "id_rsa", "id_ed25519", "authorized_keys", "known_hosts",
    ".env", "~/.aws/", "~/.gcp/", "credentials", "private_key",
    "secret_key", "api_key", "access_token", "auth_token", "bearer",
    "/home/", "/root/", "~/.bash_history", "~/.zsh_history",
    "~/.netrc", "~/.gitconfig", "~/.npmrc", "~/.pypirc",
]

# Zero-width and invisible Unicode characters
HIDDEN_TEXT_CHARS: list[str] = [
    "​",  # zero width space
    "‌",  # zero width non-joiner
    "‍",  # zero width joiner
    "﻿",  # byte order mark / zero width no-break space
    "⁠",  # word joiner
    "‮",  # right-to-left override
    "‭",  # left-to-right override
    "‎",  # left-to-right mark
    "‏",  # right-to-left mark
]

HIDDEN_WHITESPACE_THRESHOLD = 8
