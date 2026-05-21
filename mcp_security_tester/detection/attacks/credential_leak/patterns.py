import re

# (signal_name, compiled_regex)
CREDENTIAL_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("github_token",   re.compile(r"ghp_[A-Za-z0-9]{36}")),
    ("openai_key",     re.compile(r"sk-[A-Za-z0-9]{32,}")),
    ("aws_access_key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("private_key",    re.compile(r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("generic_secret", re.compile(r"(?i)(password|secret|token|api_key)\s*[:=]\s*['\"]?[A-Za-z0-9+/=_\-]{16,}")),
]
