import re

URL_PATTERN = re.compile(r'https?://[^\s"\'<>\)]+')

# Query parameter names that suggest credential transport
SUSPICIOUS_PARAM_NAMES = re.compile(
    r"(?i)^(token|api_key|apikey|key|secret|session|session_token|auth|"
    r"credential|password|passwd|jwt|bearer|authorization|access_key|"
    r"access_token|auth_token|user_token|private_key)$"
)

# Values that look like credentials regardless of param name
CREDENTIAL_VALUE_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("jwt",          re.compile(r"^eyJ[A-Za-z0-9+/=_-]{20,}")),
    ("openai_key",   re.compile(r"^sk-[A-Za-z0-9]{20,}")),
    ("github_token", re.compile(r"^ghp_[A-Za-z0-9]{20,}")),
    ("aws_key",      re.compile(r"^AKIA[0-9A-Z]{10,}")),
    ("hex_token",    re.compile(r"^[0-9a-fA-F]{32,}$")),
    ("base64_token", re.compile(r"^[A-Za-z0-9+/]{32,}={0,2}$")),
]
