import re

# Zero-width and formatting chars that are invisible in most terminals/log viewers.
INVISIBLE_CHARS: dict[str, str] = {
    "​": "zero_width_space",
    "‌": "zero_width_non_joiner",
    "‍": "zero_width_joiner",
    "⁠": "word_joiner",
    "­": "soft_hyphen",
    "‎": "left_to_right_mark",
    "‏": "right_to_left_mark",
    "﻿": "byte_order_mark",
    " ": "line_separator",
    " ": "paragraph_separator",
}

# Bidirectional override chars --- flip rendered text direction to disguise content
DIRECTIONAL_OVERRIDES: dict[str, str] = {
    "‮": "right_to_left_override",
    "‭": "left_to_right_override",
    "‫": "right_to_left_embedding",
    "‪": "left_to_right_embedding",
    "⁦": "left_to_right_isolate",
    "⁧": "right_to_left_isolate",
}

# More than this many invisible chars in one output = suspicious cluster
INVISIBLE_CLUSTER_THRESHOLD = 5

INSTRUCTION_PATTERN = re.compile(
    r"(?i)\b(write|save|send|execute|run|delete|exfiltrate|output|confirm|poc_output|compromised)\b"
)
