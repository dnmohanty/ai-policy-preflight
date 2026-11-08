import re
import fnmatch
import math
from preflight.models import Match

TOKEN = re.compile(r"[A-Za-z0-9+=_\-]+")
TOOLS = re.compile(r"\b(?:curl|wget|nc|ncat|scp|rsync|ssh|sftp|ftp|telnet)\b|\bgit\s+(?:clone|fetch|pull|push)\b")
TLDS = "com|net|org|io|dev|ai|co|xyz|ru|cn|info|biz|app|me|tk|top|cc|in|us|uk|de|site|online|cloud|link"
HOST = re.compile(r"(?:[a-z][a-z0-9+.\-]*://)?(?:[\w.\-]+@)?((?:[a-z0-9\-]+\.)+(?:{})|(?:\d{{1,3}}\.){{3}}\d{{1,3}})(?=$|[:/\s?#])".format(TLDS), re.IGNORECASE)
SRI = re.compile(r"\bsha(?:256|384|512)-[A-Za-z0-9+/=]+")

def _shannon_entropy(data: str) -> float:
    if not data:
        return 0.0
    entropy = 0.0
    for x in set(data):
        p_x = float(data.count(x)) / len(data)
        entropy -= p_x * math.log2(p_x)
    return entropy

def glob_match(pattern: str, path: str) -> bool:
    pat = pattern.lower()
    parts = [s for s in path.replace("\\", "/").lower().split("/") if s not in ("", ".", "..")]
    for i in range(len(parts)):
        segment = "/".join(parts[i:])
        if fnmatch.fnmatchcase(segment, pat) or segment.startswith(pat):
            return True
    return False

def entropy_hit(text: str, threshold: float, min_len: int) -> bool:
    text = SRI.sub(" ", text)  # drop whole integrity hashes first (they contain "/")
    for t in TOKEN.findall(text):
        if len(t) >= min_len and _shannon_entropy(t) >= threshold:
            return True
    return False

def hosts(cmd: str) -> list:
    if not TOOLS.search(cmd):
        return []
    res = []
    for tok in cmd.split():
        if not tok.startswith("-"):
            m = HOST.match(tok)
            if m:
                res.append(m.group(1).lower())
    return res

def blocked(cmd: str, allowed: list) -> list:
    return [h for h in hosts(cmd) if not any(h == d or h.endswith("." + d) for d in allowed)]

def evaluate_match(match: Match, field_value: str) -> bool:
    if not field_value:
        return False
    if match.kind == "regex":
        return bool(re.search(match.pattern, field_value))
    elif match.kind == "glob":
        return glob_match(match.pattern, field_value)
    elif match.kind == "entropy":
        return entropy_hit(field_value, match.threshold, match.min_length)
    elif match.kind == "domain_allowlist":
        return bool(blocked(field_value, match.allowed_domains))
    elif match.kind == "max_size":
        lines = field_value.splitlines()
        return len(lines) > match.max_lines
    return False