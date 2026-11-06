import re
import fnmatch
import math
from urllib.parse import urlparse
from preflight.models import Match

def _shannon_entropy(data: str) -> float:
    if not data:
        return 0.0
    entropy = 0.0
    for x in set(data):
        p_x = float(data.count(x)) / len(data)
        entropy -= p_x * math.log2(p_x)
    return entropy

def evaluate_match(match: Match, field_value: str) -> bool:
    if not field_value:
        return False
    if match.kind == "regex":
        try:
            return bool(re.search(match.pattern, field_value))
        except re.error:
            return False
    elif match.kind == "glob":
        return fnmatch.fnmatch(field_value, match.pattern)
    elif match.kind == "entropy":
        if len(field_value) < match.min_length:
            return False
        return _shannon_entropy(field_value) >= match.threshold
    elif match.kind == "domain_allowlist":
        urls = re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', field_value)
        if not urls:
            return False
        for url in urls:
            if not url.startswith("http"):
                url = "http://" + url
            try:
                host = urlparse(url).hostname
                if host and host not in match.allowed_domains:
                    return True
            except Exception:
                return True
        return False
    elif match.kind == "max_size":
        lines = field_value.splitlines()
        return len(lines) > match.max_lines
    return False