import unicodedata
import re
import base64
from typing import List

def apply_normalizers(text: str, normalizers: List[str]) -> str:
    if not text:
        return text
    result = text
    for norm in normalizers:
        if norm == "nfkc":
            result = unicodedata.normalize("NFKC", result)
        elif norm == "strip_shell_quotes":
            result = result.replace("'", "").replace('"', "")
        elif norm == "collapse_whitespace":
            result = re.sub(r'\s+', ' ', result).strip()
        elif norm == "decode_base64":
            decoded_parts = []
            for word in re.findall(r'[A-Za-z0-9+/]{16,}={0,2}', result):
                try:
                    decoded = base64.b64decode(word).decode('utf-8')
                    decoded_parts.append(decoded)
                except Exception:
                    pass
            if decoded_parts:
                result += " " + " ".join(decoded_parts)
    return result