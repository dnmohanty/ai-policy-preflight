from typing import List, Literal, Union
from pydantic import BaseModel, Field

Decision = Literal["allow", "warn", "deny"]
ActionType = Literal["shell", "write", "prompt"]
Normalizer = Literal["nfkc", "strip_shell_quotes", "collapse_whitespace", "decode_base64"]

class RegexMatch(BaseModel):
    kind: Literal["regex"]
    field: Literal["command", "content", "text", "path"]
    pattern: str

class GlobMatch(BaseModel):
    kind: Literal["glob"]
    field: Literal["path"]
    pattern: str

class EntropyMatch(BaseModel):
    kind: Literal["entropy"]
    field: Literal["command", "content", "text"]
    threshold: float
    min_length: int

class DomainAllowlistMatch(BaseModel):
    kind: Literal["domain_allowlist"]
    field: Literal["command"]
    allowed_domains: List[str]

class MaxSizeMatch(BaseModel):
    kind: Literal["max_size"]
    field: Literal["content"]
    max_lines: int

Match = Union[RegexMatch, GlobMatch, EntropyMatch, DomainAllowlistMatch, MaxSizeMatch]

class Rule(BaseModel):
    id: str
    applies_to: List[ActionType]
    match: Match
    decision: Decision
    message: str

class Policy(BaseModel):
    version: int = 1
    default_decision: Decision = "allow"
    normalizers: List[Normalizer] = Field(default_factory=list)
    rules: List[Rule] = Field(default_factory=list)