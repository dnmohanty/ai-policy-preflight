import re
from typing import List, Literal, Union
from pydantic import BaseModel, Field, field_validator, model_validator

Decision = Literal["allow", "warn", "deny"]
ActionType = Literal["shell", "write", "prompt"]
Normalizer = Literal["nfkc", "strip_shell_quotes", "collapse_whitespace", "decode_base64"]

class RegexMatch(BaseModel):
    kind: Literal["regex"]
    field: Literal["command", "content", "text", "path", "body"]
    pattern: str

    @field_validator('pattern')
    @classmethod
    def validate_regex(cls, v):
        try:
            re.compile(v)
        except re.error as e:
            raise ValueError(f"Invalid regex: {e}")
        return v

class GlobMatch(BaseModel):
    kind: Literal["glob"]
    field: Literal["path"]
    pattern: str

class EntropyMatch(BaseModel):
    kind: Literal["entropy"]
    field: Literal["command", "content", "text", "body"]
    threshold: float
    min_length: int

class DomainAllowlistMatch(BaseModel):
    kind: Literal["domain_allowlist"]
    field: Literal["command", "body"]
    allowed_domains: List[str]

class MaxSizeMatch(BaseModel):
    kind: Literal["max_size"]
    field: Literal["content", "body"]
    max_lines: int

Match = Union[RegexMatch, GlobMatch, EntropyMatch, DomainAllowlistMatch, MaxSizeMatch]

class Rule(BaseModel):
    id: str
    applies_to: List[ActionType]
    match: Match
    decision: Decision
    message: str

    @model_validator(mode='after')
    def validate_fields(self) -> 'Rule':
        valid_fields = {
            "shell": {"command", "body"},
            "write": {"content", "path", "body"},
            "prompt": {"text", "body"}
        }
        for action in self.applies_to:
            if self.match.field not in valid_fields.get(action, set()):
                raise ValueError(f"Field '{self.match.field}' is not valid for action type '{action}'")
        return self

class Policy(BaseModel):
    version: int = 1
    default_decision: Decision = "allow"
    normalizers: List[Normalizer] = Field(default_factory=list)
    rules: List[Rule] = Field(default_factory=list)