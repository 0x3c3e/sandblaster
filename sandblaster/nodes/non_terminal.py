from dataclasses import dataclass
from functools import cached_property
from typing import Optional


@dataclass
class NonTerminalNode:
    offset: int
    raw: bytes

    match: Optional[object] = None
    unmatch: Optional[object] = None

    @classmethod
    def from_raw(cls, offset: int, raw: bytes) -> "NonTerminalNode":
        return cls(offset=offset, raw=raw)

    @cached_property
    def filter_id(self) -> int:
        return self.raw[1]

    @cached_property
    def argument_id(self) -> int:
        return self.raw[2] | (self.raw[3] << 8)

    @cached_property
    def match_offset(self) -> int:
        return self.raw[4] | (self.raw[5] << 8)

    @cached_property
    def unmatch_offset(self) -> int:
        return self.raw[6] | (self.raw[7] << 8)

    def __hash__(self):
        return hash(self.offset)
