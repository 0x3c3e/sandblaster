from dataclasses import dataclass
from typing import Optional


@dataclass(slots=True)
class NonTerminalNode:
    offset: int
    raw: bytes

    match: Optional[object] = None
    unmatch: Optional[object] = None

    @property
    def filter_id(self) -> int:
        return self.raw[1]

    @property
    def argument_id(self) -> int:
        return self.raw[2] | (self.raw[3] << 8)

    @property
    def match_offset(self) -> int:
        return self.raw[4] | (self.raw[5] << 8)

    @property
    def unmatch_offset(self) -> int:
        return self.raw[6] | (self.raw[7] << 8)

    def __hash__(self):
        return hash(self.offset)
