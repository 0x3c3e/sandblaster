from dataclasses import dataclass
from typing import Optional
from functools import cached_property


@dataclass
class NonTerminalNode:
    offset: int
    raw: bytes

    # Resolved fields (set later via convert_filter)
    filter: Optional[str] = None
    argument: Optional[str] = None
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

    def convert_filter(
        self, sandbox_data, filter_resolver, modifier_resolver, terminal_resolver
    ):
        self.filter, self.argument = filter_resolver.resolve(
            self.filter_id, self.argument_id
        )

    def __hash__(self):
        return hash(self.offset)

    def __str__(self):
        return f"({self.filter} {self.argument})"
