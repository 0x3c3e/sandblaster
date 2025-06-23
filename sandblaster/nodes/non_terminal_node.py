from dataclasses import dataclass
from typing import Optional


@dataclass(slots=True)
class NonTerminalNode:
    filter_id: int
    argument_id: int
    match_offset: int
    unmatch_offset: int
    parent: object
    filter: Optional[str] = None
    argument: Optional[str] = None
    match: Optional[object] = None
    unmatch: Optional[object] = None

    @classmethod
    def from_raw(cls, parent, raw: bytes) -> "NonTerminalNode":
        filter_id = raw[1]
        argument_id = raw[2] | (raw[3] << 8)
        match_offset = raw[4] | (raw[5] << 8)
        unmatch_offset = raw[6] | (raw[7] << 8)
        return cls(filter_id, argument_id, match_offset, unmatch_offset, parent)

    def __eq__(self, other):
        return (
            self.filter_id == other.filter_id
            and self.argument_id == other.argument_id
            and self.match_offset == other.match_offset
            and self.unmatch_offset == other.unmatch_offset
        )

    def __str__(self):
        return f"({self.filter} {self.argument})"

    def convert_filter(
        self, sandbox_data, filter_resolver, modifier_resolver, terminal_resolver
    ):
        self.filter, self.argument = filter_resolver.resolve(
            self.filter_id, self.argument_id
        )
