from dataclasses import dataclass, field
from enum import IntEnum
from functools import cached_property


class NodeType(IntEnum):
    ALLOW = 0x00
    DENY = 0x01
    DELEGATE = 0x02
    AUTOBOX = 0x03


@dataclass
class TerminalNode:
    offset: int
    raw: bytes

    @classmethod
    def from_raw(cls, offset: int, raw: bytes) -> "TerminalNode":
        return cls(offset=offset, raw=raw)

    @cached_property
    def modifier_flags(self) -> int:
        return self.raw[1] | (self.raw[2] << 8) | (self.raw[3] << 16)

    @cached_property
    def action_inline(self) -> bool:
        return bool(self.modifier_flags & 0x800000)

    @cached_property
    def arg_type(self) -> int:
        return self.raw[4]

    @cached_property
    def arg_id(self) -> int:
        return self.raw[5]

    @cached_property
    def arg_value(self) -> int:
        return self.raw[6] | (self.raw[7] << 8)

    @cached_property
    def type(self) -> int:
        return NodeType(self.raw[1] & 1)

    def __hash__(self):
        return hash(self.offset)
