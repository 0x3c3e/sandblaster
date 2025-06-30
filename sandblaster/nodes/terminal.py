from dataclasses import dataclass
from enum import IntEnum


class NodeType(IntEnum):
    ALLOW = 0x00
    DENY = 0x01
    DELEGATE = 0x02
    AUTOBOX = 0x03


@dataclass(slots=True)
class TerminalNode:
    offset: int
    raw: bytes

    @property
    def modifier_flags(self) -> int:
        return self.raw[1] | (self.raw[2] << 8) | (self.raw[3] << 16)

    @property
    def action_inline(self) -> bool:
        return bool(self.modifier_flags & 0x800000)

    @property
    def arg_type(self) -> int:
        return self.raw[4]

    @property
    def arg_id(self) -> int:
        return self.raw[5]

    @property
    def arg_value(self) -> int:
        return self.raw[6] | (self.raw[7] << 8)

    @property
    def type(self) -> int:
        return NodeType(self.raw[1] & 1)

    def __hash__(self):
        return hash(self.offset)
