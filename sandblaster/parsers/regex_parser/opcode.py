from enum import IntEnum


class OpCode(IntEnum):
    CHAR = 0x02
    START = 0x19
    END = 0x29
    ANY = 0x09
    MATCH = 0x05
    JMP_BEHIND = 0x0A
    JMP_AHEAD = 0x2F
    CLASS = 0x0B
