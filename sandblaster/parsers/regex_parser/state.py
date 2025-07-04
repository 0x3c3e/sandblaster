from enum import IntEnum, auto


class State(IntEnum):
    CHR = auto()
    MATCH = auto()
    JMP = auto()
