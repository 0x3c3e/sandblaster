from enum import IntEnum, auto


class State(IntEnum):
    CALLBACK = auto()
    ASSERT = auto()
    MATCH_BYTE = auto()
    MATCH_SEQ = auto()
    LITERAL = auto()
    RESTORE_POS = auto()
    PUSH_STATE = auto()
    POP_STATE = auto()
    SUCCESS = auto()
    MATCH = auto()
    JNE = auto()
    RANGE_INCLUSIVE = auto()
    RANGE_EXCLUSIVE = auto()
