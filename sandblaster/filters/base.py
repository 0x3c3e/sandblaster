from enum import Enum, auto


class FilterType(Enum):
    SB_VALUE_TYPE_BOOL = auto()
    SB_VALUE_TYPE_BITFIELD = auto()
    SB_VALUE_TYPE_INTEGER = auto()
    SB_VALUE_TYPE_STRING = auto()
    SB_VALUE_TYPE_PATTERN_LITERAL = auto()
    SB_VALUE_TYPE_PATTERN_PREFIX = auto()
    SB_VALUE_TYPE_PATTERN_SUBPATH = auto()
    SB_VALUE_TYPE_PATTERN_REGEX = auto()
    SB_VALUE_TYPE_REGEX = auto()
    SB_VALUE_TYPE_NETWORK = auto()
    SB_VALUE_TYPE_BITMASK = auto()
