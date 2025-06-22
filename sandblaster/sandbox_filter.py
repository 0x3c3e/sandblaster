import struct
import logging
from enum import Enum, auto
from dataclasses import dataclass
from typing import List, Any
from filters import Filters
from modifiers import Modifiers
from parsers.strings import parse_fsm_string

logger = logging.getLogger(__name__)


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


@dataclass
class FilterContext:
    base_addr: int
    regex_list: List[str]
    global_vars: List[Any]


def get_filter_arg_bool(arg):
    return "#t" if arg == 1 else "#f"


def get_filter_arg_string(f, offset, filter_id, ctx: FilterContext):
    f.seek(offset * 8 + ctx.base_addr)
    string_len = struct.unpack("<H", f.read(2))[0] - 1
    res = f.read(string_len).decode()
    return f'"{res}"'


def get_filter_arg_string_by_offset(f, offset, filter_id, ctx: FilterContext):
    f.seek(offset * 8 + ctx.base_addr)
    length = struct.unpack("<H", f.read(2))[0]
    f.seek(offset * 8 + ctx.base_addr)
    s = f.read(2 + length)
    actual_string = parse_fsm_string(s[2:], ctx.global_vars)
    return ("", actual_string)


def get_filter_arg_integer(f, arg, filter_id):
    arg_key = str(arg)
    mods = Filters.get(filter_id).get("modifiers", None)
    if mods and arg_key in mods:
        return mods[arg_key]
    return f"{arg}"


def get_filter_arg_regex_by_id(f, regex_id, filter_id, ctx: FilterContext):
    return f'#"{ctx.regex_list[regex_id]}"'


def sb_filter_is_case_sensitive(filter_id):
    return (filter_id & 0xFE) == 4


def convert_filter_callback(f, sandbox_data, filter_id, filter_arg):
    ctx = FilterContext(
        base_addr=sandbox_data.base_addr,
        regex_list=sandbox_data.payload.regex_list,
        global_vars=sandbox_data.payload.global_vars,
    )

    if not Filters.exists(filter_id):
        logger.warn("filter_id {} not in keys".format(filter_id))
        return (None, None)

    filter = Filters.get(filter_id)
    append = filter["name"]
    result = None

    match FilterType[filter["argument_type"]]:
        case FilterType.SB_VALUE_TYPE_BOOL:
            result = get_filter_arg_bool(filter_arg)
        case FilterType.SB_VALUE_TYPE_INTEGER:
            result = get_filter_arg_integer(f, filter_arg, filter_id)
        case FilterType.SB_VALUE_TYPE_STRING:
            result = get_filter_arg_string(f, filter_arg, filter_id, ctx)
        case (
            FilterType.SB_VALUE_TYPE_PATTERN_LITERAL
            | FilterType.SB_VALUE_TYPE_PATTERN_PREFIX
            | FilterType.SB_VALUE_TYPE_PATTERN_SUBPATH
        ):
            result = get_filter_arg_string_by_offset(f, filter_arg, filter_id, ctx)
        case FilterType.SB_VALUE_TYPE_PATTERN_REGEX:
            result = get_filter_arg_regex_by_id(f, filter_arg, filter_id, ctx)
        case FilterType.SB_VALUE_TYPE_BITFIELD:
            result = filter_arg
        case _:
            raise KeyError

    return (append, result)


def convert_modifier_callback(f, sandbox_data, modifier_id, modifier_argument):
    ctx = FilterContext(
        base_addr=sandbox_data.base_addr,
        regex_list=sandbox_data.payload.regex_list,
        global_vars=sandbox_data.payload.global_vars,
    )

    if not Modifiers.exists(modifier_id):
        return "== NEED TO ADD MODIFIER"

    result = get_filter_arg_string(f, modifier_argument, modifier_id, ctx)
    return result
