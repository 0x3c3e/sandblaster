import struct
import re
import logging
from enum import Enum, auto
from filters import Filters
from modifiers import Modifiers
from parse_strings import parse_fsm_string

logger = logging.getLogger(__name__)

keep_builtin_filters = False
global_vars = []


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


def get_filter_arg_bool(arg):
    if arg == 1:
        return "#t"
    return "#f"


def get_filter_arg_string(f, offset, filter_id):
    global base_addr
    f.seek(offset * 8 + base_addr)
    string_len = struct.unpack("<H", f.read(2))[0] - 1
    res = f.read(string_len).decode()
    return f'"{res}"'


def get_filter_arg_string_by_offset(f, offset, filter_id):
    global base_addr
    f.seek(offset * 8 + base_addr)
    len = struct.unpack("<H", f.read(2))[0]
    f.seek(offset * 8 + base_addr)
    s = f.read(2 + len)

    actual_string = parse_fsm_string(s[2:], global_vars)
    return ("", actual_string)


def get_filter_arg_integer(f, arg, filter_id):
    arg_key = str(arg)
    mods = Filters.get(filter_id).get("modifiers", None)
    if mods and arg_key in mods:
        return mods[arg_key]
    return f"{arg}"


regex_list = []


def get_filter_arg_regex_by_id(f, regex_id, filter_id):
    global keep_builtin_filters
    return_string = ""
    global regex_list
    print(regex_list, regex_id)
    for regex in regex_list[regex_id]:
        if (
            re.match("^/com\\\.apple\\\.sandbox\$", regex)
            and keep_builtin_filters == False
        ):
            return "###$$$***"
        return_string += ' #"%s"' % (regex)
    return return_string[1:]


def sb_filter_is_case_sensitive(filter_id):
    return (filter_id & 0xFE) == 4


def convert_filter_callback(
    f, sandbox_data, keep_builtin_filters_arg, filter_id, filter_arg
):
    global regex_list
    global keep_builtin_filters
    global global_vars
    global base_addr
    keep_builtin_filters = keep_builtin_filters_arg

    global_vars = sandbox_data.global_vars
    regex_list = sandbox_data.regex_list
    base_addr = sandbox_data.base_addr

    if not Filters.exists(filter_id):
        logger.warn("filter_id {} not in keys".format(filter_id))
        return (None, None)
    filter = Filters.get(filter_id)

    (append, result) = filter["name"], None
    match FilterType[filter["argument_type"]]:
        case FilterType.SB_VALUE_TYPE_BOOL:
            result = get_filter_arg_bool(filter_arg)
        case FilterType.SB_VALUE_TYPE_BITFIELD:
            pass
        case FilterType.SB_VALUE_TYPE_INTEGER:
            result = get_filter_arg_integer(f, filter_arg, filter_id)
        case FilterType.SB_VALUE_TYPE_STRING:
            result = get_filter_arg_string(f, filter_arg, filter_id)
        case FilterType.SB_VALUE_TYPE_PATTERN_LITERAL | FilterType.SB_VALUE_TYPE_PATTERN_PREFIX | FilterType.SB_VALUE_TYPE_PATTERN_SUBPATH:
            result = get_filter_arg_string_by_offset(f, filter_arg, filter_id)
        case FilterType.SB_VALUE_TYPE_PATTERN_REGEX:
            result = get_filter_arg_regex_by_id(f, filter_arg, filter_id)
    print(result)
    return (append, result)


def convert_modifier_callback(f, sandbox_data, modifier_id, modifier_argument):
    global regex_list
    global keep_builtin_filters
    global global_vars
    global base_addr

    global_vars = sandbox_data.global_vars
    regex_list = sandbox_data.regex_list
    base_addr = sandbox_data.base_addr

    if not Modifiers.exists(modifier_id):
        return "== NEED TO ADD MODIFIER"
    modifier_func = Modifiers.get(modifier_id)
    result = get_filter_arg_string(f, modifier_argument, modifier_id)
    return result
