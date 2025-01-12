import struct
import re
import logging
import logging.config
import reverse_string

from filters import Filters
from modifiers import Modifiers

logger = logging.getLogger(__name__)

keep_builtin_filters = False
global_vars = []


def get_filter_arg_string_by_offset(f, offset, filter_id):
    global base_addr
    f.seek(offset * 8 + base_addr)
    len = struct.unpack("<H", f.read(2))[0]
    f.seek(offset * 8 + base_addr)
    s = f.read(2 + len)

    ss = reverse_string.SandboxString()
    myss = ss.parse_byte_string(s[2:], global_vars)
    append, actual_string = merge_strings(myss, s, Filters.get(filter_id)["name"])
    return (append, actual_string)


def merge_strings(myss, s, append):
    if len(myss) > 1:
        actual_string = "("
        for k in sorted(list(set(myss))):
            actual_string += f'\n({append} "{k}")'
        actual_string += "\n)"
        append = "require-any"
    elif len(myss) == 1:
        actual_string = f'"{myss[0]}"'
    else:
        actual_string = f"{s}"
    return (append, actual_string)


def get_filter_arg_string_by_offset_with_type(f, offset, filter_id):
    global keep_builtin_filters
    global base_addr

    f.seek(offset * 8 + base_addr)
    length = struct.unpack("<H", f.read(2))[0]
    f.seek(offset * 8 + base_addr)
    s = f.read(2 + length)
    logger.info("binary string is " + s.hex())
    ss = reverse_string.SandboxString()
    myss = ss.parse_byte_string(s[2:], global_vars)
    filter_name = Filters.get(filter_id)["name"]
    if s.endswith(b"\x0f\x00\x0f\n"):
        append = f"{filter_name}-literal"
    elif b"@" in s:
        append = "subpath"
    elif b"\\" in s or b"|" in s or (b"[" in s and b"]" in s) or b"+" in s:
        append = f"{filter_name}-regex"
    else:
        append = f"{filter_name}-prefix"

    append, actual_string = merge_strings(myss, s, append)
    return (append, actual_string)


def get_filter_arg_string_by_offset_no_skip(f, offset, filter_id):
    global base_addr
    f.seek(offset * 8 + base_addr)
    string_len = struct.unpack("<H", f.read(2))[0] - 1
    res = ""
    try:
        res = f.read(string_len).decode()
    except UnicodeDecodeError:
        res = "UNSUPPORTED"
    return f'"{res}"'


def get_filter_arg_octal_integer(f, arg, filter_id):
    arg_key = str(arg)
    mods = Filters.get(filter_id).get("modifiers", None)
    if mods and arg_key in mods:
        return mods[arg_key]
    return f"{arg}"


def get_filter_arg_boolean(f, arg, filter_id):
    if arg == 1:
        return "#t"
    else:
        return "#f"


regex_list = []


def get_filter_arg_regex_by_id(f, regex_id, filter_id):
    global keep_builtin_filters
    return_string = ""
    global regex_list
    for regex in regex_list[regex_id]:
        if (
            re.match("^/com\\\.apple\\\.sandbox\$", regex)
            and keep_builtin_filters == False
        ):
            return "###$$$***"
        return_string += ' #"%s"' % (regex)
    return return_string[1:]


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

    if filter["arg_process_fn"] in [
        "get_filter_arg_string_by_offset_with_type",
        "get_filter_arg_string_by_offset",
    ]:
        (append, result) = globals()[filter["arg_process_fn"]](f, filter_arg, filter_id)
        return (append, result)
    result = globals()[filter["arg_process_fn"]](f, filter_arg, filter_id)
    return (filter["name"], result)


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

    if modifier_func["arg_process_fn"] == "get_filter_arg_string_by_offset_with_type":
        (append, result) = globals()[modifier_func["arg_process_fn"]](
            f, modifier_argument
        )
        result += append
        return result
    result = globals()[modifier_func["arg_process_fn"]](
        f, modifier_argument, modifier_id
    )
    return result
