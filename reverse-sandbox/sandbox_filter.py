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
    actual_string = ""
    for sss in myss:
        actual_string = actual_string + sss + " "
    actual_string = actual_string[:-1]
    logger.info("actual string is " + actual_string)
    return myss


def get_filter_arg_string_by_offset_with_type(f, offset, filter_id):
    global keep_builtin_filters
    global base_addr

    f.seek(offset * 8 + base_addr)
    len = struct.unpack("<H", f.read(2))[0]
    f.seek(offset * 8 + base_addr)
    s = f.read(2 + len)
    logger.info("binary string is " + s.hex())
    ss = reverse_string.SandboxString()
    myss = ss.parse_byte_string(s[2:], global_vars)
    append = "literal"
    actual_string = ""
    for sss in myss:
        actual_string = actual_string + sss + " "
    actual_string = actual_string[:-1]
    logger.info("actual string is " + actual_string)
    return (append, myss)


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
    return "#o%04o" % arg


def get_filter_arg_boolean(f, arg, filter_id):
    if arg == 1:
        return "#t"
    else:
        return "#f"


regex_list = []


def get_filter_arg_regex_by_id(f, regex_id, filter_id):
    """Get regular expression by index."""
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

    if not filter["arg_process_fn"]:
        logger.warn("no function for filter {}".format(filter_id))
        return (None, None)
    if filter["arg_process_fn"] == "get_filter_arg_string_by_offset_with_type":
        (append, result) = globals()[filter["arg_process_fn"]](f, filter_arg, filter_id)
        if filter_id == 0x01 and append == "path":
            append = "subpath"
        if result == None and filter["name"] != "debug-mode":
            logger.warn(
                "result of calling string offset for filter {} is none".format(
                    filter_id
                )
            )
            return (None, None)
        return (filter["name"] + ("-" if len(filter["name"]) else "") + append, result)
    result = globals()[filter["arg_process_fn"]](f, filter_arg, filter_id)
    if result == None and filter["name"] != "debug-mode":
        logger.warn(
            "result of calling arg_process_fn for filter {} is none".format(filter_id)
        )
        return (None, None)
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
