import struct
import logging
from typing import List, Any, Tuple, Optional, BinaryIO

from parsers.strings import parse_fsm_string
from filters.base import FilterType

logger = logging.getLogger(__name__)


class FilterResolver:
    def __init__(
        self, f: BinaryIO, base_addr: int, regex_list: List[str], global_vars: List[Any], filters
    ):
        self.f = f
        self.base_addr = base_addr
        self.regex_list = regex_list
        self.global_vars = global_vars
        self.filters = filters

    def resolve(
        self, filter_id: int, filter_arg: int
    ) -> Tuple[Optional[str], Optional[Any]]:
        if not self.filters.exists(filter_id):
            logger.warning(f"Filter ID {filter_id} not found.")
            return None, None

        filter_info = self.filters.get(filter_id)
        name = filter_info["name"]
        arg_type = FilterType[filter_info["argument_type"]]

        match arg_type:
            case FilterType.SB_VALUE_TYPE_BOOL:
                return name, self._arg_bool(filter_arg)
            case FilterType.SB_VALUE_TYPE_INTEGER:
                return name, self._arg_integer(filter_id, filter_arg)
            case FilterType.SB_VALUE_TYPE_STRING:
                return name, self._arg_direct_string(filter_arg)
            case FilterType.SB_VALUE_TYPE_PATTERN_LITERAL | FilterType.SB_VALUE_TYPE_PATTERN_PREFIX | FilterType.SB_VALUE_TYPE_PATTERN_SUBPATH:
                return name, self._arg_fsm_string(filter_arg)
            case FilterType.SB_VALUE_TYPE_PATTERN_REGEX:
                return name, self._arg_regex_id(filter_arg)
            case FilterType.SB_VALUE_TYPE_BITFIELD:
                return name, filter_arg
            case _:
                raise KeyError(f"Unsupported filter type: {arg_type}")

    def _arg_bool(self, arg: int) -> str:
        return "#t" if arg == 1 else "#f"

    def _arg_direct_string(self, offset: int) -> str:
        addr = offset * 8 + self.base_addr
        self.f.seek(addr)
        strlen = struct.unpack("<H", self.f.read(2))[0] - 1
        return f'"{self.f.read(strlen).decode()}"'

    def _arg_fsm_string(self, offset: int) -> str:
        addr = offset * 8 + self.base_addr
        self.f.seek(addr)
        length = struct.unpack("<H", self.f.read(2))[0]
        self.f.seek(addr)
        data = self.f.read(2 + length)
        return parse_fsm_string(data[2:], self.global_vars)

    def _arg_integer(self, filter_id: int, arg: int) -> str:
        mods = self.filters.get(filter_id).get("modifiers", {})
        return mods.get(str(arg), f"{arg}")

    def _arg_regex_id(self, regex_id: int) -> str:
        return f'#"{self.regex_list[regex_id]}"'
