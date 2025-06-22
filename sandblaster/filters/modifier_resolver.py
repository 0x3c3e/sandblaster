import struct
import logging
from typing import List, Any, BinaryIO


logger = logging.getLogger(__name__)


class ModifierResolver:
    def __init__(
        self, f: BinaryIO, base_addr: int, regex_list: List[str], global_vars: List[Any], modifiers
    ):
        self.f = f
        self.base_addr = base_addr
        self.regex_list = regex_list
        self.global_vars = global_vars
        self.modifiers = modifiers

    def resolve(self, modifier_id: int, modifier_argument: int) -> str:
        if not self.modifiers.exists(modifier_id):
            logger.warning(f"Modifier ID {modifier_id} not found.")
            return "== NEED TO ADD MODIFIER"
        return self._arg_direct_string(modifier_argument)

    def _arg_direct_string(self, offset: int) -> str:
        addr = offset * 8 + self.base_addr
        self.f.seek(addr)
        strlen = struct.unpack("<H", self.f.read(2))[0] - 1
        return f'"{self.f.read(strlen).decode()}"'
