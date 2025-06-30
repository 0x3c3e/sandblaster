import struct
from typing import BinaryIO, List


class GlobalVarsParser:
    @staticmethod
    def parse(infile: BinaryIO, base_addr: int, count: int, offset: int) -> List[str]:
        global_vars = []
        for i in range(count):
            infile.seek(offset + i * 2)
            var_offset = struct.unpack("<H", infile.read(2))[0]
            infile.seek(base_addr + var_offset * 8)
            strlen = struct.unpack("<H", infile.read(2))[0]
            string = infile.read(strlen - 1).decode("utf-8")
            global_vars.append(string)
        return global_vars
