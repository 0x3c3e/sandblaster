from typing import BinaryIO, List

from construct import Bytes, Int16ul, Struct, this

VarOffset = Int16ul

GlobalVarEntry = Struct("strlen" / Int16ul, "name" / Bytes(this.strlen - 1))


class GlobalVarsParser:
    @staticmethod
    def parse(infile: BinaryIO, base_addr: int, count: int, offset: int) -> List[str]:
        global_vars: List[str] = []

        for i in range(count):
            infile.seek(offset + i * 2)
            var_index = VarOffset.parse_stream(infile)

            infile.seek(base_addr + var_index * 8)
            entry = GlobalVarEntry.parse_stream(infile)

            global_vars.append(entry.name.decode("utf-8", errors="replace"))

        return global_vars
