import struct
from typing import BinaryIO, List

import sandblaster.parsers.regex as regex


class RegexListParser:
    @staticmethod
    def parse(infile: BinaryIO, base_addr: int, count: int, offset: int) -> List[str]:
        if count == 0:
            return []

        infile.seek(offset)
        offsets = struct.unpack(f"<{count}H", infile.read(2 * count))

        regex_list = []
        for off in offsets:
            infile.seek(base_addr + off * 8)
            length = struct.unpack("<H", infile.read(2))[0]
            data = infile.read(length)
            regex_list.append(regex.analyze(data))

        return regex_list
