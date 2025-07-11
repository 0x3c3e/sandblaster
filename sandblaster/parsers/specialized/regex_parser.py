from typing import BinaryIO, List

from construct import Bytes, Int16ul, Struct, this

import sandblaster.parsers.regex_parser.processor as processor

RegexOffset = Int16ul

RegexEntry = Struct("length" / Int16ul, "data" / Bytes(this.length))


class RegexListParser:
    @staticmethod
    def parse(infile: BinaryIO, base_addr: int, count: int, offset: int) -> List[str]:
        if count == 0:
            return []

        infile.seek(offset)
        offsets = [RegexOffset.parse_stream(infile) for _ in range(count)]

        regex_list: List[str] = []
        for off in offsets:
            infile.seek(base_addr + off * 8)
            entry = RegexEntry.parse_stream(infile)
            regex_list.append(processor.analyze(entry.data))

        return regex_list
