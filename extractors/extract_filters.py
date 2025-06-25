import sys
import lief
import json

mapping = {
    0x1: "SB_VALUE_TYPE_BOOL",
    0x2: "SB_VALUE_TYPE_BITFIELD",
    0x3: "SB_VALUE_TYPE_INTEGER",
    0x4: "SB_VALUE_TYPE_STRING",
    0x5: "SB_VALUE_TYPE_PATTERN_LITERAL",
    0x6: "SB_VALUE_TYPE_PATTERN_PREFIX",
    0x7: "SB_VALUE_TYPE_PATTERN_SUBPATH",
    0x8: "SB_VALUE_TYPE_PATTERN_REGEX",
    0x9: "SB_VALUE_TYPE_REGEX",
    0xA: "SB_VALUE_TYPE_NETWORK",
    0xB: "SB_VALUE_TYPE_BITMASK",
}


def get_cstring(target_macho, offset):
    value = ""
    while char := target_macho.get_content_from_virtual_address(
        0x180000000 + offset, 1
    )[0]:
        value += chr(char)
        offset += 1
    return value


def extract_modifiers(target_macho, start_address):
    output = {}
    while True:
        offset = target_macho.get_int_from_virtual_address(start_address, 4)
        if offset == 0:
            break
        name = get_cstring(target_macho, offset)
        func = target_macho.get_int_from_virtual_address(start_address + 0x8, 2)
        start_address += 0x10
        output[func] = name
    return output


def extract_data_between_variables(file_path, output_path):
    output = {}
    fat_binary = lief.MachO.parse(file_path)
    target_macho = fat_binary.take(lief.MachO.Header.CPU_TYPE.ARM64)
    start_address = target_macho.get_symbol("_filter_info").value + 0x20
    end_address = target_macho.get_symbol("_modifier_info").value - 0x20
    for i in range(int((end_address - start_address) / 0x20)):
        mods = None
        offset = target_macho.get_int_from_virtual_address(start_address, 4)
        key = i + 1
        name = get_cstring(target_macho, offset)
        category_offset = target_macho.get_int_from_virtual_address(
            start_address + 0x8, 4
        )
        category = get_cstring(target_macho, category_offset)
        func = target_macho.get_int_from_virtual_address(start_address + 0x10, 1)
        modifiers = target_macho.get_int_from_virtual_address(start_address + 0x18, 4)
        prerequisite = target_macho.get_int_from_virtual_address(
            start_address + 0x14, 1
        )
        if modifiers:
            mods = extract_modifiers(target_macho, modifiers + 0x180000000)
        start_address += 0x20
        output[key] = {
            "name": name,
            "category": category,
            "argument_type": mapping[func],
            "modifiers": mods,
            "prerequisite": prerequisite,
        }
    length = len(output) - 1
    for key in range(1, length):
        new_key = key + length + 0x20
        output[new_key] = {
            "name": output[key]["name"],
            "argument_type": (
                "SB_VALUE_TYPE_INTEGER"
                if "INTEGER" in output[key]["argument_type"]
                else "SB_VALUE_TYPE_PATTERN_REGEX"
            ),
        }
    with open(output_path, "w") as file:
        json.dump(output, file, indent=4, sort_keys=int)


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python extract_filters.py <file_path> <output_path>")
        exit(1)
    file_path = sys.argv[1]
    output_path = sys.argv[2]
    extract_data_between_variables(file_path, output_path)
