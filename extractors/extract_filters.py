import sys
import lief
import json

mapping = {
    1: "get_filter_arg_boolean",
    2: "get_filter_arg_octal_integer",
    3: "get_filter_arg_octal_integer",
    4: "get_filter_arg_string_by_offset_no_skip",
    5: "get_filter_arg_string_by_offset",
    6: "get_filter_arg_string_by_offset",
    7: "get_filter_arg_string_by_offset_with_type",
    8: "get_filter_arg_octal_integer",
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
        func = target_macho.get_int_from_virtual_address(start_address + 0x10, 1)
        modifiers = target_macho.get_int_from_virtual_address(start_address + 0x18, 4)
        if modifiers:
            mods = extract_modifiers(target_macho, modifiers + 0x180000000)
        start_address += 0x20
        output[hex(key)] = {"name": name, "arg_process_fn": mapping[func], "modifiers": mods}
    length = len(output) - 1
    for key in range(1, length):
        new_key = hex(key + length + 0x20)
        output[new_key] = {
            "name": output[hex(key)]["name"],
            "arg_process_fn": "get_filter_arg_regex_by_id" if "string" in output[hex(key)]["arg_process_fn"] else "get_filter_arg_octal_integer",
        }
    with open(output_path, "w") as file:
        json.dump(output, file, indent=4, sort_keys=int)


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(
            "Usage: python extract_profile_data_from_kext.py <file_path> <output_path>"
        )
        exit(1)
    file_path = sys.argv[1]
    output_path = sys.argv[2]
    extract_data_between_variables(file_path, output_path)
