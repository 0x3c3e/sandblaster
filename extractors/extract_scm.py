import sys
import lief
import pathlib


def get_cstring(target_macho, offset):
    value = ""
    while char := target_macho.get_content_from_virtual_address(offset, 1)[0]:
        value += chr(char)
        offset += 1
    return value


def extract_data_between_variables(file_path, symbol, output_path):
    fat_binary = lief.MachO.parse(file_path)
    target_macho = fat_binary.take(lief.MachO.Header.CPU_TYPE.ARM64)
    start_address = target_macho.get_symbol(symbol).value

    data = get_cstring(target_macho, start_address)
    with open(output_path, "w") as out_file:
        out_file.write(data)
    print(f"Saved to {output_path}")


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python extract_scm.py <libsandbox_path> <output_dir>")
        exit(1)
    file_path = sys.argv[1]
    output_path = sys.argv[2]
    path = pathlib.Path(output_path)
    for p in ["init", "sbpl", "sbpl1", "sbpl2", "sbpl3"]:
        extract_data_between_variables(file_path, f"_{p}_scm", path / f"{p}.scm")
