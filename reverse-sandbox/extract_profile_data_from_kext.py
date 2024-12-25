import sys
import lief


def extract_data_between_variables(file_path, output_path):
    fat_binary = lief.MachO.parse(file_path)
    target_macho = fat_binary.take(lief.MachO.Header.CPU_TYPE.ARM64)
    start_address = target_macho.get_symbol("_platform_profile_data").value
    end_address = target_macho.get_symbol("_collection_data").value

    data = target_macho.get_content_from_virtual_address(
        start_address, end_address - start_address
    )
    with open(output_path, "wb") as out_file:
        out_file.write(data)
    print(f"Saved to {output_path}")


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python script.py <file_path> <output_path> [<target_arch>]")
        exit(1)
    file_path = sys.argv[1]
    output_path = sys.argv[2]
    extract_data_between_variables(file_path, output_path)
