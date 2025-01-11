import sys
import lief


def extract_sandbox_operations(binary):
    extracted_strings = []

    for section in binary.sections:
        if section.type == lief.MachO.Section.TYPE.CSTRING_LITERALS:
            strings_bytes = section.content.tobytes()
            strings = strings_bytes.decode("utf-8", errors="ignore")
            extracted_strings.extend(strings.split("\x00"))

    operations = []
    capture = False

    for string in extracted_strings:
        if string == "default":
            capture = True
        if capture:
            operations.append(string)
        if string == "xpc-message-send":
            capture = False

    return operations


def main(input_file, output_file):
    binary = lief.parse(input_file)
    operations = extract_sandbox_operations(binary)

    with open(output_file, "w") as f:
        for operation in operations:
            f.write(operation + "\n")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(
            "Usage: python extract_sandbox_operations.py <path_to_macho_binary> <output_file>"
        )
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = sys.argv[2]
    main(input_file, output_file)
