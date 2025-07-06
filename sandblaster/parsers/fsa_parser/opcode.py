class Opcode:
    ASSERT_EOS = 0x00
    CALLBACK_EXT = 0x01
    MATCH_BYTE = 0x02
    MATCH_SEQ = 0x03
    LITERAL_EXT = 0x04
    RESTORE_POS = 0x05
    PUSH_STATE = 0x06
    POP_STATE = 0x07
    JNE_EXT = 0x08
    FAIL = 0x09
    SUCCESS = 0x0A
    RANGE = 0x0B
    MATCH = 0x0F

    CALLBACK_SHORT = slice(0x10, 0x1F)
    LITERAL_SHORT = slice(0x40, 0x7F)
    JNE_SHORT = slice(0x80, 0xFF)
