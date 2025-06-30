import pytest

from sandblaster.parsers.strings import parse_fsm_string

TEST_CASES = [
    (b"C/aaa\x0f\x00\x0f\n", sorted(["/aaa"]), "Single simple path"),
    (
        b"@/\x0fBbbb\x82\x00\x0f\nBaaa\x0f\x00\x0f\n",
        sorted(["/aaa", "/bbb"]),
        "Two simple paths",
    ),
    (
        b"A/a\x0fA/a\x82\x00\x0f\nAaa\x0f\x00\x0f\n",
        sorted(["/a/a", "/aaa"]),
        "Paths with similar names",
    ),
    (
        b"@/\x0f@a\x8dA/a\x82\x00\x0f\nAaa\x0f\x00\x0f\nDb/a/c\x0f\x00\x0f\n",
        sorted(["/a/a", "/aaa", "/b/a/c"]),
        "Multiple paths with varying depths",
    ),
    (
        b"C/aaa\x0f@/\x80\n\x00\x0f\n",
        sorted(["/aaa", "/aaa/"]),
        "Path with and without trailing slash",
    ),
    (b"Aa/\x82\x00\x0f\nA/a\x0f\x00\x0f\n", sorted(["/a", "a/"]), ""),
    (
        b"@/\x0f\x0b\x00\x00\xff\x0fFtrashes\x0f\n",
        sorted(["/[\\x00-\\xff]trashes"]),
        "",
    ),
    (
        b"@/\x0f\x0b\x00\x00\xff\x0fFtrashes\x0f\x0b\x0009\x0f\n",
        ["/[\\x00-\\xff]trashes[0-9]"],
        "",
    ),
]


@pytest.mark.parametrize("input_bytes,expected,test_description", TEST_CASES)
def test_parse_fsm_string(input_bytes, expected, test_description):
    """Test parse_fsm_string with various input patterns."""
    assert parse_fsm_string(input_bytes, []) == expected
