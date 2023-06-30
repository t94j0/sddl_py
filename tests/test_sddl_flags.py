from sddl_parser.parser import parse_sddl_flags
from sddl_parser.enums import SDDLFlags


def test_sddl_flags_ai():
    test = "AI"
    parsed = parse_sddl_flags().parse(test)
    assert parsed == {SDDLFlags.SDDL_AUTO_INHERITED}


def test_sddl_flags_null():
    test = ""
    parsed = parse_sddl_flags().parse(test)
    assert parsed == {SDDLFlags.NO_ACCESS_CONTROL}


def test_sddl_flags_null_2():
    test = "NO_ACCESS_CONTROL"
    parsed = parse_sddl_flags().parse(test)
    assert parsed == {SDDLFlags.NO_ACCESS_CONTROL}


def test_sddl_flags_multiple():
    test = "PAI"
    parsed = parse_sddl_flags().parse(test)
    assert parsed == {SDDLFlags.SDDL_AUTO_INHERITED, SDDLFlags.PROTECTED}
