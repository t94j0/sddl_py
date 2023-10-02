from sddl_parser.parser import parse_ace_rights


def test_ace_rights_many():
    test = "CCLCSWLOCRRC"
    parsed = parse_ace_rights().parse(test)
    assert 0x2018D == parsed


def test_ace_rights_num():
    test = "0x125"
    parsed = parse_ace_rights().parse(test)
    assert 0x125 == parsed
