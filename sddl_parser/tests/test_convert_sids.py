from sddl_parser import api


def test_convert_sid_owner():
    test = "O:S-1-20-20-20G:SYD:"
    sidmap = {"S-1-20-20-20": "DOMAIN\\user"}
    parsed = api.parse_sddl(test, sidmap=sidmap)

    assert parsed.owner == "DOMAIN\\user"


def test_convert_sid_group():
    test = "O:SYG:S-1-20-20-20D:"
    sidmap = {"S-1-20-20-20": "DOMAIN\\user"}
    parsed = api.parse_sddl(test, sidmap=sidmap)

    assert parsed.group == "DOMAIN\\user"


def test_convert_sid_aces():
    test = "O:SYG:SYD:(A;ID;FA;;;S-1-20-20-20)"
    sidmap = {"S-1-20-20-20": "DOMAIN\\user"}
    parsed = api.parse_sddl(test, sidmap=sidmap)

    assert parsed.dacl is not None
    assert parsed.dacl.aces[0].sid == "DOMAIN\\user"
