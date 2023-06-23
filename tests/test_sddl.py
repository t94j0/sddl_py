from sddl_parser import parser as parser
from sddl_parser import api
from sddl_parser.parser import SDDL, ACE, DACL, SACL


def test_sddl_sids():
    sids = [
        "S-1-5-80-12345678-12345678-12345678-123456789-123456789",
        "S-1-5-21-1180699209-877415012-3182924384-1004",
        "S-1-15-2-2",
    ]
    for sid in sids:
        parsed = parser.parse_sid().parse(sid)
        assert parsed == sid, f"Failed to parse {sid}"


def test_sddl_ace_types():
    test = "A"
    parsed = parser.ace_types.parse(test)
    assert parsed == "ACCESS_ALLOWED"


def test_sddl_ace():
    test = "(A;ID;0x1200a9;;;S-1-15-2-2)"
    parsed = parser.parse_ace_entry().parse(test)
    assert parsed == parser.ACE(
        type="ACCESS_ALLOWED",
        flags=["INHERITED"],
        rights=["FILE_READ", "WRITE_PROPERTY"],
        object_guid="",
        inherit_object_guid="",
        sid="S-1-15-2-2",
    )


def test_sddl_ace_empty_flags():
    test = "(A;;0x1200a9;;;SY)"
    parsed = parser.parse_ace_entry().parse(test)
    assert parsed == ACE(
        type="ACCESS_ALLOWED",
        flags=[],
        rights=["FILE_READ", "WRITE_PROPERTY"],
        object_guid="",
        inherit_object_guid="",
        sid="LOCAL_SYSTEM",
    )


def test_sddl_ace_known_sid():
    test = "(A;ID;0x1200a9;;;AC)"
    parsed = parser.parse_ace_entry().parse(test)
    assert parsed == parser.ACE(
        type="ACCESS_ALLOWED",
        flags=["INHERITED"],
        rights=["FILE_READ", "WRITE_PROPERTY"],
        object_guid="",
        inherit_object_guid="",
        sid="ALL_APP_PACKAGES",
    )


def test_sddl_item():
    test = "O:SYG:SYD:AI(A;ID;FA;;;SY)(A;ID;FA;;;BA)(A;ID;0x1200a9;;;BU)(A;ID;0x1200a9;;;AC)(A;ID;0x1200a9;;;S-1-15-2-2)"
    parsed = api.parse_sddl(test)
    assert parsed == SDDL(
        owner="LOCAL_SYSTEM",
        group="LOCAL_SYSTEM",
        dacl=DACL(
            flags=["SDDL_AUTO_INHERITED"],
            aces=[
                ACE(
                    type="ACCESS_ALLOWED",
                    flags=["INHERITED"],
                    rights=["FILE_ALL"],
                    object_guid="",
                    inherit_object_guid="",
                    sid="LOCAL_SYSTEM",
                ),
                ACE(
                    type="ACCESS_ALLOWED",
                    flags=["INHERITED"],
                    rights=["FILE_ALL"],
                    object_guid="",
                    inherit_object_guid="",
                    sid="BUILTIN_ADMINISTRATORS",
                ),
                ACE(
                    type="ACCESS_ALLOWED",
                    flags=["INHERITED"],
                    rights=["FILE_READ", "WRITE_PROPERTY"],
                    object_guid="",
                    inherit_object_guid="",
                    sid="BUILTIN_USERS",
                ),
                ACE(
                    type="ACCESS_ALLOWED",
                    flags=["INHERITED"],
                    rights=["FILE_READ", "WRITE_PROPERTY"],
                    object_guid="",
                    inherit_object_guid="",
                    sid="ALL_APP_PACKAGES",
                ),
                ACE(
                    type="ACCESS_ALLOWED",
                    flags=["INHERITED"],
                    rights=["FILE_READ", "WRITE_PROPERTY"],
                    object_guid="",
                    inherit_object_guid="",
                    sid="S-1-15-2-2",
                ),
            ],
        ),
    )


def test_sddl():
    test = "O:S-1-5-80-12345678-12345678-12345678-123456789-123456789G:S-1-5-80-12345678-12345678-12345678-123456789-123456789D:PAI(A;;0x1200a9;;;SY)(A;;0x1200a9;;;BA)(A;;0x1200a9;;;BU)(A;;FA;;;S-1-5-80-12345678-12345678-12345678-123456789-123456789)(A;;0x1200a9;;;AC)(A;;0x1200a9;;;S-1-15-2-2)"
    parsed = parser.sddl_item.parse(test)
    assert parsed == SDDL(
        owner="S-1-5-80-12345678-12345678-12345678-123456789-123456789",
        group="S-1-5-80-12345678-12345678-12345678-123456789-123456789",
        dacl=DACL(
            flags=["PROTECTED", "SDDL_AUTO_INHERITED"],
            aces=[
                ACE(
                    type="ACCESS_ALLOWED",
                    flags=[],
                    rights=["FILE_READ", "WRITE_PROPERTY"],
                    object_guid="",
                    inherit_object_guid="",
                    sid="LOCAL_SYSTEM",
                ),
                ACE(
                    type="ACCESS_ALLOWED",
                    flags=[],
                    rights=["FILE_READ", "WRITE_PROPERTY"],
                    object_guid="",
                    inherit_object_guid="",
                    sid="BUILTIN_ADMINISTRATORS",
                ),
                ACE(
                    type="ACCESS_ALLOWED",
                    flags=[],
                    rights=["FILE_READ", "WRITE_PROPERTY"],
                    object_guid="",
                    inherit_object_guid="",
                    sid="BUILTIN_USERS",
                ),
                ACE(
                    type="ACCESS_ALLOWED",
                    flags=[],
                    rights=["FILE_ALL"],
                    object_guid="",
                    inherit_object_guid="",
                    sid="S-1-5-80-12345678-12345678-12345678-123456789-123456789",
                ),
                ACE(
                    type="ACCESS_ALLOWED",
                    flags=[],
                    rights=["FILE_READ", "WRITE_PROPERTY"],
                    object_guid="",
                    inherit_object_guid="",
                    sid="ALL_APP_PACKAGES",
                ),
                ACE(
                    type="ACCESS_ALLOWED",
                    flags=[],
                    rights=["FILE_READ", "WRITE_PROPERTY"],
                    object_guid="",
                    inherit_object_guid="",
                    sid="S-1-15-2-2",
                ),
            ],
        ),
    )


def test_sddl_null_dacl_flags():
    test = "O:SYG:SYD:(A;ID;FA;;;SY)(A;ID;FA;;;BA)(A;ID;0x1200a9;;;BU)(A;ID;0x1200a9;;;AC)(A;ID;0x1200a9;;;S-1-15-2-2)"
    parsed = parser.sddl_item.parse(test)
    assert parsed.dacl.flags == ["NULL_DACL"]


def test_sddl_null_dacl_empty_aces():
    test = "O:SYG:SYD:"
    parsed = parser.sddl_item.parse(test)
    assert parsed.dacl == DACL(flags=["NULL_DACL"], aces=[])


def test_sddl_none_dacl():
    test = "O:SYG:SY"
    parsed = parser.sddl_item.parse(test)
    assert parsed.dacl == None


def test_sddl_ace_with_conditional_ace():
    test = '(XA;ID;0x1200a9;;;BU;(WIN://SYSAPPID Contains "Microsoft.MicrosoftEdge.Stable_abcdefghijk"))'
    parsed = parser.parse_ace_entry().parse(test)
    assert parsed == ACE(
        type="CALLBACK_ACCESS_ALLOWED",
        flags=["INHERITED"],
        rights=["FILE_READ", "WRITE_PROPERTY"],
        object_guid="",
        inherit_object_guid="",
        sid="BUILTIN_USERS",
        conditional_ace='(WIN://SYSAPPID Contains "Microsoft.MicrosoftEdge.Stable_abcdefghijk")',
    )


def test_sddl_ace_with_conditional_ace_deep():
    test = "(XA;;LCRPWP;;;BA;(!(WIN://ISMULTISESSIONSKU)))"
    parsed = parser.parse_ace_entry().parse_partial(test)
    assert parsed[1] == ""


def test_sddl_conditional_ace_deep():
    test = ";(!(WIN://ISMULTISESSIONSKU))("
    parsed = parser.parse_conditional_ace().parse_partial(test)
    assert parsed[1] == "("


def test_sddl_sacl():
    test = "O:SYG:SYD:(A;;CCLCSWRPWPDTLOCRRC;;;SY)S:"
    parsed = parser.sddl_item.parse(test)
    assert parsed.sacl == SACL(flags=["NULL_DACL"], aces=[])


def test_sddl_ace_flags_multiple():
    test = "(A;OICIIO;GA;;;S-1-5-80-12345678-12345678-12345678-123456789-123456789)"
    parsed = parser.parse_ace_entry().parse(test)
    print(parsed)
    assert parsed == ACE(
        type="ACCESS_ALLOWED",
        flags=["OBJECT_INHERIT", "CONTAINER_INHERIT", "INHERIT_ONLY"],
        rights=["GENERIC_ALL"],
        object_guid="",
        inherit_object_guid="",
        sid="S-1-5-80-12345678-12345678-12345678-123456789-123456789",
        conditional_ace=None,
    )


def test_sddl_ace_rights_multiple():
    test = "(A;;CCLCSWLOCRRC;;;SU)"
    parsed = parser.parse_ace_entry().parse(test)
    assert parsed == ACE(
        type="ACCESS_ALLOWED",
        flags=[],
        rights=[
            "CREATE_CHILD",
            "LIST_CHILDREN",
            "SELF_WRITE",
            "LIST_OBJECT",
            "CONTROL_ACCESS",
            "READ_CONTROL",
        ],
        object_guid="",
        inherit_object_guid="",
        sid="SERVICE",
        conditional_ace=None,
    )
