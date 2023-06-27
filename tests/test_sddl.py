from sddl_parser import parser as parser
from sddl_parser import api
from sddl_parser.parser import SDDL, ACE, DACL, SACL
from sddl_parser.rights_enums import GenericAccessRights
from sddl_parser.type_enums import AceType


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
    assert parsed == AceType.ACCESS_ALLOWED


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
                    type=AceType.ACCESS_ALLOWED,
                    flags=["INHERITED"],
                    rights_int=0x1F01FF,
                    rights={
                        GenericAccessRights.ACCESS0,
                        GenericAccessRights.ACCESS1,
                        GenericAccessRights.ACCESS2,
                        GenericAccessRights.ACCESS3,
                        GenericAccessRights.ACCESS4,
                        GenericAccessRights.ACCESS5,
                        GenericAccessRights.ACCESS6,
                        GenericAccessRights.ACCESS7,
                        GenericAccessRights.ACCESS8,
                        GenericAccessRights.DELETE,
                        GenericAccessRights.READ_CONTROL,
                        GenericAccessRights.WRITE_DAC,
                        GenericAccessRights.WRITE_OWNER,
                        GenericAccessRights.STANDARD_RIGHTS_REQUIRED,
                        GenericAccessRights.SYNCHRONIZE,
                        GenericAccessRights.STANDARD_RIGHTS_ALL,
                    },
                    object_guid="",
                    inherit_object_guid="",
                    sid="LOCAL_SYSTEM",
                ),
                ACE(
                    type=AceType.ACCESS_ALLOWED,
                    flags=["INHERITED"],
                    rights_int=0x1F01FF,
                    rights={
                        GenericAccessRights.ACCESS0,
                        GenericAccessRights.ACCESS1,
                        GenericAccessRights.ACCESS2,
                        GenericAccessRights.ACCESS3,
                        GenericAccessRights.ACCESS4,
                        GenericAccessRights.ACCESS5,
                        GenericAccessRights.ACCESS6,
                        GenericAccessRights.ACCESS7,
                        GenericAccessRights.ACCESS8,
                        GenericAccessRights.DELETE,
                        GenericAccessRights.READ_CONTROL,
                        GenericAccessRights.WRITE_DAC,
                        GenericAccessRights.WRITE_OWNER,
                        GenericAccessRights.STANDARD_RIGHTS_REQUIRED,
                        GenericAccessRights.SYNCHRONIZE,
                        GenericAccessRights.STANDARD_RIGHTS_ALL,
                    },
                    object_guid="",
                    inherit_object_guid="",
                    sid="BUILTIN_ADMINISTRATORS",
                ),
                ACE(
                    type=AceType.ACCESS_ALLOWED,
                    flags=["INHERITED"],
                    rights_int=0x1200A9,
                    rights={
                        GenericAccessRights.ACCESS0,
                        GenericAccessRights.ACCESS3,
                        GenericAccessRights.ACCESS5,
                        GenericAccessRights.ACCESS7,
                        GenericAccessRights.READ_CONTROL,
                        GenericAccessRights.SYNCHRONIZE,
                    },
                    object_guid="",
                    inherit_object_guid="",
                    sid="BUILTIN_USERS",
                ),
                ACE(
                    type=AceType.ACCESS_ALLOWED,
                    flags=["INHERITED"],
                    rights_int=0x1200A9,
                    rights={
                        GenericAccessRights.ACCESS0,
                        GenericAccessRights.ACCESS3,
                        GenericAccessRights.ACCESS5,
                        GenericAccessRights.ACCESS7,
                        GenericAccessRights.READ_CONTROL,
                        GenericAccessRights.SYNCHRONIZE,
                    },
                    object_guid="",
                    inherit_object_guid="",
                    sid="ALL_APP_PACKAGES",
                ),
                ACE(
                    type=AceType.ACCESS_ALLOWED,
                    flags=["INHERITED"],
                    rights_int=0x1200A9,
                    rights={
                        GenericAccessRights.ACCESS0,
                        GenericAccessRights.ACCESS3,
                        GenericAccessRights.ACCESS5,
                        GenericAccessRights.ACCESS7,
                        GenericAccessRights.READ_CONTROL,
                        GenericAccessRights.SYNCHRONIZE,
                    },
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


def test_sddl_sacl():
    test = "O:SYG:SYD:(A;;CCLCSWRPWPDTLOCRRC;;;SY)S:"
    parsed = parser.sddl_item.parse(test)
    assert parsed.sacl == SACL(flags=["NULL_DACL"], aces=[])
