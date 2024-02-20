from sddl_parser import parser as parser
from sddl_parser import api
from sddl_parser.parser import SDDL, ACE, ACL
from sddl_parser.ace_rights_enums import GenericAccessRights
from sddl_parser.enums import AceFlags, AceType, SDDLFlags
from sddl_parser.sid_enum import SIDEnum


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
        owner=SIDEnum.LOCAL_SYSTEM,
        group=SIDEnum.LOCAL_SYSTEM,
        dacl=ACL(
            flags={SDDLFlags.SDDL_AUTO_INHERITED},
            aces=[
                ACE(
                    type=AceType.ACCESS_ALLOWED,
                    flags={AceFlags.INHERITED},
                    rights_int=0x1F01FF,
                    rights={
                        GenericAccessRights.CREATE_CHILD,
                        GenericAccessRights.DELETE_CHILD,
                        GenericAccessRights.LIST_CHILDREN,
                        GenericAccessRights.SELF_WRITE,
                        GenericAccessRights.READ_PROPERTY,
                        GenericAccessRights.WRITE_PROPERTY,
                        GenericAccessRights.DELETE_TREE,
                        GenericAccessRights.LIST_OBJECT,
                        GenericAccessRights.CONTROL_ACCESS,
                        GenericAccessRights.STANDARD_DELETE,
                        GenericAccessRights.READ_CONTROL,
                        GenericAccessRights.WRITE_DAC,
                        GenericAccessRights.WRITE_OWNER,
                        GenericAccessRights.STANDARD_RIGHTS_REQUIRED,
                        GenericAccessRights.SYNCHRONIZE,
                        GenericAccessRights.STANDARD_RIGHTS_ALL,
                    },
                    object_guid="",
                    inherit_object_guid="",
                    sid=SIDEnum.LOCAL_SYSTEM,
                ),
                ACE(
                    type=AceType.ACCESS_ALLOWED,
                    flags={AceFlags.INHERITED},
                    rights_int=0x1F01FF,
                    rights={
                        GenericAccessRights.CREATE_CHILD,
                        GenericAccessRights.DELETE_CHILD,
                        GenericAccessRights.LIST_CHILDREN,
                        GenericAccessRights.SELF_WRITE,
                        GenericAccessRights.READ_PROPERTY,
                        GenericAccessRights.WRITE_PROPERTY,
                        GenericAccessRights.DELETE_TREE,
                        GenericAccessRights.LIST_OBJECT,
                        GenericAccessRights.CONTROL_ACCESS,
                        GenericAccessRights.STANDARD_DELETE,
                        GenericAccessRights.READ_CONTROL,
                        GenericAccessRights.WRITE_DAC,
                        GenericAccessRights.WRITE_OWNER,
                        GenericAccessRights.STANDARD_RIGHTS_REQUIRED,
                        GenericAccessRights.SYNCHRONIZE,
                        GenericAccessRights.STANDARD_RIGHTS_ALL,
                    },
                    object_guid="",
                    inherit_object_guid="",
                    sid=SIDEnum.BUILTIN_ADMINISTRATORS,
                ),
                ACE(
                    type=AceType.ACCESS_ALLOWED,
                    flags={AceFlags.INHERITED},
                    rights_int=0x1200A9,
                    rights={
                        GenericAccessRights.CREATE_CHILD,
                        GenericAccessRights.SELF_WRITE,
                        GenericAccessRights.WRITE_PROPERTY,
                        GenericAccessRights.LIST_OBJECT,
                        GenericAccessRights.READ_CONTROL,
                        GenericAccessRights.SYNCHRONIZE,
                    },
                    object_guid="",
                    inherit_object_guid="",
                    sid=SIDEnum.BUILTIN_USERS,
                ),
                ACE(
                    type=AceType.ACCESS_ALLOWED,
                    flags={AceFlags.INHERITED},
                    rights_int=0x1200A9,
                    rights={
                        GenericAccessRights.CREATE_CHILD,
                        GenericAccessRights.SELF_WRITE,
                        GenericAccessRights.WRITE_PROPERTY,
                        GenericAccessRights.LIST_OBJECT,
                        GenericAccessRights.READ_CONTROL,
                        GenericAccessRights.SYNCHRONIZE,
                    },
                    object_guid="",
                    inherit_object_guid="",
                    sid=SIDEnum.ALL_APP_PACKAGES,
                ),
                ACE(
                    type=AceType.ACCESS_ALLOWED,
                    flags={AceFlags.INHERITED},
                    rights_int=0x1200A9,
                    rights={
                        GenericAccessRights.CREATE_CHILD,
                        GenericAccessRights.SELF_WRITE,
                        GenericAccessRights.WRITE_PROPERTY,
                        GenericAccessRights.LIST_OBJECT,
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
    assert parsed.dacl.flags == {SDDLFlags.NO_ACCESS_CONTROL}


def test_sddl_null_dacl_empty_aces():
    test = "O:SYG:SYD:"
    parsed = parser.sddl_item.parse(test)
    assert parsed.dacl == ACL(flags={SDDLFlags.NO_ACCESS_CONTROL}, aces=[])


def test_sddl_none_dacl():
    test = "O:SYG:SY"
    parsed = parser.sddl_item.parse(test)
    assert parsed.dacl == None


def test_sddl_sacl():
    test = "O:SYG:SYD:(A;;CCLCSWRPWPDTLOCRRC;;;SY)S:"
    parsed = parser.sddl_item.parse(test)
    assert parsed.sacl == ACL(flags={SDDLFlags.NO_ACCESS_CONTROL}, aces=[])
