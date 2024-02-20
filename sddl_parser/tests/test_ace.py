from sddl_parser import parser as parser
from sddl_parser import api
from sddl_parser.parser import ACE
from sddl_parser.ace_rights_enums import GenericAccessRights
from sddl_parser.enums import AceType, AceFlags
from sddl_parser.sid_enum import SIDEnum


def test_standard():
    test = "(A;;0x1200a9;;;SY)"
    parsed = api.parse_ace(test)
    assert parsed == ACE(
        type=AceType.ACCESS_ALLOWED,
        flags=set(),
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
        sid=SIDEnum.LOCAL_SYSTEM,
    )


def test_sid():
    test = "(A;ID;0x1200a9;;;S-1-15-2-2)"
    parsed = api.parse_ace(test)
    assert parsed == parser.ACE(
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
    )


def test_empty_flags():
    test = "(A;;0x1200a9;;;SY)"
    parsed = api.parse_ace(test)
    assert parsed == ACE(
        type=AceType.ACCESS_ALLOWED,
        flags=set(),
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
        sid=SIDEnum.LOCAL_SYSTEM,
    )


def test_known_sid():
    test = "(A;ID;0x1200a9;;;AC)"
    parsed = api.parse_ace(test)
    assert parsed == parser.ACE(
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
    )


def test_with_conditional_ace():
    test = '(XA;ID;0x1200a9;;;BU;(WIN://SYSAPPID Contains "Microsoft.MicrosoftEdge.Stable_abcdefghijk"))'
    parsed = api.parse_ace(test)
    assert parsed == ACE(
        type=AceType.ACCESS_ALLOWED_CALLBACK,
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
        conditional_ace='(WIN://SYSAPPID Contains "Microsoft.MicrosoftEdge.Stable_abcdefghijk")',
    )


def test_with_conditional_ace_deep():
    test = "(XA;;LCRPWP;;;BA;(!(WIN://ISMULTISESSIONSKU)))"
    parsed = parser.parse_ace_entry().parse_partial(test)
    assert parsed[1] == ""


def test_conditional_ace_deep():
    test = ";(!(WIN://ISMULTISESSIONSKU))("
    parsed = parser.parse_conditional_ace().parse_partial(test)
    assert parsed[1] == "("


def test_flags_multiple():
    test = "(A;OICIIO;GA;;;S-1-5-80-12345678-12345678-12345678-123456789-123456789)"
    parsed = api.parse_ace(test)
    assert parsed == ACE(
        type=AceType.ACCESS_ALLOWED,
        flags={
            AceFlags.OBJECT_INHERIT,
            AceFlags.CONTAINER_INHERIT,
            AceFlags.INHERIT_ONLY,
        },
        rights_int=0x10000000,
        rights={GenericAccessRights.GENERIC_ALL},
        object_guid="",
        inherit_object_guid="",
        sid="S-1-5-80-12345678-12345678-12345678-123456789-123456789",
        conditional_ace=None,
    )


def test_rights_multiple():
    test = "(A;;CCLCSWLOCRRC;;;SU)"
    parsed = api.parse_ace(test)
    assert parsed == ACE(
        type=AceType.ACCESS_ALLOWED,
        flags=set(),
        rights_int=0x2018D,
        rights={
            GenericAccessRights.CREATE_CHILD,
            GenericAccessRights.LIST_CHILDREN,
            GenericAccessRights.SELF_WRITE,
            GenericAccessRights.LIST_OBJECT,
            GenericAccessRights.CONTROL_ACCESS,
            GenericAccessRights.READ_CONTROL,
        },
        object_guid="",
        inherit_object_guid="",
        sid=SIDEnum.SERVICE,
        conditional_ace=None,
    )


def test_critical_flag():
    test = "(A;CR;KA;;;S-1-5-80-12345678-12345678-12345678-123456789-123456789)"
    parsed = api.parse_ace(test)
    assert parsed == ACE(
        type=AceType.ACCESS_ALLOWED,
        flags={
            AceFlags.CRITICAL,
        },
        object_guid="",
        rights_int=983103,
        inherit_object_guid="",
        sid="S-1-5-80-12345678-12345678-12345678-123456789-123456789",
        conditional_ace=None,
        rights={
            GenericAccessRights.WRITE_PROPERTY,
            GenericAccessRights.CREATE_CHILD,
            GenericAccessRights.DELETE_CHILD,
            GenericAccessRights.STANDARD_DELETE,
            GenericAccessRights.LIST_CHILDREN,
            GenericAccessRights.READ_CONTROL,
            GenericAccessRights.WRITE_DAC,
            GenericAccessRights.WRITE_OWNER,
            GenericAccessRights.SELF_WRITE,
            GenericAccessRights.STANDARD_RIGHTS_REQUIRED,
            GenericAccessRights.READ_PROPERTY,
        },
    )
