from sddl_parser import parser as parser
from sddl_parser import api
from sddl_parser.parser import SDDL, ACE, ACL
from sddl_parser.ace_rights_enums import ServiceAccessRights
from sddl_parser.enums import AceType, SDDLFlags
from sddl_parser.sid_enum import SIDEnum


def test_translate_service_access():
    test = "O:SYG:SYD:(A;;CCLCSWRPWPDTLOCRRC;;;SY)S:"
    parsed = api.parse_sddl(test, ServiceAccessRights)
    assert parsed == SDDL(
        owner=SIDEnum.LOCAL_SYSTEM,
        group=SIDEnum.LOCAL_SYSTEM,
        dacl=ACL(
            flags={SDDLFlags.NO_ACCESS_CONTROL},
            aces=[
                ACE(
                    type=AceType.ACCESS_ALLOWED,
                    flags=set(),
                    rights_int=0x201FD,
                    rights={
                        ServiceAccessRights.SERVICE_QUERY_CONFIG,
                        ServiceAccessRights.SERVICE_QUERY_STATUS,
                        ServiceAccessRights.SERVICE_ENUMERATE_DEPENDENTS,
                        ServiceAccessRights.SERVICE_START,
                        ServiceAccessRights.SERVICE_STOP,
                        ServiceAccessRights.SERVICE_PAUSE_CONTINUE,
                        ServiceAccessRights.SERVICE_INTERROGATE,
                        ServiceAccessRights.SERVICE_USER_DEFINED_CONTROL,
                        ServiceAccessRights.READ_CONTROL,
                    },
                    object_guid="",
                    inherit_object_guid="",
                    sid=SIDEnum.LOCAL_SYSTEM,
                ),
            ],
        ),
        sacl=ACL(flags={SDDLFlags.NO_ACCESS_CONTROL}, aces=[]),
    )
