from sddl_parser import parser as parser
from sddl_parser import api
from sddl_parser.parser import SDDL, ACE, DACL, SACL
from sddl_parser.rights_enums import ServiceAccessRights
from sddl_parser.type_enums import AceType


def test_translate_service_access():
    test = "O:SYG:SYD:(A;;CCLCSWRPWPDTLOCRRC;;;SY)S:"
    parsed = api.parse_sddl(test, ServiceAccessRights)
    assert parsed == SDDL(
        owner="LOCAL_SYSTEM",
        group="LOCAL_SYSTEM",
        dacl=DACL(
            flags=["NULL_DACL"],
            aces=[
                ACE(
                    type=AceType.ACCESS_ALLOWED,
                    flags=[],
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
                    sid="LOCAL_SYSTEM",
                ),
            ],
        ),
        sacl=SACL(flags=["NULL_DACL"], aces=[]),
    )
