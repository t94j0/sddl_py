from enum import IntEnum


class AceType(IntEnum):
    ACCESS_ALLOWED = 0x0
    ACCESS_DENIED = 0x1
    SYSTEM_AUDIT = 0x2
    SYSTEM_ALARM = 0x3
    ACCESS_ALLOWED_COMPOUND = 0x4
    ACCESS_ALLOWED_OBJECT = 0x5
    ACCESS_DENIED_OBJECT = 0x6
    SYSTEM_AUDIT_OBJECT = 0x7
    SYSTEM_ALARM_OBJECT = 0x8
    ACCESS_ALLOWED_CALLBACK = 0x9
    ACCESS_DENIED_CALLBACK = 0xA
    ACCESS_ALLOWED_CALLBACK_OBJECT = 0xB
    ACCESS_DENIED_CALLBACK_OBJECT = 0xC
    SYSTEM_AUDIT_CALLBACK = 0xD
    SYSTEM_ALARM_CALLBACK = 0xE
    SYSTEM_AUDIT_CALLBACK_OBJECT = 0xF
    SYSTEM_ALARM_CALLBACK_OBJECT = 0x10
    SYSTEM_MANDATORY_LABEL = 0x11
    SYSTEM_RESOURCE_ATTRIBUTE = 0x12
    SYSTEM_SCOPED_POLICY_ID = 0x13
    SYSTEM_PROCESS_TRUST_LABEL = 0x14
    SYSTEM_ACCESS_FILTER = 0x15