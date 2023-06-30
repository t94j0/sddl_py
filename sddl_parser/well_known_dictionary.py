from typing import Dict
from sddl_parser.ace_rights_enums import (
    GenericAccessRights,
    FileAccessRights,
    RegistryKeyAccessRights,
)
from sddl_parser.sid_enum import SIDEnum
from sddl_parser.enums import AceType, AceFlags, SDDLFlags

# https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/628ebb1d-c509-4ea0-a10f-77ef97ca4586
ACE_TYPE: Dict[str, AceType] = {
    "A": AceType.ACCESS_ALLOWED,
    "D": AceType.ACCESS_DENIED,
    "OA": AceType.ACCESS_ALLOWED_OBJECT,
    "OD": AceType.ACCESS_DENIED_OBJECT,
    "AU": AceType.SYSTEM_AUDIT,
    "AL": AceType.SYSTEM_ALARM,
    "OU": AceType.SYSTEM_AUDIT_OBJECT,
    "OL": AceType.SYSTEM_ALARM_OBJECT,
    "ML": AceType.SYSTEM_MANDATORY_LABEL,
    "XA": AceType.ACCESS_ALLOWED_CALLBACK,
    "XD": AceType.ACCESS_DENIED_CALLBACK,
    "RA": AceType.SYSTEM_RESOURCE_ATTRIBUTE,
    "SP": AceType.SYSTEM_SCOPED_POLICY_ID,
    "XU": AceType.SYSTEM_AUDIT_CALLBACK,
    "ZA": AceType.ACCESS_ALLOWED_CALLBACK_OBJECT,
    "TL": AceType.SYSTEM_PROCESS_TRUST_LABEL,
    "FL": AceType.SYSTEM_ACCESS_FILTER,
}

ACE_FLAGS = {
    "CI": AceFlags.CONTAINER_INHERIT,
    "OI": AceFlags.OBJECT_INHERIT,
    "NP": AceFlags.NO_PROPAGATE,
    "IO": AceFlags.INHERIT_ONLY,
    "ID": AceFlags.INHERITED,
    "SA": AceFlags.AUDIT_SUCCESS,
    "FA": AceFlags.AUDIT_FAILURE,
    "TP": AceFlags.TRUST_PROTECTED_FILTER
    # TODO: CR missing - https://learn.microsoft.com/en-us/windows/win32/secauthz/ace-strings
}


# https://github.com/tpn/winsdk-10/blob/master/Include/10.0.14393.0/shared/sddl.h#L123
ACE_RIGHTS: Dict[str, int] = {
    "CC": GenericAccessRights.ACCESS0,
    "DC": GenericAccessRights.ACCESS1,
    "LC": GenericAccessRights.ACCESS2,
    "SW": GenericAccessRights.ACCESS3,
    "RP": GenericAccessRights.ACCESS4,
    "WP": GenericAccessRights.ACCESS5,
    "DT": GenericAccessRights.ACCESS6,
    "LO": GenericAccessRights.ACCESS7,
    "CR": GenericAccessRights.ACCESS8,
    "SD": GenericAccessRights.DELETE,
    "RC": GenericAccessRights.READ_CONTROL,
    "WD": GenericAccessRights.WRITE_DAC,
    "WO": GenericAccessRights.WRITE_OWNER,
    "GA": GenericAccessRights.GENERIC_ALL,
    "GX": GenericAccessRights.GENERIC_EXECUTE,
    "GW": GenericAccessRights.GENERIC_WRITE,
    "GR": GenericAccessRights.GENERIC_READ,
    "FA": FileAccessRights.FILE_ALL_ACCESS,
    "FR": FileAccessRights.FILE_GENERIC_READ,
    "FW": FileAccessRights.FILE_GENERIC_WRITE,
    "FX": FileAccessRights.FILE_GENERIC_EXECUTE,
    "KA": RegistryKeyAccessRights.KEY_ALL_ACCESS,
    "KR": RegistryKeyAccessRights.KEY_READ,
    "KW": RegistryKeyAccessRights.KEY_WRITE,
    "KX": RegistryKeyAccessRights.KEY_EXECUTE,
    # SDDL_NO_READ_UP
    "NR": 0x01,
    # SDDL_NO_WRITE_UP
    "NW": 0x02,
    # SDDL_NO_EXECUTE_UP
    "NX": 0x04,
}

# Well known SIDs
SDDL_SIDS = {
    "AA": SIDEnum.ACCESS_CONTROL_ASSISTANCE_OPS,
    "AC": SIDEnum.ALL_APP_PACKAGES,
    "AN": SIDEnum.ANONYMOUS,
    "AO": SIDEnum.ACCOUNT_OPERATORS,
    "AP": SIDEnum.PROTECTED_USERS,
    "AU": SIDEnum.AUTHENTICATED_USERS,
    "BA": SIDEnum.BUILTIN_ADMINISTRATORS,
    "BG": SIDEnum.BUILTIN_GUESTS,
    "BO": SIDEnum.BACKUP_OPERATORS,
    "BU": SIDEnum.BUILTIN_USERS,
    "CA": SIDEnum.CERT_SERV_ADMINISTRATORS,
    "CD": SIDEnum.CERTSVC_DCOM_ACCESS,
    "CG": SIDEnum.CREATOR_GROUP,
    "CN": SIDEnum.CLONEABLE_CONTROLLERS,
    "CO": SIDEnum.CREATOR_OWNER,
    "CY": SIDEnum.CRYPTO_OPERATORS,
    "DA": SIDEnum.DOMAIN_ADMINISTRATORS,
    "DC": SIDEnum.DOMAIN_COMPUTERS,
    "DD": SIDEnum.DOMAIN_DOMAIN_CONTROLLERS,
    "DG": SIDEnum.DOMAIN_GUESTS,
    "DU": SIDEnum.DOMAIN_USERS,
    "EA": SIDEnum.ENTERPRISE_ADMINS,
    "ED": SIDEnum.ENTERPRISE_DOMAIN_CONTROLLERS,
    "EK": SIDEnum.ENTERPRISE_KEY_ADMINS,
    "ER": SIDEnum.EVENT_LOG_READERS,
    "ES": SIDEnum.RDS_ENDPOINT_SERVERS,
    "HA": SIDEnum.HYPER_V_ADMINS,
    "HI": SIDEnum.ML_HIGH,
    "IS": SIDEnum.IIS_USERS,
    "IU": SIDEnum.INTERACTIVE,
    "KA": SIDEnum.KEY_ADMINS,
    "LA": SIDEnum.LOCAL_ADMIN,
    "LG": SIDEnum.LOCAL_GUEST,
    "LS": SIDEnum.LOCAL_SERVICE,
    "LU": SIDEnum.PERFLOG_USERS,
    "LW": SIDEnum.ML_LOW,
    "ME": SIDEnum.ML_MEDIUM,
    "MP": SIDEnum.ML_MEDIUM_PLUS,
    "MU": SIDEnum.PERFMON_USERS,
    "NO": SIDEnum.NETWORK_CONFIGURATION_OPS,
    "NS": SIDEnum.NETWORK_SERVICE,
    "NU": SIDEnum.NETWORK,
    "OW": SIDEnum.OWNER_RIGHTS,
    "PA": SIDEnum.GROUP_POLICY_ADMINS,
    "PO": SIDEnum.PRINTER_OPERATORS,
    "PS": SIDEnum.PERSONAL_SELF,
    "PU": SIDEnum.POWER_USERS,
    "RA": SIDEnum.RDS_REMOTE_ACCESS_SERVERS,
    "RC": SIDEnum.RESTRICTED_CODE,
    "RD": SIDEnum.REMOTE_DESKTOP,
    "RE": SIDEnum.REPLICATOR,
    "RM": SIDEnum.RMS__SERVICE_OPERATORS,
    "RO": SIDEnum.ENTERPRISE_RO_DCs,
    "RS": SIDEnum.RAS_SERVERS,
    "RU": SIDEnum.ALIAS_PREW2KCOMPACC,
    "SA": SIDEnum.SCHEMA_ADMINISTRATORS,
    "SI": SIDEnum.ML_SYSTEM,
    "SO": SIDEnum.SERVER_OPERATORS,
    "SS": SIDEnum.SERVICE_ASSERTED,
    "SU": SIDEnum.SERVICE,
    "SY": SIDEnum.LOCAL_SYSTEM,
    "UD": SIDEnum.USER_MODE_DRIVERS,
    "WD": SIDEnum.EVERYONE,
    "WR": SIDEnum.WRITE_RESTRICTED_CODE,
}


SDDL_FLAGS = {
    "AR": SDDLFlags.SDDL_AUTO_INHERIT_REQ,
    "AI": SDDLFlags.SDDL_AUTO_INHERITED,
    "P": SDDLFlags.PROTECTED,
    "NO_ACCESS_CONTROL": SDDLFlags.NO_ACCESS_CONTROL,
}
