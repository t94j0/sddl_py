from enum import Enum


DOMAIN_SENTINAL = "DOMAIN"


class SIDEnum(Enum):
    """
    https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/81d92bba-d22b-4a8c-908a-554ab29148ab
    """

    ACCESS_CONTROL_ASSISTANCE_OPS = "S-1-5-32-579"
    ALL_APP_PACKAGES = "S-1-15-2-1"
    ANONYMOUS = "S-1-5-7"
    ACCOUNT_OPERATORS = "S-1-5-32-548"
    PROTECTED_USERS = f"S-1-5-21-{DOMAIN_SENTINAL}-525"
    AUTHENTICATED_USERS = "S-1-5-11"
    BUILTIN_ADMINISTRATORS = "S-1-5-32-544"
    BUILTIN_GUESTS = "S-1-5-32-546"
    BACKUP_OPERATORS = "S-1-5-32-551"
    BUILTIN_USERS = "S-1-5-32-545"
    CERT_SERV_ADMINISTRATORS = "CERT_SERV_ADMINISTRATORS"
    CERTSVC_DCOM_ACCESS = ""
    CREATOR_GROUP = "S-1-3-1"
    CLONEABLE_CONTROLLERS = f"S-1-5-21-{DOMAIN_SENTINAL}-522"
    CREATOR_OWNER = "S-1-3-0"
    CRYPTO_OPERATORS = "S-1-5-32-569"
    DOMAIN_ADMINISTRATORS = "RMS__SERVICE_OPERATORS"
    DOMAIN_COMPUTERS = f"S-1-5-21-{DOMAIN_SENTINAL}-515"
    DOMAIN_DOMAIN_CONTROLLERS = f"S-1-5-21-{DOMAIN_SENTINAL}-516"
    DOMAIN_GUESTS = f"S-1-5-21-{DOMAIN_SENTINAL}-514"
    DOMAIN_USERS = f"S-1-5-21-{DOMAIN_SENTINAL}-513"
    ENTERPRISE_ADMINS = f"S-1-5-21-{DOMAIN_SENTINAL}-519"
    ENTERPRISE_DOMAIN_CONTROLLERS = "S-1-5-9"
    ENTERPRISE_KEY_ADMINS = f"S-1-5-21-{DOMAIN_SENTINAL}-527"
    EVENT_LOG_READERS = "S-1-5-32-573"
    RDS_ENDPOINT_SERVERS = "S-1-5-32-576"
    HYPER_V_ADMINS = "S-1-5-32-578"
    ML_HIGH = "S-1-16-12288"
    IIS_USERS = "S-1-5-17"
    INTERACTIVE = "S-1-5-4"
    KEY_ADMINS = f"S-1-5-21-{DOMAIN_SENTINAL}-526"
    # Is this correct?
    LOCAL_ADMIN = "S-1-5-21-<machine>-500"
    # Is this correct?
    LOCAL_GUEST = "S-1-5-21-<machine>-501"
    LOCAL_SERVICE = "S-1-5-19"
    PERFLOG_USERS = "S-1-5-32-559"
    ML_LOW = "S-1-16-4096"
    ML_MEDIUM = "S-1-16-8192"
    ML_MEDIUM_PLUS = "S-1-16-8448"
    PERFMON_USERS = "S-1-5-32-558"
    NETWORK_CONFIGURATION_OPS = "S-1-5-32-556"
    NETWORK_SERVICE = "S-1-5-20"
    NETWORK = "S-1-5-2"
    OWNER_RIGHTS = "S-1-3-4"
    GROUP_POLICY_ADMINS = "RMS__SERVICE_OPERATORS"
    PRINTER_OPERATORS = "S-1-5-32-550"
    PERSONAL_SELF = "S-1-5-10"
    POWER_USERS = "S-1-5-32-547"
    RDS_REMOTE_ACCESS_SERVERS = "S-1-5-32-575"
    RESTRICTED_CODE = "S-1-5-12"
    REMOTE_DESKTOP = "S-1-5-32-555"
    REPLICATOR = "S-1-5-32-552"
    RMS__SERVICE_OPERATORS = "RMS__SERVICE_OPERATORS"
    ENTERPRISE_RO_DCs = f"S-1-5-21-{DOMAIN_SENTINAL}-498"
    RAS_SERVERS = f"S-1-5-21-{DOMAIN_SENTINAL}-553"
    ALIAS_PREW2KCOMPACC = "S-1-5-32-554"
    SCHEMA_ADMINISTRATORS = "S-1-5-21-<root-domain>-518"
    ML_SYSTEM = "S-1-16-16384"
    SERVER_OPERATORS = "S-1-5-32-549"
    SERVICE_ASSERTED = "S-1-18-2"
    SERVICE = "S-1-5-6"
    LOCAL_SYSTEM = "S-1-5-18"
    USER_MODE_DRIVERS = "S-1-5-84-0-0-0-0-0"
    EVERYONE = "S-1-1-0"
    WRITE_RESTRICTED_CODE = "S-1-5-33"
