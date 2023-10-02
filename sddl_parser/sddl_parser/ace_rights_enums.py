from enum import IntEnum


class GenericAccessRights(IntEnum):
    ACCESS0 = 0x1
    ACCESS1 = 0x2
    ACCESS2 = 0x4
    ACCESS3 = 0x8
    ACCESS4 = 0x10
    ACCESS5 = 0x20
    ACCESS6 = 0x40
    ACCESS7 = 0x80
    ACCESS8 = 0x100
    ACCESS9 = 0x200
    ACCESS10 = 0x400
    ACCESS11 = 0x800
    ACCESS12 = 0x1000
    ACCESS13 = 0x2000
    ACCESS14 = 0x4000
    ACCESS15 = 0x8000
    DELETE = 0x10000
    READ_CONTROL = 0x20000
    WRITE_DAC = 0x40000
    WRITE_OWNER = 0x80000
    SYNCHRONIZE = 0x100000
    ACCESS_SYSTEM_SECURITY = 0x1000000
    MAXIMUM_ALLOWED = 0x2000000
    GENERIC_ALL = 0x10000000
    GENERIC_EXECUTE = 0x20000000
    GENERIC_WRITE = 0x40000000
    GENERIC_READ = 0x80000000
    STANDARD_RIGHTS_ALL = DELETE | READ_CONTROL | WRITE_DAC | WRITE_OWNER | SYNCHRONIZE
    STANDARD_RIGHTS_EXECUTE = READ_CONTROL
    STANDARD_RIGHTS_READ = READ_CONTROL
    STANDARD_RIGHTS_REQUIRED = DELETE | READ_CONTROL | WRITE_DAC | WRITE_OWNER
    STANDARD_RIGHTS_WRITE = READ_CONTROL


class ServiceControlManagerAccessRights(IntEnum):
    """
    https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/0d7a7011-9f41-470d-ad52-8535b47ac282
    """

    SC_MANAGER_CONNECT = GenericAccessRights.ACCESS0
    SC_MANAGER_CREATE_SERVICE = GenericAccessRights.ACCESS1
    SC_MANAGER_ENUMERATE_SERVICE = GenericAccessRights.ACCESS2
    SC_MANAGER_LOCK = GenericAccessRights.ACCESS3
    SC_MANAGER_QUERY_LOCK_STATUS = GenericAccessRights.ACCESS4
    SC_MANAGER_MODIFY_BOOT_CONFIG = GenericAccessRights.ACCESS5
    SC_MANAGER_ALL_ACCESS = (
        GenericAccessRights.STANDARD_RIGHTS_REQUIRED.value
        | SC_MANAGER_CONNECT
        | SC_MANAGER_CREATE_SERVICE
        | SC_MANAGER_ENUMERATE_SERVICE
        | SC_MANAGER_LOCK
        | SC_MANAGER_QUERY_LOCK_STATUS
        | SC_MANAGER_MODIFY_BOOT_CONFIG
    )
    GENERIC_READ = GenericAccessRights.GENERIC_READ
    GENERIC_WRITE = GenericAccessRights.GENERIC_WRITE
    GENERIC_EXECUTE = GenericAccessRights.GENERIC_EXECUTE
    GENERIC_ALL = GenericAccessRights.GENERIC_ALL
    DELETE = GenericAccessRights.DELETE
    READ_CONTROL = GenericAccessRights.READ_CONTROL
    WRITE_DAC = GenericAccessRights.WRITE_DAC
    WRITE_OWNER = GenericAccessRights.WRITE_OWNER
    SYNCHRONIZE = GenericAccessRights.SYNCHRONIZE
    MAXIMUM_ALLOWED = GenericAccessRights.MAXIMUM_ALLOWED
    ACCESS_SYSTEM_SECURITY = GenericAccessRights.ACCESS_SYSTEM_SECURITY


class ServiceAccessRights(IntEnum):
    """
    https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/0d7a7011-9f41-470d-ad52-8535b47ac282
    """

    SERVICE_QUERY_CONFIG = GenericAccessRights.ACCESS0
    SERVICE_CHANGE_CONFIG = GenericAccessRights.ACCESS1
    SERVICE_QUERY_STATUS = GenericAccessRights.ACCESS2
    SERVICE_ENUMERATE_DEPENDENTS = GenericAccessRights.ACCESS3
    SERVICE_START = GenericAccessRights.ACCESS4
    SERVICE_STOP = GenericAccessRights.ACCESS5
    SERVICE_PAUSE_CONTINUE = GenericAccessRights.ACCESS6
    SERVICE_INTERROGATE = GenericAccessRights.ACCESS7
    SERVICE_USER_DEFINED_CONTROL = GenericAccessRights.ACCESS8
    SERVICE_SET_STATUS = GenericAccessRights.ACCESS15
    SERVICE_ALL_ACCESS = (
        GenericAccessRights.STANDARD_RIGHTS_REQUIRED.value
        | SERVICE_CHANGE_CONFIG
        | SERVICE_ENUMERATE_DEPENDENTS
        | SERVICE_INTERROGATE
        | SERVICE_PAUSE_CONTINUE
        | SERVICE_QUERY_CONFIG
        | SERVICE_QUERY_STATUS
        | SERVICE_START
        | SERVICE_STOP
        | SERVICE_USER_DEFINED_CONTROL
    )
    GENERIC_READ = GenericAccessRights.GENERIC_READ
    GENERIC_WRITE = GenericAccessRights.GENERIC_WRITE
    GENERIC_EXECUTE = GenericAccessRights.GENERIC_EXECUTE
    GENERIC_ALL = GenericAccessRights.GENERIC_ALL
    DELETE = GenericAccessRights.DELETE
    READ_CONTROL = GenericAccessRights.READ_CONTROL
    WRITE_DAC = GenericAccessRights.WRITE_DAC
    WRITE_OWNER = GenericAccessRights.WRITE_OWNER
    SYNCHRONIZE = GenericAccessRights.SYNCHRONIZE
    MAXIMUM_ALLOWED = GenericAccessRights.MAXIMUM_ALLOWED
    ACCESS_SYSTEM_SECURITY = GenericAccessRights.ACCESS_SYSTEM_SECURITY


class FileAccessRights(IntEnum):
    """
    https://learn.microsoft.com/en-us/windows/win32/fileio/file-access-rights-constants
    """

    FILE_READ_DATA = GenericAccessRights.ACCESS0
    FILE_WRITE_DATA = GenericAccessRights.ACCESS1
    FILE_APPEND_DATA = GenericAccessRights.ACCESS2
    FILE_READ_EA = GenericAccessRights.ACCESS3
    FILE_WRITE_EA = GenericAccessRights.ACCESS4
    FILE_EXECUTE = GenericAccessRights.ACCESS5
    FILE_DELETE_CHILD = GenericAccessRights.ACCESS6
    FILE_READ_ATTRIBUTES = GenericAccessRights.ACCESS7
    FILE_WRITE_ATTRIBUTES = GenericAccessRights.ACCESS8
    GENERIC_READ = GenericAccessRights.GENERIC_READ
    GENERIC_WRITE = GenericAccessRights.GENERIC_WRITE
    GENERIC_EXECUTE = GenericAccessRights.GENERIC_EXECUTE
    GENERIC_ALL = GenericAccessRights.GENERIC_ALL
    DELETE = GenericAccessRights.DELETE
    READ_CONTROL = GenericAccessRights.READ_CONTROL
    WRITE_DAC = GenericAccessRights.WRITE_DAC
    WRITE_OWNER = GenericAccessRights.WRITE_OWNER
    SYNCHRONIZE = GenericAccessRights.SYNCHRONIZE
    MAXIMUM_ALLOWED = GenericAccessRights.MAXIMUM_ALLOWED
    ACCESS_SYSTEM_SECURITY = GenericAccessRights.ACCESS_SYSTEM_SECURITY
    FILE_ALL_ACCESS = GenericAccessRights.STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0x1FF
    FILE_GENERIC_READ = (
        GenericAccessRights.STANDARD_RIGHTS_READ
        | FILE_READ_DATA
        | FILE_READ_ATTRIBUTES
        | FILE_READ_EA
        | SYNCHRONIZE
    )
    FILE_GENERIC_WRITE = (
        GenericAccessRights.STANDARD_RIGHTS_WRITE
        | FILE_WRITE_DATA
        | FILE_WRITE_ATTRIBUTES
        | FILE_WRITE_EA
        | FILE_APPEND_DATA
        | SYNCHRONIZE
    )
    FILE_GENERIC_EXECUTE = (
        GenericAccessRights.STANDARD_RIGHTS_EXECUTE
        | FILE_READ_ATTRIBUTES
        | FILE_EXECUTE
        | SYNCHRONIZE
    )


class RegistryKeyAccessRights(IntEnum):
    """
    https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-key-security-and-access-rights
    """

    KEY_QUERY_VALUE = GenericAccessRights.ACCESS0
    KEY_SET_VALUE = GenericAccessRights.ACCESS1
    KEY_CREATE_SUB_KEY = GenericAccessRights.ACCESS2
    KEY_ENUMERATE_SUB_KEYS = GenericAccessRights.ACCESS3
    KEY_NOTIFY = GenericAccessRights.ACCESS4
    KEY_CREATE_LINK = GenericAccessRights.ACCESS5
    KEY_WOW64_64KEY = GenericAccessRights.ACCESS8
    KEY_WOW64_32KEY = GenericAccessRights.ACCESS9
    GENERIC_READ = GenericAccessRights.GENERIC_READ
    GENERIC_WRITE = GenericAccessRights.GENERIC_WRITE
    GENERIC_EXECUTE = GenericAccessRights.GENERIC_EXECUTE
    GENERIC_ALL = GenericAccessRights.GENERIC_ALL
    DELETE = GenericAccessRights.DELETE
    READ_CONTROL = GenericAccessRights.READ_CONTROL
    WRITE_DAC = GenericAccessRights.WRITE_DAC
    WRITE_OWNER = GenericAccessRights.WRITE_OWNER
    SYNCHRONIZE = GenericAccessRights.SYNCHRONIZE
    MAXIMUM_ALLOWED = GenericAccessRights.MAXIMUM_ALLOWED
    ACCESS_SYSTEM_SECURITY = GenericAccessRights.ACCESS_SYSTEM_SECURITY
    KEY_ALL_ACCESS = (
        GenericAccessRights.STANDARD_RIGHTS_REQUIRED.value
        | KEY_QUERY_VALUE
        | KEY_SET_VALUE
        | KEY_CREATE_SUB_KEY
        | KEY_ENUMERATE_SUB_KEYS
        | KEY_NOTIFY
        | KEY_CREATE_LINK
    )
    KEY_READ = (
        GenericAccessRights.STANDARD_RIGHTS_READ.value
        | KEY_QUERY_VALUE
        | KEY_ENUMERATE_SUB_KEYS
        | KEY_NOTIFY
    )
    KEY_WRITE = (
        GenericAccessRights.STANDARD_RIGHTS_WRITE.value
        | KEY_SET_VALUE
        | KEY_CREATE_SUB_KEY
    )
    KEY_EXECUTE = KEY_READ


class AlpcAccessRights(IntEnum):
    PORT_CONNECT = GenericAccessRights.ACCESS0
    GENERIC_READ = GenericAccessRights.GENERIC_READ
    GENERIC_WRITE = GenericAccessRights.GENERIC_WRITE
    GENERIC_EXECUTE = GenericAccessRights.GENERIC_EXECUTE
    GENERIC_ALL = GenericAccessRights.GENERIC_ALL
    DELETE = GenericAccessRights.DELETE
    READ_CONTROL = GenericAccessRights.READ_CONTROL
    WRITE_DAC = GenericAccessRights.WRITE_DAC
    WRITE_OWNER = GenericAccessRights.WRITE_OWNER
    SYNCHRONIZE = GenericAccessRights.SYNCHRONIZE
    MAXIMUM_ALLOWED = GenericAccessRights.MAXIMUM_ALLOWED
    ACCESS_SYSTEM_SECURITY = GenericAccessRights.ACCESS_SYSTEM_SECURITY


class DebugAccessRights(IntEnum):
    DEBUG_READ_EVENT = GenericAccessRights.ACCESS0
    DEBUG_PROCESS_ASSIGN = GenericAccessRights.ACCESS1
    DEBUG_SET_INFORMATION = GenericAccessRights.ACCESS2
    DEBUG_QUERY_INFORMATION = GenericAccessRights.ACCESS3
    GENERIC_READ = GenericAccessRights.GENERIC_READ
    GENERIC_WRITE = GenericAccessRights.GENERIC_WRITE
    GENERIC_EXECUTE = GenericAccessRights.GENERIC_EXECUTE
    GENERIC_ALL = GenericAccessRights.GENERIC_ALL
    DELETE = GenericAccessRights.DELETE
    READ_CONTROL = GenericAccessRights.READ_CONTROL
    WRITE_DAC = GenericAccessRights.WRITE_DAC
    WRITE_OWNER = GenericAccessRights.WRITE_OWNER
    SYNCHRONIZE = GenericAccessRights.SYNCHRONIZE
    MAXIMUM_ALLOWED = GenericAccessRights.MAXIMUM_ALLOWED
    ACCESS_SYSTEM_SECURITY = GenericAccessRights.ACCESS_SYSTEM_SECURITY


class DesktopAccessRights(IntEnum):
    DESKTOP_READOBJECTS = GenericAccessRights.ACCESS0
    DESKTOP_CREATEWINDOW = GenericAccessRights.ACCESS1
    DESKTOP_CREATEMENU = GenericAccessRights.ACCESS2
    DESKTOP_HOOKCONTROL = GenericAccessRights.ACCESS3
    DESKTOP_JOURNALRECORD = GenericAccessRights.ACCESS4
    DESKTOP_JOURNALPLAYBACK = GenericAccessRights.ACCESS5
    DESKTOP_ENUMERATE = GenericAccessRights.ACCESS6
    DESKTOP_WRITEOBJECTS = GenericAccessRights.ACCESS7
    DESKTOP_SWITCHDESKTOP = GenericAccessRights.ACCESS8
    GENERIC_READ = GenericAccessRights.GENERIC_READ
    GENERIC_WRITE = GenericAccessRights.GENERIC_WRITE
    GENERIC_EXECUTE = GenericAccessRights.GENERIC_EXECUTE
    GENERIC_ALL = GenericAccessRights.GENERIC_ALL
    DELETE = GenericAccessRights.DELETE
    READ_CONTROL = GenericAccessRights.READ_CONTROL
    WRITE_DAC = GenericAccessRights.WRITE_DAC
    WRITE_OWNER = GenericAccessRights.WRITE_OWNER
    SYNCHRONIZE = GenericAccessRights.SYNCHRONIZE
    MAXIMUM_ALLOWED = GenericAccessRights.MAXIMUM_ALLOWED
    ACCESS_SYSTEM_SECURITY = GenericAccessRights.ACCESS_SYSTEM_SECURITY


class DirectoryAccessRights(IntEnum):
    DIRECTORY_QUERY = GenericAccessRights.ACCESS0
    DIRECTORY_TRAVERSE = GenericAccessRights.ACCESS1
    DIRECTORY_CREATE_OBJECT = GenericAccessRights.ACCESS2
    DIRECTORY_CREATE_SUBDIRECTORY = GenericAccessRights.ACCESS3
    GENERIC_READ = GenericAccessRights.GENERIC_READ
    GENERIC_WRITE = GenericAccessRights.GENERIC_WRITE
    GENERIC_EXECUTE = GenericAccessRights.GENERIC_EXECUTE
    GENERIC_ALL = GenericAccessRights.GENERIC_ALL
    DELETE = GenericAccessRights.DELETE
    READ_CONTROL = GenericAccessRights.READ_CONTROL
    WRITE_DAC = GenericAccessRights.WRITE_DAC
    WRITE_OWNER = GenericAccessRights.WRITE_OWNER
    SYNCHRONIZE = GenericAccessRights.SYNCHRONIZE
    MAXIMUM_ALLOWED = GenericAccessRights.MAXIMUM_ALLOWED
    ACCESS_SYSTEM_SECURITY = GenericAccessRights.ACCESS_SYSTEM_SECURITY


class EnlistmentAccessRights(IntEnum):
    ENLISTMENT_QUERY_INFORMATION = GenericAccessRights.ACCESS0
    ENLISTMENT_SET_INFORMATION = GenericAccessRights.ACCESS1
    ENLISTMENT_RECOVER = GenericAccessRights.ACCESS2
    ENLISTMENT_SUBORDINATE_RIGHTS = GenericAccessRights.ACCESS3
    ENLISTMENT_SUPERIOR_RIGHTS = GenericAccessRights.ACCESS4
    GENERIC_READ = GenericAccessRights.GENERIC_READ
    GENERIC_WRITE = GenericAccessRights.GENERIC_WRITE
    GENERIC_EXECUTE = GenericAccessRights.GENERIC_EXECUTE
    GENERIC_ALL = GenericAccessRights.GENERIC_ALL
    DELETE = GenericAccessRights.DELETE
    READ_CONTROL = GenericAccessRights.READ_CONTROL
    WRITE_DAC = GenericAccessRights.WRITE_DAC
    WRITE_OWNER = GenericAccessRights.WRITE_OWNER
    SYNCHRONIZE = GenericAccessRights.SYNCHRONIZE
    MAXIMUM_ALLOWED = GenericAccessRights.MAXIMUM_ALLOWED
    ACCESS_SYSTEM_SECURITY = GenericAccessRights.ACCESS_SYSTEM_SECURITY


class EventAccessRights(IntEnum):
    EVENT_QUERY_STATE = GenericAccessRights.ACCESS0
    EVENT_MODIFY_STATE = GenericAccessRights.ACCESS1
    GENERIC_READ = GenericAccessRights.GENERIC_READ
    GENERIC_WRITE = GenericAccessRights.GENERIC_WRITE
    GENERIC_EXECUTE = GenericAccessRights.GENERIC_EXECUTE
    GENERIC_ALL = GenericAccessRights.GENERIC_ALL
    DELETE = GenericAccessRights.DELETE
    READ_CONTROL = GenericAccessRights.READ_CONTROL
    WRITE_DAC = GenericAccessRights.WRITE_DAC
    WRITE_OWNER = GenericAccessRights.WRITE_OWNER
    SYNCHRONIZE = GenericAccessRights.SYNCHRONIZE
    MAXIMUM_ALLOWED = GenericAccessRights.MAXIMUM_ALLOWED
    ACCESS_SYSTEM_SECURITY = GenericAccessRights.ACCESS_SYSTEM_SECURITY


class FileDirectoryAccessRights(IntEnum):
    """
    https://learn.microsoft.com/en-us/windows/win32/fileio/file-access-rights-constants
    """

    FILE_LIST_DIRECTORY = GenericAccessRights.ACCESS0
    FILE_ADD_FILE = GenericAccessRights.ACCESS1
    FILE_ADD_SUBDIRECTORY = GenericAccessRights.ACCESS2
    FILE_READ_EA = GenericAccessRights.ACCESS3
    FILE_WRITE_EA = GenericAccessRights.ACCESS4
    FILE_TRAVERSE = GenericAccessRights.ACCESS5
    FILE_DELETE_CHILD = GenericAccessRights.ACCESS6
    FILE_READ_ATTRIBUTES = GenericAccessRights.ACCESS7
    FILE_WRITE_ATTRIBUTES = GenericAccessRights.ACCESS8
    GENERIC_READ = GenericAccessRights.GENERIC_READ
    GENERIC_WRITE = GenericAccessRights.GENERIC_WRITE
    GENERIC_EXECUTE = GenericAccessRights.GENERIC_EXECUTE
    GENERIC_ALL = GenericAccessRights.GENERIC_ALL
    DELETE = GenericAccessRights.DELETE
    READ_CONTROL = GenericAccessRights.READ_CONTROL
    WRITE_DAC = GenericAccessRights.WRITE_DAC
    WRITE_OWNER = GenericAccessRights.WRITE_OWNER
    SYNCHRONIZE = GenericAccessRights.SYNCHRONIZE
    MAXIMUM_ALLOWED = GenericAccessRights.MAXIMUM_ALLOWED
    ACCESS_SYSTEM_SECURITY = GenericAccessRights.ACCESS_SYSTEM_SECURITY


class FilterConnectionPortAccessRights(IntEnum):
    FILTER_CONNECTION_PORT_CONNECT = GenericAccessRights.ACCESS0
    GENERIC_READ = GenericAccessRights.GENERIC_READ
    GENERIC_WRITE = GenericAccessRights.GENERIC_WRITE
    GENERIC_EXECUTE = GenericAccessRights.GENERIC_EXECUTE
    GENERIC_ALL = GenericAccessRights.GENERIC_ALL
    DELETE = GenericAccessRights.DELETE
    READ_CONTROL = GenericAccessRights.READ_CONTROL
    WRITE_DAC = GenericAccessRights.WRITE_DAC
    WRITE_OWNER = GenericAccessRights.WRITE_OWNER
    SYNCHRONIZE = GenericAccessRights.SYNCHRONIZE
    MAXIMUM_ALLOWED = GenericAccessRights.MAXIMUM_ALLOWED
    ACCESS_SYSTEM_SECURITY = GenericAccessRights.ACCESS_SYSTEM_SECURITY


class IoCompletionAccessRights(IntEnum):
    IO_COMPLETION_QUERY_STATE = GenericAccessRights.ACCESS0
    IO_COMPLETION_SET_COMPLETION = GenericAccessRights.ACCESS1
    GENERIC_READ = GenericAccessRights.GENERIC_READ
    GENERIC_WRITE = GenericAccessRights.GENERIC_WRITE
    GENERIC_EXECUTE = GenericAccessRights.GENERIC_EXECUTE
    GENERIC_ALL = GenericAccessRights.GENERIC_ALL
    DELETE = GenericAccessRights.DELETE
    READ_CONTROL = GenericAccessRights.READ_CONTROL
    WRITE_DAC = GenericAccessRights.WRITE_DAC
    WRITE_OWNER = GenericAccessRights.WRITE_OWNER
    SYNCHRONIZE = GenericAccessRights.SYNCHRONIZE
    MAXIMUM_ALLOWED = GenericAccessRights.MAXIMUM_ALLOWED
    ACCESS_SYSTEM_SECURITY = GenericAccessRights.ACCESS_SYSTEM_SECURITY


class JobAccessRights(IntEnum):
    JOB_ASSIGN_PROCESS = GenericAccessRights.ACCESS0
    JOB_SET_ATTRIBUTES = GenericAccessRights.ACCESS1
    JOB_QUERY = GenericAccessRights.ACCESS2
    JOB_TERMINATE = GenericAccessRights.ACCESS3
    JOB_SET_SECURITY_ATTRIBUTES = GenericAccessRights.ACCESS4
    JOB_IMPERSONATE = GenericAccessRights.ACCESS5
    GENERIC_READ = GenericAccessRights.GENERIC_READ
    GENERIC_WRITE = GenericAccessRights.GENERIC_WRITE
    GENERIC_EXECUTE = GenericAccessRights.GENERIC_EXECUTE
    GENERIC_ALL = GenericAccessRights.GENERIC_ALL
    DELETE = GenericAccessRights.DELETE
    READ_CONTROL = GenericAccessRights.READ_CONTROL
    WRITE_DAC = GenericAccessRights.WRITE_DAC
    WRITE_OWNER = GenericAccessRights.WRITE_OWNER
    SYNCHRONIZE = GenericAccessRights.SYNCHRONIZE
    MAXIMUM_ALLOWED = GenericAccessRights.MAXIMUM_ALLOWED
    ACCESS_SYSTEM_SECURITY = GenericAccessRights.ACCESS_SYSTEM_SECURITY


class KeyAccessRights(IntEnum):
    KEY_QUERY_VALUE = GenericAccessRights.ACCESS0
    KEY_SET_VALUE = GenericAccessRights.ACCESS1
    KEY_CREATE_SUB_KEY = GenericAccessRights.ACCESS2
    KEY_ENUMERATE_SUB_KEYS = GenericAccessRights.ACCESS3
    KEY_NOTIFY = GenericAccessRights.ACCESS4
    KEY_CREATE_LINK = GenericAccessRights.ACCESS5
    GENERIC_READ = GenericAccessRights.GENERIC_READ
    GENERIC_WRITE = GenericAccessRights.GENERIC_WRITE
    GENERIC_EXECUTE = GenericAccessRights.GENERIC_EXECUTE
    GENERIC_ALL = GenericAccessRights.GENERIC_ALL
    DELETE = GenericAccessRights.DELETE
    READ_CONTROL = GenericAccessRights.READ_CONTROL
    WRITE_DAC = GenericAccessRights.WRITE_DAC
    WRITE_OWNER = GenericAccessRights.WRITE_OWNER
    SYNCHRONIZE = GenericAccessRights.SYNCHRONIZE
    MAXIMUM_ALLOWED = GenericAccessRights.MAXIMUM_ALLOWED
    ACCESS_SYSTEM_SECURITY = GenericAccessRights.ACCESS_SYSTEM_SECURITY


class MutantAccessRights(IntEnum):
    MUTANT_MODIFY_STATE = GenericAccessRights.ACCESS0
    GENERIC_READ = GenericAccessRights.GENERIC_READ
    GENERIC_WRITE = GenericAccessRights.GENERIC_WRITE
    GENERIC_EXECUTE = GenericAccessRights.GENERIC_EXECUTE
    GENERIC_ALL = GenericAccessRights.GENERIC_ALL
    DELETE = GenericAccessRights.DELETE
    READ_CONTROL = GenericAccessRights.READ_CONTROL
    WRITE_DAC = GenericAccessRights.WRITE_DAC
    WRITE_OWNER = GenericAccessRights.WRITE_OWNER
    SYNCHRONIZE = GenericAccessRights.SYNCHRONIZE
    MAXIMUM_ALLOWED = GenericAccessRights.MAXIMUM_ALLOWED
    ACCESS_SYSTEM_SECURITY = GenericAccessRights.ACCESS_SYSTEM_SECURITY


class MemoryPartitionAccessRights(IntEnum):
    MEMORY_PARTITION_QUERY_ACCESS = GenericAccessRights.ACCESS0
    MEMORY_PARTITION_MODIFY_ACCESS = GenericAccessRights.ACCESS1
    GENERIC_READ = GenericAccessRights.GENERIC_READ
    GENERIC_WRITE = GenericAccessRights.GENERIC_WRITE
    GENERIC_EXECUTE = GenericAccessRights.GENERIC_EXECUTE
    GENERIC_ALL = GenericAccessRights.GENERIC_ALL
    DELETE = GenericAccessRights.DELETE
    READ_CONTROL = GenericAccessRights.READ_CONTROL
    WRITE_DAC = GenericAccessRights.WRITE_DAC
    WRITE_OWNER = GenericAccessRights.WRITE_OWNER
    SYNCHRONIZE = GenericAccessRights.SYNCHRONIZE
    MAXIMUM_ALLOWED = GenericAccessRights.MAXIMUM_ALLOWED
    ACCESS_SYSTEM_SECURITY = GenericAccessRights.ACCESS_SYSTEM_SECURITY


class ProcessAccessRights(IntEnum):
    PROCESS_TERMINATE = GenericAccessRights.ACCESS0
    PROCESS_CREATE_THREAD = GenericAccessRights.ACCESS1
    PROCESS_SET_SESSIONID = GenericAccessRights.ACCESS2
    PROCESS_VM_OPERATION = GenericAccessRights.ACCESS3
    PROCESS_VM_READ = GenericAccessRights.ACCESS4
    PROCESS_VM_WRITE = GenericAccessRights.ACCESS5
    PROCESS_DUP_HANDLE = GenericAccessRights.ACCESS6
    PROCESS_CREATE_PROCESS = GenericAccessRights.ACCESS7
    PROCESS_SET_QUOTA = GenericAccessRights.ACCESS8
    PROCESS_SET_INFORMATION = GenericAccessRights.ACCESS9
    PROCESS_QUERY_INFORMATION = GenericAccessRights.ACCESS10
    PROCESS_SUSPEND_RESUME = GenericAccessRights.ACCESS11
    PROCESS_QUERY_LIMITED_INFORMATION = GenericAccessRights.ACCESS12
    PROCESS_SET_LIMITED_INFORMATION = GenericAccessRights.ACCESS13
    GENERIC_READ = GenericAccessRights.GENERIC_READ
    GENERIC_WRITE = GenericAccessRights.GENERIC_WRITE
    GENERIC_EXECUTE = GenericAccessRights.GENERIC_EXECUTE
    GENERIC_ALL = GenericAccessRights.GENERIC_ALL
    DELETE = GenericAccessRights.DELETE
    READ_CONTROL = GenericAccessRights.READ_CONTROL
    WRITE_DAC = GenericAccessRights.WRITE_DAC
    WRITE_OWNER = GenericAccessRights.WRITE_OWNER
    SYNCHRONIZE = GenericAccessRights.SYNCHRONIZE
    MAXIMUM_ALLOWED = GenericAccessRights.MAXIMUM_ALLOWED
    ACCESS_SYSTEM_SECURITY = GenericAccessRights.ACCESS_SYSTEM_SECURITY

    AllAccess = (0x1FFFFF,)


class RegistryTransactionAccessRights(IntEnum):
    TRANSACTION_QUERY_INFORMATION = GenericAccessRights.ACCESS0
    TRANSACTION_SET_INFORMATION = GenericAccessRights.ACCESS1
    TRANSACTION_ENLIST = GenericAccessRights.ACCESS2
    TRANSACTION_COMMIT = GenericAccessRights.ACCESS3
    TRANSACTION_ROLLBACK = GenericAccessRights.ACCESS4
    TRANSACTION_PROPAGATE = GenericAccessRights.ACCESS5
    GENERIC_READ = GenericAccessRights.GENERIC_READ
    GENERIC_WRITE = GenericAccessRights.GENERIC_WRITE
    GENERIC_EXECUTE = GenericAccessRights.GENERIC_EXECUTE
    GENERIC_ALL = GenericAccessRights.GENERIC_ALL
    DELETE = GenericAccessRights.DELETE
    READ_CONTROL = GenericAccessRights.READ_CONTROL
    WRITE_DAC = GenericAccessRights.WRITE_DAC
    WRITE_OWNER = GenericAccessRights.WRITE_OWNER
    SYNCHRONIZE = GenericAccessRights.SYNCHRONIZE
    MAXIMUM_ALLOWED = GenericAccessRights.MAXIMUM_ALLOWED
    ACCESS_SYSTEM_SECURITY = GenericAccessRights.ACCESS_SYSTEM_SECURITY


class ResourceManagerAccessRights(IntEnum):
    RESOURCEMANAGER_QUERY_INFORMATION = GenericAccessRights.ACCESS0
    RESOURCEMANAGER_SET_INFORMATION = GenericAccessRights.ACCESS1
    RESOURCEMANAGER_RECOVER = GenericAccessRights.ACCESS2
    RESOURCEMANAGER_ENLIST = GenericAccessRights.ACCESS3
    RESOURCEMANAGER_GET_NOTIFICATION = GenericAccessRights.ACCESS4
    RESOURCEMANAGER_REGISTER_PROTOCOL = GenericAccessRights.ACCESS5
    RESOURCEMANAGER_COMPLETE_PROPAGATION = GenericAccessRights.ACCESS6
    GENERIC_READ = GenericAccessRights.GENERIC_READ
    GENERIC_WRITE = GenericAccessRights.GENERIC_WRITE
    GENERIC_EXECUTE = GenericAccessRights.GENERIC_EXECUTE
    GENERIC_ALL = GenericAccessRights.GENERIC_ALL
    DELETE = GenericAccessRights.DELETE
    READ_CONTROL = GenericAccessRights.READ_CONTROL
    WRITE_DAC = GenericAccessRights.WRITE_DAC
    WRITE_OWNER = GenericAccessRights.WRITE_OWNER
    SYNCHRONIZE = GenericAccessRights.SYNCHRONIZE
    MAXIMUM_ALLOWED = GenericAccessRights.MAXIMUM_ALLOWED
    ACCESS_SYSTEM_SECURITY = GenericAccessRights.ACCESS_SYSTEM_SECURITY


class SectionAccessRights(IntEnum):
    SECTION_QUERY = GenericAccessRights.ACCESS0
    SECTION_MAP_WRITE = GenericAccessRights.ACCESS1
    SECTION_MAP_READ = GenericAccessRights.ACCESS2
    SECTION_MAP_EXECUTE = GenericAccessRights.ACCESS3
    SECTION_EXTEND_SIZE = GenericAccessRights.ACCESS4
    SECTION_MAP_EXECUTE_EXPLICIT = GenericAccessRights.ACCESS5
    GENERIC_READ = GenericAccessRights.GENERIC_READ
    GENERIC_WRITE = GenericAccessRights.GENERIC_WRITE
    GENERIC_EXECUTE = GenericAccessRights.GENERIC_EXECUTE
    GENERIC_ALL = GenericAccessRights.GENERIC_ALL
    DELETE = GenericAccessRights.DELETE
    READ_CONTROL = GenericAccessRights.READ_CONTROL
    WRITE_DAC = GenericAccessRights.WRITE_DAC
    WRITE_OWNER = GenericAccessRights.WRITE_OWNER
    SYNCHRONIZE = GenericAccessRights.SYNCHRONIZE
    MAXIMUM_ALLOWED = GenericAccessRights.MAXIMUM_ALLOWED
    ACCESS_SYSTEM_SECURITY = GenericAccessRights.ACCESS_SYSTEM_SECURITY


class SemaphoreAccessRights(IntEnum):
    SEMAPHORE_QUERY_STATE = GenericAccessRights.ACCESS0
    SEMAPHORE_MODIFY_STATE = GenericAccessRights.ACCESS1
    GENERIC_READ = GenericAccessRights.GENERIC_READ
    GENERIC_WRITE = GenericAccessRights.GENERIC_WRITE
    GENERIC_EXECUTE = GenericAccessRights.GENERIC_EXECUTE
    GENERIC_ALL = GenericAccessRights.GENERIC_ALL
    DELETE = GenericAccessRights.DELETE
    READ_CONTROL = GenericAccessRights.READ_CONTROL
    WRITE_DAC = GenericAccessRights.WRITE_DAC
    WRITE_OWNER = GenericAccessRights.WRITE_OWNER
    SYNCHRONIZE = GenericAccessRights.SYNCHRONIZE
    MAXIMUM_ALLOWED = GenericAccessRights.MAXIMUM_ALLOWED
    ACCESS_SYSTEM_SECURITY = GenericAccessRights.ACCESS_SYSTEM_SECURITY


class SessionAccessRights(IntEnum):
    SESSION_QUERY = GenericAccessRights.ACCESS0
    SESSION_MODIFY = GenericAccessRights.ACCESS1
    GENERIC_READ = GenericAccessRights.GENERIC_READ
    GENERIC_WRITE = GenericAccessRights.GENERIC_WRITE
    GENERIC_EXECUTE = GenericAccessRights.GENERIC_EXECUTE
    GENERIC_ALL = GenericAccessRights.GENERIC_ALL
    DELETE = GenericAccessRights.DELETE
    READ_CONTROL = GenericAccessRights.READ_CONTROL
    WRITE_DAC = GenericAccessRights.WRITE_DAC
    WRITE_OWNER = GenericAccessRights.WRITE_OWNER
    SYNCHRONIZE = GenericAccessRights.SYNCHRONIZE
    MAXIMUM_ALLOWED = GenericAccessRights.MAXIMUM_ALLOWED
    ACCESS_SYSTEM_SECURITY = GenericAccessRights.ACCESS_SYSTEM_SECURITY


class SymbolicLinkAccessRights(IntEnum):
    SYMBOLIC_LINK_QUERY = GenericAccessRights.ACCESS0
    SYMBOLIC_LINK_SET = GenericAccessRights.ACCESS1
    GENERIC_READ = GenericAccessRights.GENERIC_READ
    GENERIC_WRITE = GenericAccessRights.GENERIC_WRITE
    GENERIC_EXECUTE = GenericAccessRights.GENERIC_EXECUTE
    GENERIC_ALL = GenericAccessRights.GENERIC_ALL
    DELETE = GenericAccessRights.DELETE
    READ_CONTROL = GenericAccessRights.READ_CONTROL
    WRITE_DAC = GenericAccessRights.WRITE_DAC
    WRITE_OWNER = GenericAccessRights.WRITE_OWNER
    SYNCHRONIZE = GenericAccessRights.SYNCHRONIZE
    MAXIMUM_ALLOWED = GenericAccessRights.MAXIMUM_ALLOWED
    ACCESS_SYSTEM_SECURITY = GenericAccessRights.ACCESS_SYSTEM_SECURITY


class ThreadAccessRights(IntEnum):
    THREAD_TERMINATE = GenericAccessRights.ACCESS0
    THREAD_SUSPEND_RESUME = GenericAccessRights.ACCESS1
    THREAD_ALERT = GenericAccessRights.ACCESS2
    THREAD_GET_CONTEXT = GenericAccessRights.ACCESS3
    THREAD_SET_CONTEXT = GenericAccessRights.ACCESS4
    THREAD_SET_INFORMATION = GenericAccessRights.ACCESS5
    THREAD_QUERY_INFORMATION = GenericAccessRights.ACCESS6
    THREAD_SET_THREAD_TOKEN = GenericAccessRights.ACCESS7
    THREAD_IMPERSONATE = GenericAccessRights.ACCESS8
    THREAD_DIRECT_IMPERSONATION = GenericAccessRights.ACCESS9
    THREAD_SET_LIMITED_INFORMATION = GenericAccessRights.ACCESS10
    THREAD_QUERY_LIMITED_INFORMATION = GenericAccessRights.ACCESS11
    THREAD_RESUME = GenericAccessRights.ACCESS12
    GENERIC_READ = GenericAccessRights.GENERIC_READ
    GENERIC_WRITE = GenericAccessRights.GENERIC_WRITE
    GENERIC_EXECUTE = GenericAccessRights.GENERIC_EXECUTE
    GENERIC_ALL = GenericAccessRights.GENERIC_ALL
    DELETE = GenericAccessRights.DELETE
    READ_CONTROL = GenericAccessRights.READ_CONTROL
    WRITE_DAC = GenericAccessRights.WRITE_DAC
    WRITE_OWNER = GenericAccessRights.WRITE_OWNER
    SYNCHRONIZE = GenericAccessRights.SYNCHRONIZE
    MAXIMUM_ALLOWED = GenericAccessRights.MAXIMUM_ALLOWED
    ACCESS_SYSTEM_SECURITY = GenericAccessRights.ACCESS_SYSTEM_SECURITY
    THREAD_ALL_ACCESS = 0x1FFFFF


class TimerAccessRights(IntEnum):
    TIMER_QUERY_STATE = GenericAccessRights.ACCESS0
    TIMER_SET_STATE = GenericAccessRights.ACCESS1
    GENERIC_READ = GenericAccessRights.GENERIC_READ
    GENERIC_WRITE = GenericAccessRights.GENERIC_WRITE
    GENERIC_EXECUTE = GenericAccessRights.GENERIC_EXECUTE
    GENERIC_ALL = GenericAccessRights.GENERIC_ALL
    DELETE = GenericAccessRights.DELETE
    READ_CONTROL = GenericAccessRights.READ_CONTROL
    WRITE_DAC = GenericAccessRights.WRITE_DAC
    WRITE_OWNER = GenericAccessRights.WRITE_OWNER
    SYNCHRONIZE = GenericAccessRights.SYNCHRONIZE
    MAXIMUM_ALLOWED = GenericAccessRights.MAXIMUM_ALLOWED
    ACCESS_SYSTEM_SECURITY = GenericAccessRights.ACCESS_SYSTEM_SECURITY


class TokenAccessRights(IntEnum):
    TOKEN_ASSIGN_PRIMARY = GenericAccessRights.ACCESS0
    TOKEN_DUPLICATE = GenericAccessRights.ACCESS1
    TOKEN_IMPERSONATE = GenericAccessRights.ACCESS2
    TOKEN_QUERY = GenericAccessRights.ACCESS3
    TOKEN_QUERY_SOURCE = GenericAccessRights.ACCESS4
    TOKEN_ADJUST_PRIVILEGES = GenericAccessRights.ACCESS5
    TOKEN_ADJUST_GROUPS = GenericAccessRights.ACCESS6
    TOKEN_ADJUST_DEFAULT = GenericAccessRights.ACCESS7
    TOKEN_ADJUST_SESSIONID = GenericAccessRights.ACCESS8
    GENERIC_READ = GenericAccessRights.GENERIC_READ
    GENERIC_WRITE = GenericAccessRights.GENERIC_WRITE
    GENERIC_EXECUTE = GenericAccessRights.GENERIC_EXECUTE
    GENERIC_ALL = GenericAccessRights.GENERIC_ALL
    DELETE = GenericAccessRights.DELETE
    READ_CONTROL = GenericAccessRights.READ_CONTROL
    WRITE_DAC = GenericAccessRights.WRITE_DAC
    WRITE_OWNER = GenericAccessRights.WRITE_OWNER
    SYNCHRONIZE = GenericAccessRights.SYNCHRONIZE
    MAXIMUM_ALLOWED = GenericAccessRights.MAXIMUM_ALLOWED
    ACCESS_SYSTEM_SECURITY = GenericAccessRights.ACCESS_SYSTEM_SECURITY


class TraceAccessRights(IntEnum):
    WMIGUID_QUERY = GenericAccessRights.ACCESS0
    WMIGUID_SET = GenericAccessRights.ACCESS1
    WMIGUID_NOTIFICATION = GenericAccessRights.ACCESS2
    WMIGUID_READ_DESCRIPTION = GenericAccessRights.ACCESS3
    WMIGUID_EXECUTE = GenericAccessRights.ACCESS4
    TRACELOG_CREATE_REALTIME = GenericAccessRights.ACCESS5
    TRACELOG_CREATE_ONDISK = GenericAccessRights.ACCESS6
    TRACELOG_GUID_ENABLE = GenericAccessRights.ACCESS7
    TRACELOG_ACCESS_KERNEL_LOGGER = GenericAccessRights.ACCESS8
    TRACELOG_LOG_EVENT = GenericAccessRights.ACCESS9
    TRACELOG_ACCESS_REALTIME = GenericAccessRights.ACCESS10
    TRACELOG_REGISTER_GUIDS = GenericAccessRights.ACCESS11
    TRACELOG_JOIN_GROUP = GenericAccessRights.ACCESS12
    GENERIC_READ = GenericAccessRights.GENERIC_READ
    GENERIC_WRITE = GenericAccessRights.GENERIC_WRITE
    GENERIC_EXECUTE = GenericAccessRights.GENERIC_EXECUTE
    GENERIC_ALL = GenericAccessRights.GENERIC_ALL
    DELETE = GenericAccessRights.DELETE
    READ_CONTROL = GenericAccessRights.READ_CONTROL
    WRITE_DAC = GenericAccessRights.WRITE_DAC
    WRITE_OWNER = GenericAccessRights.WRITE_OWNER
    SYNCHRONIZE = GenericAccessRights.SYNCHRONIZE
    MAXIMUM_ALLOWED = GenericAccessRights.MAXIMUM_ALLOWED
    ACCESS_SYSTEM_SECURITY = GenericAccessRights.ACCESS_SYSTEM_SECURITY


class TransactionManagerAccessRights(IntEnum):
    TRANSACTIONMANAGER_QUERY_INFORMATION = GenericAccessRights.ACCESS0
    TRANSACTIONMANAGER_SET_INFORMATION = GenericAccessRights.ACCESS1
    TRANSACTIONMANAGER_RECOVER = GenericAccessRights.ACCESS2
    TRANSACTIONMANAGER_RENAME = GenericAccessRights.ACCESS3
    TRANSACTIONMANAGER_CREATE_RM = GenericAccessRights.ACCESS4
    TRANSACTIONMANAGER_BIND_TRANSACTION = GenericAccessRights.ACCESS5
    GENERIC_READ = GenericAccessRights.GENERIC_READ
    GENERIC_WRITE = GenericAccessRights.GENERIC_WRITE
    GENERIC_EXECUTE = GenericAccessRights.GENERIC_EXECUTE
    GENERIC_ALL = GenericAccessRights.GENERIC_ALL
    DELETE = GenericAccessRights.DELETE
    READ_CONTROL = GenericAccessRights.READ_CONTROL
    WRITE_DAC = GenericAccessRights.WRITE_DAC
    WRITE_OWNER = GenericAccessRights.WRITE_OWNER
    SYNCHRONIZE = GenericAccessRights.SYNCHRONIZE
    MAXIMUM_ALLOWED = GenericAccessRights.MAXIMUM_ALLOWED
    ACCESS_SYSTEM_SECURITY = GenericAccessRights.ACCESS_SYSTEM_SECURITY


class TransactionAccessRights(IntEnum):
    TRANSACTION_QUERY_INFORMATION = GenericAccessRights.ACCESS0
    TRANSACTION_SET_INFORMATION = GenericAccessRights.ACCESS1
    TRANSACTION_ENLIST = GenericAccessRights.ACCESS2
    TRANSACTION_COMMIT = GenericAccessRights.ACCESS3
    TRANSACTION_ROLLBACK = GenericAccessRights.ACCESS4
    TRANSACTION_PROPAGATE = GenericAccessRights.ACCESS5
    TRANSACTION_RIGHT_RESERVED1 = GenericAccessRights.ACCESS6
    GENERIC_READ = GenericAccessRights.GENERIC_READ
    GENERIC_WRITE = GenericAccessRights.GENERIC_WRITE
    GENERIC_EXECUTE = GenericAccessRights.GENERIC_EXECUTE
    GENERIC_ALL = GenericAccessRights.GENERIC_ALL
    DELETE = GenericAccessRights.DELETE
    READ_CONTROL = GenericAccessRights.READ_CONTROL
    WRITE_DAC = GenericAccessRights.WRITE_DAC
    WRITE_OWNER = GenericAccessRights.WRITE_OWNER
    SYNCHRONIZE = GenericAccessRights.SYNCHRONIZE
    MAXIMUM_ALLOWED = GenericAccessRights.MAXIMUM_ALLOWED
    ACCESS_SYSTEM_SECURITY = GenericAccessRights.ACCESS_SYSTEM_SECURITY


class WindowStationAccessRights(IntEnum):
    WINSTA_ENUMDESKTOPS = GenericAccessRights.ACCESS0
    WINSTA_READATTRIBUTES = GenericAccessRights.ACCESS1
    WINSTA_ACCESSCLIPBOARD = GenericAccessRights.ACCESS2
    WINSTA_CREATEDESKTOP = GenericAccessRights.ACCESS3
    WINSTA_WRITEATTRIBUTES = GenericAccessRights.ACCESS4
    WINSTA_ACCESSGLOBALATOMS = GenericAccessRights.ACCESS5
    WINSTA_EXITWINDOWS = GenericAccessRights.ACCESS6
    WINSTA_ENUMERATE = GenericAccessRights.ACCESS8
    WINSTA_READSCREEN = GenericAccessRights.ACCESS9
    GENERIC_READ = GenericAccessRights.GENERIC_READ
    GENERIC_WRITE = GenericAccessRights.GENERIC_WRITE
    GENERIC_EXECUTE = GenericAccessRights.GENERIC_EXECUTE
    GENERIC_ALL = GenericAccessRights.GENERIC_ALL
    DELETE = GenericAccessRights.DELETE
    READ_CONTROL = GenericAccessRights.READ_CONTROL
    WRITE_DAC = GenericAccessRights.WRITE_DAC
    WRITE_OWNER = GenericAccessRights.WRITE_OWNER
    SYNCHRONIZE = GenericAccessRights.SYNCHRONIZE
    MAXIMUM_ALLOWED = GenericAccessRights.MAXIMUM_ALLOWED
    ACCESS_SYSTEM_SECURITY = GenericAccessRights.ACCESS_SYSTEM_SECURITY


class WnfAccessRights(IntEnum):
    WNF_READ_DATA = GenericAccessRights.ACCESS0
    WNF_WRITE_DATA = GenericAccessRights.ACCESS1
    WNF_UNKNOWN_10 = GenericAccessRights.ACCESS4
    GENERIC_READ = GenericAccessRights.GENERIC_READ
    GENERIC_WRITE = GenericAccessRights.GENERIC_WRITE
    GENERIC_EXECUTE = GenericAccessRights.GENERIC_EXECUTE
    GENERIC_ALL = GenericAccessRights.GENERIC_ALL
    DELETE = GenericAccessRights.DELETE
    READ_CONTROL = GenericAccessRights.READ_CONTROL
    WRITE_DAC = GenericAccessRights.WRITE_DAC
    WRITE_OWNER = GenericAccessRights.WRITE_OWNER
    SYNCHRONIZE = GenericAccessRights.SYNCHRONIZE
    MAXIMUM_ALLOWED = GenericAccessRights.MAXIMUM_ALLOWED
    ACCESS_SYSTEM_SECURITY = GenericAccessRights.ACCESS_SYSTEM_SECURITY


class FirewallAccessRights(IntEnum):
    FWPM_ACTRL_ADD = GenericAccessRights.ACCESS0
    FWPM_ACTRL_ADD_LINK = GenericAccessRights.ACCESS1
    FWPM_ACTRL_BEGIN_READ_TXN = GenericAccessRights.ACCESS2
    FWPM_ACTRL_BEGIN_WRITE_TXN = GenericAccessRights.ACCESS3
    FWPM_ACTRL_CLASSIFY = GenericAccessRights.ACCESS4
    FWPM_ACTRL_ENUM = GenericAccessRights.ACCESS5
    FWPM_ACTRL_OPEN = GenericAccessRights.ACCESS6
    FWPM_ACTRL_READ = GenericAccessRights.ACCESS7
    FWPM_ACTRL_READ_STATS = GenericAccessRights.ACCESS8
    FWPM_ACTRL_SUBSCRIBE = GenericAccessRights.ACCESS9
    FWPM_ACTRL_WRITE = GenericAccessRights.ACCESS10
    GENERIC_READ = GenericAccessRights.GENERIC_READ
    GENERIC_WRITE = GenericAccessRights.GENERIC_WRITE
    GENERIC_EXECUTE = GenericAccessRights.GENERIC_EXECUTE
    GENERIC_ALL = GenericAccessRights.GENERIC_ALL
    DELETE = GenericAccessRights.DELETE
    READ_CONTROL = GenericAccessRights.READ_CONTROL
    WRITE_DAC = GenericAccessRights.WRITE_DAC
    WRITE_OWNER = GenericAccessRights.WRITE_OWNER
    MAXIMUM_ALLOWED = GenericAccessRights.MAXIMUM_ALLOWED
    ACCESS_SYSTEM_SECURITY = GenericAccessRights.ACCESS_SYSTEM_SECURITY


class FirewallFilterAccessRights(IntEnum):
    FWP_ACTRL_MATCH_FILTER = GenericAccessRights.ACCESS0
    GENERIC_READ = GenericAccessRights.GENERIC_READ
    GENERIC_WRITE = GenericAccessRights.GENERIC_WRITE
    GENERIC_EXECUTE = GenericAccessRights.GENERIC_EXECUTE
    GENERIC_ALL = GenericAccessRights.GENERIC_ALL
    DELETE = GenericAccessRights.DELETE
    READ_CONTROL = GenericAccessRights.READ_CONTROL
    WRITE_DAC = GenericAccessRights.WRITE_DAC
    WRITE_OWNER = GenericAccessRights.WRITE_OWNER
    MAXIMUM_ALLOWED = GenericAccessRights.MAXIMUM_ALLOWED
    ACCESS_SYSTEM_SECURITY = GenericAccessRights.ACCESS_SYSTEM_SECURITY


class DirectoryServiceAccessRights(IntEnum):
    ACTRL_DS_CREATE_CHILD = GenericAccessRights.ACCESS0
    ACTRL_DS_DELETE_CHILD = GenericAccessRights.ACCESS1
    ACTRL_DS_LIST = GenericAccessRights.ACCESS2
    ACTRL_DS_SELF = GenericAccessRights.ACCESS3
    ACTRL_DS_READ_PROP = GenericAccessRights.ACCESS4
    ACTRL_DS_WRITE_PROP = GenericAccessRights.ACCESS5
    ACTRL_DS_DELETE_TREE = GenericAccessRights.ACCESS6
    ACTRL_DS_LIST_OBJECT = GenericAccessRights.ACCESS7
    ACTRL_DS_CONTROL_ACCESS = GenericAccessRights.ACCESS8
    GENERIC_READ = GenericAccessRights.GENERIC_READ
    GENERIC_WRITE = GenericAccessRights.GENERIC_WRITE
    GENERIC_EXECUTE = GenericAccessRights.GENERIC_EXECUTE
    GENERIC_ALL = GenericAccessRights.GENERIC_ALL
    DELETE = GenericAccessRights.DELETE
    READ_CONTROL = GenericAccessRights.READ_CONTROL
    WRITE_DAC = GenericAccessRights.WRITE_DAC
    WRITE_OWNER = GenericAccessRights.WRITE_OWNER
    MAXIMUM_ALLOWED = GenericAccessRights.MAXIMUM_ALLOWED
    ACCESS_SYSTEM_SECURITY = GenericAccessRights.ACCESS_SYSTEM_SECURITY
    ACTRL_DS_ALL_ACCESS = (
        WRITE_OWNER
        | WRITE_DAC
        | READ_CONTROL
        | DELETE
        | ACTRL_DS_CONTROL_ACCESS
        | ACTRL_DS_LIST_OBJECT
        | ACTRL_DS_DELETE_TREE
        | ACTRL_DS_WRITE_PROP
        | ACTRL_DS_READ_PROP
        | ACTRL_DS_SELF
        | ACTRL_DS_LIST
        | ACTRL_DS_CREATE_CHILD
        | ACTRL_DS_DELETE_CHILD
    )


class PrintSpoolerAccessRights(IntEnum):
    SERVER_ACCESS_ADMINISTER = GenericAccessRights.ACCESS0
    SERVER_ACCESS_ENUMERATE = GenericAccessRights.ACCESS1
    PRINTER_ACCESS_ADMINISTER = GenericAccessRights.ACCESS2
    PRINTER_ACCESS_USE = GenericAccessRights.ACCESS3
    JOB_ACCESS_ADMINISTER = GenericAccessRights.ACCESS4
    JOB_ACCESS_READ = GenericAccessRights.ACCESS5
    PRINTER_ACCESS_MANAGE_LIMITED = GenericAccessRights.ACCESS6
    GENERIC_READ = GenericAccessRights.GENERIC_READ
    GENERIC_WRITE = GenericAccessRights.GENERIC_WRITE
    GENERIC_EXECUTE = GenericAccessRights.GENERIC_EXECUTE
    GENERIC_ALL = GenericAccessRights.GENERIC_ALL
    DELETE = GenericAccessRights.DELETE
    READ_CONTROL = GenericAccessRights.READ_CONTROL
    WRITE_DAC = GenericAccessRights.WRITE_DAC
    WRITE_OWNER = GenericAccessRights.WRITE_OWNER
    MAXIMUM_ALLOWED = GenericAccessRights.MAXIMUM_ALLOWED
    ACCESS_SYSTEM_SECURITY = GenericAccessRights.ACCESS_SYSTEM_SECURITY


class AuditAccessRights(IntEnum):
    AUDIT_SET_SYSTEM_POLICY = GenericAccessRights.ACCESS0
    AUDIT_QUERY_SYSTEM_POLICY = GenericAccessRights.ACCESS1
    AUDIT_SET_USER_POLICY = GenericAccessRights.ACCESS2
    AUDIT_QUERY_USER_POLICY = GenericAccessRights.ACCESS3
    AUDIT_ENUMERATE_USERS = GenericAccessRights.ACCESS4
    AUDIT_SET_MISC_POLICY = GenericAccessRights.ACCESS5
    AUDIT_QUERY_MISC_POLICY = GenericAccessRights.ACCESS6
    GENERIC_READ = GenericAccessRights.GENERIC_READ
    GENERIC_WRITE = GenericAccessRights.GENERIC_WRITE
    GENERIC_EXECUTE = GenericAccessRights.GENERIC_EXECUTE
    GENERIC_ALL = GenericAccessRights.GENERIC_ALL
    DELETE = GenericAccessRights.DELETE
    READ_CONTROL = GenericAccessRights.READ_CONTROL
    WRITE_DAC = GenericAccessRights.WRITE_DAC
    WRITE_OWNER = GenericAccessRights.WRITE_OWNER
    SYNCHRONIZE = GenericAccessRights.SYNCHRONIZE
    MAXIMUM_ALLOWED = GenericAccessRights.MAXIMUM_ALLOWED
    ACCESS_SYSTEM_SECURITY = GenericAccessRights.ACCESS_SYSTEM_SECURITY
    AUDIT_ALL_ACCESS = (
        WRITE_OWNER
        | WRITE_DAC
        | READ_CONTROL
        | DELETE
        | AUDIT_SET_SYSTEM_POLICY
        | AUDIT_QUERY_SYSTEM_POLICY
        | AUDIT_SET_USER_POLICY
        | AUDIT_QUERY_USER_POLICY
        | AUDIT_ENUMERATE_USERS
        | AUDIT_SET_MISC_POLICY
        | AUDIT_QUERY_MISC_POLICY
    )


class LsaAccountAccessRights(IntEnum):
    ACCOUNT_VIEW = GenericAccessRights.ACCESS0
    ACCOUNT_ADJUST_PRIVILEGES = GenericAccessRights.ACCESS1
    ACCOUNT_ADJUST_QUOTAS = GenericAccessRights.ACCESS2
    ACCOUNT_ADJUST_SYSTEM_ACCESS = GenericAccessRights.ACCESS3
    GENERIC_READ = GenericAccessRights.GENERIC_READ
    GENERIC_WRITE = GenericAccessRights.GENERIC_WRITE
    GENERIC_EXECUTE = GenericAccessRights.GENERIC_EXECUTE
    GENERIC_ALL = GenericAccessRights.GENERIC_ALL
    DELETE = GenericAccessRights.DELETE
    READ_CONTROL = GenericAccessRights.READ_CONTROL
    WRITE_DAC = GenericAccessRights.WRITE_DAC
    WRITE_OWNER = GenericAccessRights.WRITE_OWNER
    MAXIMUM_ALLOWED = GenericAccessRights.MAXIMUM_ALLOWED
    ACCESS_SYSTEM_SECURITY = GenericAccessRights.ACCESS_SYSTEM_SECURITY


class LsaPolicyAccessRights(IntEnum):
    POLICY_VIEW_LOCAL_INFORMATION = GenericAccessRights.ACCESS0
    POLICY_VIEW_AUDIT_INFORMATION = GenericAccessRights.ACCESS1
    POLICY_GET_PRIVATE_INFORMATION = GenericAccessRights.ACCESS2
    POLICY_TRUST_ADMIN = GenericAccessRights.ACCESS3
    POLICY_CREATE_ACCOUNT = GenericAccessRights.ACCESS4
    POLICY_CREATE_SECRET = GenericAccessRights.ACCESS5
    POLICY_CREATE_PRIVILEGE = GenericAccessRights.ACCESS6
    POLICY_SET_DEFAULT_QUOTA_LIMITS = GenericAccessRights.ACCESS7
    POLICY_SET_AUDIT_REQUIREMENTS = GenericAccessRights.ACCESS8
    POLICY_AUDIT_LOG_ADMIN = GenericAccessRights.ACCESS9
    POLICY_SERVER_ADMIN = GenericAccessRights.ACCESS10
    POLICY_LOOKUP_NAMES = GenericAccessRights.ACCESS11
    POLICY_NOTIFICATION = GenericAccessRights.ACCESS12
    GENERIC_READ = GenericAccessRights.GENERIC_READ
    GENERIC_WRITE = GenericAccessRights.GENERIC_WRITE
    GENERIC_EXECUTE = GenericAccessRights.GENERIC_EXECUTE
    GENERIC_ALL = GenericAccessRights.GENERIC_ALL
    DELETE = GenericAccessRights.DELETE
    READ_CONTROL = GenericAccessRights.READ_CONTROL
    WRITE_DAC = GenericAccessRights.WRITE_DAC
    WRITE_OWNER = GenericAccessRights.WRITE_OWNER
    MAXIMUM_ALLOWED = GenericAccessRights.MAXIMUM_ALLOWED
    ACCESS_SYSTEM_SECURITY = GenericAccessRights.ACCESS_SYSTEM_SECURITY


class LsaSecretAccessRights(IntEnum):
    SECRET_SET_VALUE = GenericAccessRights.ACCESS0
    SECRET_QUERY_VALUE = GenericAccessRights.ACCESS1
    GENERIC_READ = GenericAccessRights.GENERIC_READ
    GENERIC_WRITE = GenericAccessRights.GENERIC_WRITE
    GENERIC_EXECUTE = GenericAccessRights.GENERIC_EXECUTE
    GENERIC_ALL = GenericAccessRights.GENERIC_ALL
    DELETE = GenericAccessRights.DELETE
    READ_CONTROL = GenericAccessRights.READ_CONTROL
    WRITE_DAC = GenericAccessRights.WRITE_DAC
    WRITE_OWNER = GenericAccessRights.WRITE_OWNER
    MAXIMUM_ALLOWED = GenericAccessRights.MAXIMUM_ALLOWED
    ACCESS_SYSTEM_SECURITY = GenericAccessRights.ACCESS_SYSTEM_SECURITY


class LsaTrustedDomainAccessRights(IntEnum):
    TRUSTED_QUERY_DOMAIN_NAME = GenericAccessRights.ACCESS0
    TRUSTED_QUERY_CONTROLLERS = GenericAccessRights.ACCESS1
    TRUSTED_SET_CONTROLLERS = GenericAccessRights.ACCESS2
    TRUSTED_QUERY_POSIX = GenericAccessRights.ACCESS3
    TRUSTED_SET_POSIX = GenericAccessRights.ACCESS4
    TRUSTED_SET_AUTH = GenericAccessRights.ACCESS5
    TRUSTED_QUERY_AUTH = GenericAccessRights.ACCESS6
    GENERIC_READ = GenericAccessRights.GENERIC_READ
    GENERIC_WRITE = GenericAccessRights.GENERIC_WRITE
    GENERIC_EXECUTE = GenericAccessRights.GENERIC_EXECUTE
    GENERIC_ALL = GenericAccessRights.GENERIC_ALL
    DELETE = GenericAccessRights.DELETE
    READ_CONTROL = GenericAccessRights.READ_CONTROL
    WRITE_DAC = GenericAccessRights.WRITE_DAC
    WRITE_OWNER = GenericAccessRights.WRITE_OWNER
    MAXIMUM_ALLOWED = GenericAccessRights.MAXIMUM_ALLOWED
    ACCESS_SYSTEM_SECURITY = GenericAccessRights.ACCESS_SYSTEM_SECURITY


class SamAliasAccessRights(IntEnum):
    ALIAS_ADD_MEMBER = GenericAccessRights.ACCESS0
    ALIAS_REMOVE_MEMBER = GenericAccessRights.ACCESS1
    ALIAS_LIST_MEMBERS = GenericAccessRights.ACCESS2
    ALIAS_READ_INFORMATION = GenericAccessRights.ACCESS3
    ALIAS_WRITE_ACCOUNT = GenericAccessRights.ACCESS4
    GENERIC_READ = GenericAccessRights.GENERIC_READ
    GENERIC_WRITE = GenericAccessRights.GENERIC_WRITE
    GENERIC_EXECUTE = GenericAccessRights.GENERIC_EXECUTE
    GENERIC_ALL = GenericAccessRights.GENERIC_ALL
    DELETE = GenericAccessRights.DELETE
    READ_CONTROL = GenericAccessRights.READ_CONTROL
    WRITE_DAC = GenericAccessRights.WRITE_DAC
    WRITE_OWNER = GenericAccessRights.WRITE_OWNER
    MAXIMUM_ALLOWED = GenericAccessRights.MAXIMUM_ALLOWED
    ACCESS_SYSTEM_SECURITY = GenericAccessRights.ACCESS_SYSTEM_SECURITY


class SamDomainAccessRights(IntEnum):
    DOMAIN_READ_PASSWORD_PARAMETERS = GenericAccessRights.ACCESS0
    DOMAIN_WRITE_PASSWORD_PARAMS = GenericAccessRights.ACCESS1
    DOMAIN_READ_OTHER_PARAMETERS = GenericAccessRights.ACCESS2
    DOMAIN_WRITE_OTHER_PARAMETERS = GenericAccessRights.ACCESS3
    DOMAIN_CREATE_USER = GenericAccessRights.ACCESS4
    DOMAIN_CREATE_GROUP = GenericAccessRights.ACCESS5
    DOMAIN_CREATE_ALIAS = GenericAccessRights.ACCESS6
    DOMAIN_GET_ALIAS_MEMBERSHIP = GenericAccessRights.ACCESS7
    DOMAIN_LIST_ACCOUNTS = GenericAccessRights.ACCESS8
    DOMAIN_LOOKUP = GenericAccessRights.ACCESS9
    DOMAIN_ADMINISTER_SERVER = GenericAccessRights.ACCESS10
    GENERIC_READ = GenericAccessRights.GENERIC_READ
    GENERIC_WRITE = GenericAccessRights.GENERIC_WRITE
    GENERIC_EXECUTE = GenericAccessRights.GENERIC_EXECUTE
    GENERIC_ALL = GenericAccessRights.GENERIC_ALL
    DELETE = GenericAccessRights.DELETE
    READ_CONTROL = GenericAccessRights.READ_CONTROL
    WRITE_DAC = GenericAccessRights.WRITE_DAC
    WRITE_OWNER = GenericAccessRights.WRITE_OWNER
    MAXIMUM_ALLOWED = GenericAccessRights.MAXIMUM_ALLOWED
    ACCESS_SYSTEM_SECURITY = GenericAccessRights.ACCESS_SYSTEM_SECURITY


class SamGroupAccessRights(IntEnum):
    GROUP_READ_INFORMATION = GenericAccessRights.ACCESS0
    GROUP_WRITE_ACCOUNT = GenericAccessRights.ACCESS1
    GROUP_ADD_MEMBER = GenericAccessRights.ACCESS2
    GROUP_REMOVE_MEMBER = GenericAccessRights.ACCESS3
    GROUP_LIST_MEMBERS = GenericAccessRights.ACCESS4
    GENERIC_READ = GenericAccessRights.GENERIC_READ
    GENERIC_WRITE = GenericAccessRights.GENERIC_WRITE
    GENERIC_EXECUTE = GenericAccessRights.GENERIC_EXECUTE
    GENERIC_ALL = GenericAccessRights.GENERIC_ALL
    DELETE = GenericAccessRights.DELETE
    READ_CONTROL = GenericAccessRights.READ_CONTROL
    WRITE_DAC = GenericAccessRights.WRITE_DAC
    WRITE_OWNER = GenericAccessRights.WRITE_OWNER
    MAXIMUM_ALLOWED = GenericAccessRights.MAXIMUM_ALLOWED
    ACCESS_SYSTEM_SECURITY = GenericAccessRights.ACCESS_SYSTEM_SECURITY


class SamServerAccessRights(IntEnum):
    SAM_SERVER_CONNECT = GenericAccessRights.ACCESS0
    SAM_SERVER_SHUTDOWN = GenericAccessRights.ACCESS1
    SAM_SERVER_INITIALIZE = GenericAccessRights.ACCESS2
    SAM_SERVER_CREATE_DOMAIN = GenericAccessRights.ACCESS3
    SAM_SERVER_ENUMERATE_DOMAINS = GenericAccessRights.ACCESS4
    SAM_SERVER_LOOKUP_DOMAIN = GenericAccessRights.ACCESS5
    GENERIC_READ = GenericAccessRights.GENERIC_READ
    GENERIC_WRITE = GenericAccessRights.GENERIC_WRITE
    GENERIC_EXECUTE = GenericAccessRights.GENERIC_EXECUTE
    GENERIC_ALL = GenericAccessRights.GENERIC_ALL
    DELETE = GenericAccessRights.DELETE
    READ_CONTROL = GenericAccessRights.READ_CONTROL
    WRITE_DAC = GenericAccessRights.WRITE_DAC
    WRITE_OWNER = GenericAccessRights.WRITE_OWNER
    MAXIMUM_ALLOWED = GenericAccessRights.MAXIMUM_ALLOWED
    ACCESS_SYSTEM_SECURITY = GenericAccessRights.ACCESS_SYSTEM_SECURITY


class SamUserAccessRights(IntEnum):
    USER_READ_GENERAL = GenericAccessRights.ACCESS0
    USER_READ_PREFERENCES = GenericAccessRights.ACCESS1
    USER_WRITE_PREFERENCES = GenericAccessRights.ACCESS2
    USER_READ_LOGON = GenericAccessRights.ACCESS3
    USER_READ_ACCOUNT = GenericAccessRights.ACCESS4
    USER_WRITE_ACCOUNT = GenericAccessRights.ACCESS5
    USER_CHANGE_PASSWORD = GenericAccessRights.ACCESS6
    USER_FORCE_PASSWORD_CHANGE = GenericAccessRights.ACCESS7
    USER_LIST_GROUPS = GenericAccessRights.ACCESS8
    USER_READ_GROUP_INFORMATION = GenericAccessRights.ACCESS9
    USER_WRITE_GROUP_INFORMATION = GenericAccessRights.ACCESS10
    GENERIC_READ = GenericAccessRights.GENERIC_READ
    GENERIC_WRITE = GenericAccessRights.GENERIC_WRITE
    GENERIC_EXECUTE = GenericAccessRights.GENERIC_EXECUTE
    GENERIC_ALL = GenericAccessRights.GENERIC_ALL
    DELETE = GenericAccessRights.DELETE
    READ_CONTROL = GenericAccessRights.READ_CONTROL
    WRITE_DAC = GenericAccessRights.WRITE_DAC
    WRITE_OWNER = GenericAccessRights.WRITE_OWNER
    MAXIMUM_ALLOWED = GenericAccessRights.MAXIMUM_ALLOWED
    ACCESS_SYSTEM_SECURITY = GenericAccessRights.ACCESS_SYSTEM_SECURITY


# TODO: Maybe when I get bored one day, I'll make a class for subclassing enums. Why isn't that implemented already? Probably a good reason

AllRightsT = (
    AlpcAccessRights
    | AuditAccessRights
    | DebugAccessRights
    | DesktopAccessRights
    | DirectoryAccessRights
    | DirectoryServiceAccessRights
    | EnlistmentAccessRights
    | EventAccessRights
    | FileAccessRights
    | FileDirectoryAccessRights
    | FilterConnectionPortAccessRights
    | FirewallAccessRights
    | FirewallFilterAccessRights
    | GenericAccessRights
    | IoCompletionAccessRights
    | JobAccessRights
    | KeyAccessRights
    | LsaAccountAccessRights
    | LsaPolicyAccessRights
    | LsaSecretAccessRights
    | LsaTrustedDomainAccessRights
    | MemoryPartitionAccessRights
    | MutantAccessRights
    | PrintSpoolerAccessRights
    | ProcessAccessRights
    | RegistryKeyAccessRights
    | RegistryTransactionAccessRights
    | ResourceManagerAccessRights
    | SamAliasAccessRights
    | SamDomainAccessRights
    | SamGroupAccessRights
    | SamServerAccessRights
    | SamUserAccessRights
    | SemaphoreAccessRights
    | ServiceAccessRights
    | ServiceControlManagerAccessRights
    | SessionAccessRights
    | SymbolicLinkAccessRights
    | ThreadAccessRights
    | TimerAccessRights
    | TokenAccessRights
    | TraceAccessRights
    | TransactionAccessRights
    | TransactionManagerAccessRights
    | WindowStationAccessRights
    | WnfAccessRights
)
