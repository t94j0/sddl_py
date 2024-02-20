from enum import IntEnum


class GenericAccessRights(IntEnum):
    """
    Name comes from sddl.h
    """

    CREATE_CHILD = 0x1
    DELETE_CHILD = 0x2
    LIST_CHILDREN = 0x4
    SELF_WRITE = 0x8
    READ_PROPERTY = 0x10
    WRITE_PROPERTY = 0x20
    DELETE_TREE = 0x40
    LIST_OBJECT = 0x80
    CONTROL_ACCESS = 0x100
    ACCESS9 = 0x200
    ACCESS10 = 0x400
    ACCESS11 = 0x800
    ACCESS12 = 0x1000
    ACCESS13 = 0x2000
    ACCESS14 = 0x4000
    ACCESS15 = 0x8000
    STANDARD_DELETE = 0x10000
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
    STANDARD_RIGHTS_ALL = (
        STANDARD_DELETE | READ_CONTROL | WRITE_DAC | WRITE_OWNER | SYNCHRONIZE
    )
    STANDARD_RIGHTS_EXECUTE = READ_CONTROL
    STANDARD_RIGHTS_READ = READ_CONTROL
    STANDARD_RIGHTS_REQUIRED = STANDARD_DELETE | READ_CONTROL | WRITE_DAC | WRITE_OWNER
    STANDARD_RIGHTS_WRITE = READ_CONTROL


class ServiceControlManagerAccessRights(IntEnum):
    """
    https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/0d7a7011-9f41-470d-ad52-8535b47ac282
    """

    SC_MANAGER_CONNECT = GenericAccessRights.CREATE_CHILD
    SC_MANAGER_CREATE_SERVICE = GenericAccessRights.DELETE_CHILD
    SC_MANAGER_ENUMERATE_SERVICE = GenericAccessRights.LIST_CHILDREN
    SC_MANAGER_LOCK = GenericAccessRights.SELF_WRITE
    SC_MANAGER_QUERY_LOCK_STATUS = GenericAccessRights.READ_PROPERTY
    SC_MANAGER_MODIFY_BOOT_CONFIG = GenericAccessRights.WRITE_PROPERTY
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
    DELETE = GenericAccessRights.STANDARD_DELETE
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

    SERVICE_QUERY_CONFIG = GenericAccessRights.CREATE_CHILD
    SERVICE_CHANGE_CONFIG = GenericAccessRights.DELETE_CHILD
    SERVICE_QUERY_STATUS = GenericAccessRights.LIST_CHILDREN
    SERVICE_ENUMERATE_DEPENDENTS = GenericAccessRights.SELF_WRITE
    SERVICE_START = GenericAccessRights.READ_PROPERTY
    SERVICE_STOP = GenericAccessRights.WRITE_PROPERTY
    SERVICE_PAUSE_CONTINUE = GenericAccessRights.DELETE_TREE
    SERVICE_INTERROGATE = GenericAccessRights.LIST_OBJECT
    SERVICE_USER_DEFINED_CONTROL = GenericAccessRights.CONTROL_ACCESS
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
    DELETE = GenericAccessRights.STANDARD_DELETE
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

    FILE_READ_DATA = GenericAccessRights.CREATE_CHILD
    FILE_WRITE_DATA = GenericAccessRights.DELETE_CHILD
    FILE_APPEND_DATA = GenericAccessRights.LIST_CHILDREN
    FILE_READ_EA = GenericAccessRights.SELF_WRITE
    FILE_WRITE_EA = GenericAccessRights.READ_PROPERTY
    FILE_EXECUTE = GenericAccessRights.WRITE_PROPERTY
    FILE_DELETE_CHILD = GenericAccessRights.DELETE_TREE
    FILE_READ_ATTRIBUTES = GenericAccessRights.LIST_OBJECT
    FILE_WRITE_ATTRIBUTES = GenericAccessRights.CONTROL_ACCESS
    GENERIC_READ = GenericAccessRights.GENERIC_READ
    GENERIC_WRITE = GenericAccessRights.GENERIC_WRITE
    GENERIC_EXECUTE = GenericAccessRights.GENERIC_EXECUTE
    GENERIC_ALL = GenericAccessRights.GENERIC_ALL
    DELETE = GenericAccessRights.STANDARD_DELETE
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

    KEY_QUERY_VALUE = GenericAccessRights.CREATE_CHILD
    KEY_SET_VALUE = GenericAccessRights.DELETE_CHILD
    KEY_CREATE_SUB_KEY = GenericAccessRights.LIST_CHILDREN
    KEY_ENUMERATE_SUB_KEYS = GenericAccessRights.SELF_WRITE
    KEY_NOTIFY = GenericAccessRights.READ_PROPERTY
    KEY_CREATE_LINK = GenericAccessRights.WRITE_PROPERTY
    KEY_WOW64_64KEY = GenericAccessRights.CONTROL_ACCESS
    KEY_WOW64_32KEY = GenericAccessRights.ACCESS9
    GENERIC_READ = GenericAccessRights.GENERIC_READ
    GENERIC_WRITE = GenericAccessRights.GENERIC_WRITE
    GENERIC_EXECUTE = GenericAccessRights.GENERIC_EXECUTE
    GENERIC_ALL = GenericAccessRights.GENERIC_ALL
    DELETE = GenericAccessRights.STANDARD_DELETE
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
    PORT_CONNECT = GenericAccessRights.CREATE_CHILD
    GENERIC_READ = GenericAccessRights.GENERIC_READ
    GENERIC_WRITE = GenericAccessRights.GENERIC_WRITE
    GENERIC_EXECUTE = GenericAccessRights.GENERIC_EXECUTE
    GENERIC_ALL = GenericAccessRights.GENERIC_ALL
    DELETE = GenericAccessRights.STANDARD_DELETE
    READ_CONTROL = GenericAccessRights.READ_CONTROL
    WRITE_DAC = GenericAccessRights.WRITE_DAC
    WRITE_OWNER = GenericAccessRights.WRITE_OWNER
    SYNCHRONIZE = GenericAccessRights.SYNCHRONIZE
    MAXIMUM_ALLOWED = GenericAccessRights.MAXIMUM_ALLOWED
    ACCESS_SYSTEM_SECURITY = GenericAccessRights.ACCESS_SYSTEM_SECURITY


class DebugAccessRights(IntEnum):
    DEBUG_READ_EVENT = GenericAccessRights.CREATE_CHILD
    DEBUG_PROCESS_ASSIGN = GenericAccessRights.DELETE_CHILD
    DEBUG_SET_INFORMATION = GenericAccessRights.LIST_CHILDREN
    DEBUG_QUERY_INFORMATION = GenericAccessRights.SELF_WRITE
    GENERIC_READ = GenericAccessRights.GENERIC_READ
    GENERIC_WRITE = GenericAccessRights.GENERIC_WRITE
    GENERIC_EXECUTE = GenericAccessRights.GENERIC_EXECUTE
    GENERIC_ALL = GenericAccessRights.GENERIC_ALL
    DELETE = GenericAccessRights.STANDARD_DELETE
    READ_CONTROL = GenericAccessRights.READ_CONTROL
    WRITE_DAC = GenericAccessRights.WRITE_DAC
    WRITE_OWNER = GenericAccessRights.WRITE_OWNER
    SYNCHRONIZE = GenericAccessRights.SYNCHRONIZE
    MAXIMUM_ALLOWED = GenericAccessRights.MAXIMUM_ALLOWED
    ACCESS_SYSTEM_SECURITY = GenericAccessRights.ACCESS_SYSTEM_SECURITY


class DesktopAccessRights(IntEnum):
    DESKTOP_READOBJECTS = GenericAccessRights.CREATE_CHILD
    DESKTOP_CREATEWINDOW = GenericAccessRights.DELETE_CHILD
    DESKTOP_CREATEMENU = GenericAccessRights.LIST_CHILDREN
    DESKTOP_HOOKCONTROL = GenericAccessRights.SELF_WRITE
    DESKTOP_JOURNALRECORD = GenericAccessRights.READ_PROPERTY
    DESKTOP_JOURNALPLAYBACK = GenericAccessRights.WRITE_PROPERTY
    DESKTOP_ENUMERATE = GenericAccessRights.DELETE_TREE
    DESKTOP_WRITEOBJECTS = GenericAccessRights.LIST_OBJECT
    DESKTOP_SWITCHDESKTOP = GenericAccessRights.CONTROL_ACCESS
    GENERIC_READ = GenericAccessRights.GENERIC_READ
    GENERIC_WRITE = GenericAccessRights.GENERIC_WRITE
    GENERIC_EXECUTE = GenericAccessRights.GENERIC_EXECUTE
    GENERIC_ALL = GenericAccessRights.GENERIC_ALL
    DELETE = GenericAccessRights.STANDARD_DELETE
    READ_CONTROL = GenericAccessRights.READ_CONTROL
    WRITE_DAC = GenericAccessRights.WRITE_DAC
    WRITE_OWNER = GenericAccessRights.WRITE_OWNER
    SYNCHRONIZE = GenericAccessRights.SYNCHRONIZE
    MAXIMUM_ALLOWED = GenericAccessRights.MAXIMUM_ALLOWED
    ACCESS_SYSTEM_SECURITY = GenericAccessRights.ACCESS_SYSTEM_SECURITY


class DirectoryAccessRights(IntEnum):
    DIRECTORY_QUERY = GenericAccessRights.CREATE_CHILD
    DIRECTORY_TRAVERSE = GenericAccessRights.DELETE_CHILD
    DIRECTORY_CREATE_OBJECT = GenericAccessRights.LIST_CHILDREN
    DIRECTORY_CREATE_SUBDIRECTORY = GenericAccessRights.SELF_WRITE
    GENERIC_READ = GenericAccessRights.GENERIC_READ
    GENERIC_WRITE = GenericAccessRights.GENERIC_WRITE
    GENERIC_EXECUTE = GenericAccessRights.GENERIC_EXECUTE
    GENERIC_ALL = GenericAccessRights.GENERIC_ALL
    DELETE = GenericAccessRights.STANDARD_DELETE
    READ_CONTROL = GenericAccessRights.READ_CONTROL
    WRITE_DAC = GenericAccessRights.WRITE_DAC
    WRITE_OWNER = GenericAccessRights.WRITE_OWNER
    SYNCHRONIZE = GenericAccessRights.SYNCHRONIZE
    MAXIMUM_ALLOWED = GenericAccessRights.MAXIMUM_ALLOWED
    ACCESS_SYSTEM_SECURITY = GenericAccessRights.ACCESS_SYSTEM_SECURITY


class EnlistmentAccessRights(IntEnum):
    ENLISTMENT_QUERY_INFORMATION = GenericAccessRights.CREATE_CHILD
    ENLISTMENT_SET_INFORMATION = GenericAccessRights.DELETE_CHILD
    ENLISTMENT_RECOVER = GenericAccessRights.LIST_CHILDREN
    ENLISTMENT_SUBORDINATE_RIGHTS = GenericAccessRights.SELF_WRITE
    ENLISTMENT_SUPERIOR_RIGHTS = GenericAccessRights.READ_PROPERTY
    GENERIC_READ = GenericAccessRights.GENERIC_READ
    GENERIC_WRITE = GenericAccessRights.GENERIC_WRITE
    GENERIC_EXECUTE = GenericAccessRights.GENERIC_EXECUTE
    GENERIC_ALL = GenericAccessRights.GENERIC_ALL
    DELETE = GenericAccessRights.STANDARD_DELETE
    READ_CONTROL = GenericAccessRights.READ_CONTROL
    WRITE_DAC = GenericAccessRights.WRITE_DAC
    WRITE_OWNER = GenericAccessRights.WRITE_OWNER
    SYNCHRONIZE = GenericAccessRights.SYNCHRONIZE
    MAXIMUM_ALLOWED = GenericAccessRights.MAXIMUM_ALLOWED
    ACCESS_SYSTEM_SECURITY = GenericAccessRights.ACCESS_SYSTEM_SECURITY


class EventAccessRights(IntEnum):
    EVENT_QUERY_STATE = GenericAccessRights.CREATE_CHILD
    EVENT_MODIFY_STATE = GenericAccessRights.DELETE_CHILD
    GENERIC_READ = GenericAccessRights.GENERIC_READ
    GENERIC_WRITE = GenericAccessRights.GENERIC_WRITE
    GENERIC_EXECUTE = GenericAccessRights.GENERIC_EXECUTE
    GENERIC_ALL = GenericAccessRights.GENERIC_ALL
    DELETE = GenericAccessRights.STANDARD_DELETE
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

    FILE_LIST_DIRECTORY = GenericAccessRights.CREATE_CHILD
    FILE_ADD_FILE = GenericAccessRights.DELETE_CHILD
    FILE_ADD_SUBDIRECTORY = GenericAccessRights.LIST_CHILDREN
    FILE_READ_EA = GenericAccessRights.SELF_WRITE
    FILE_WRITE_EA = GenericAccessRights.READ_PROPERTY
    FILE_TRAVERSE = GenericAccessRights.WRITE_PROPERTY
    FILE_DELETE_CHILD = GenericAccessRights.DELETE_TREE
    FILE_READ_ATTRIBUTES = GenericAccessRights.LIST_OBJECT
    FILE_WRITE_ATTRIBUTES = GenericAccessRights.CONTROL_ACCESS
    GENERIC_READ = GenericAccessRights.GENERIC_READ
    GENERIC_WRITE = GenericAccessRights.GENERIC_WRITE
    GENERIC_EXECUTE = GenericAccessRights.GENERIC_EXECUTE
    GENERIC_ALL = GenericAccessRights.GENERIC_ALL
    DELETE = GenericAccessRights.STANDARD_DELETE
    READ_CONTROL = GenericAccessRights.READ_CONTROL
    WRITE_DAC = GenericAccessRights.WRITE_DAC
    WRITE_OWNER = GenericAccessRights.WRITE_OWNER
    SYNCHRONIZE = GenericAccessRights.SYNCHRONIZE
    MAXIMUM_ALLOWED = GenericAccessRights.MAXIMUM_ALLOWED
    ACCESS_SYSTEM_SECURITY = GenericAccessRights.ACCESS_SYSTEM_SECURITY


class FilterConnectionPortAccessRights(IntEnum):
    FILTER_CONNECTION_PORT_CONNECT = GenericAccessRights.CREATE_CHILD
    GENERIC_READ = GenericAccessRights.GENERIC_READ
    GENERIC_WRITE = GenericAccessRights.GENERIC_WRITE
    GENERIC_EXECUTE = GenericAccessRights.GENERIC_EXECUTE
    GENERIC_ALL = GenericAccessRights.GENERIC_ALL
    DELETE = GenericAccessRights.STANDARD_DELETE
    READ_CONTROL = GenericAccessRights.READ_CONTROL
    WRITE_DAC = GenericAccessRights.WRITE_DAC
    WRITE_OWNER = GenericAccessRights.WRITE_OWNER
    SYNCHRONIZE = GenericAccessRights.SYNCHRONIZE
    MAXIMUM_ALLOWED = GenericAccessRights.MAXIMUM_ALLOWED
    ACCESS_SYSTEM_SECURITY = GenericAccessRights.ACCESS_SYSTEM_SECURITY


class IoCompletionAccessRights(IntEnum):
    IO_COMPLETION_QUERY_STATE = GenericAccessRights.CREATE_CHILD
    IO_COMPLETION_SET_COMPLETION = GenericAccessRights.DELETE_CHILD
    GENERIC_READ = GenericAccessRights.GENERIC_READ
    GENERIC_WRITE = GenericAccessRights.GENERIC_WRITE
    GENERIC_EXECUTE = GenericAccessRights.GENERIC_EXECUTE
    GENERIC_ALL = GenericAccessRights.GENERIC_ALL
    DELETE = GenericAccessRights.STANDARD_DELETE
    READ_CONTROL = GenericAccessRights.READ_CONTROL
    WRITE_DAC = GenericAccessRights.WRITE_DAC
    WRITE_OWNER = GenericAccessRights.WRITE_OWNER
    SYNCHRONIZE = GenericAccessRights.SYNCHRONIZE
    MAXIMUM_ALLOWED = GenericAccessRights.MAXIMUM_ALLOWED
    ACCESS_SYSTEM_SECURITY = GenericAccessRights.ACCESS_SYSTEM_SECURITY


class JobAccessRights(IntEnum):
    JOB_ASSIGN_PROCESS = GenericAccessRights.CREATE_CHILD
    JOB_SET_ATTRIBUTES = GenericAccessRights.DELETE_CHILD
    JOB_QUERY = GenericAccessRights.LIST_CHILDREN
    JOB_TERMINATE = GenericAccessRights.SELF_WRITE
    JOB_SET_SECURITY_ATTRIBUTES = GenericAccessRights.READ_PROPERTY
    JOB_IMPERSONATE = GenericAccessRights.WRITE_PROPERTY
    GENERIC_READ = GenericAccessRights.GENERIC_READ
    GENERIC_WRITE = GenericAccessRights.GENERIC_WRITE
    GENERIC_EXECUTE = GenericAccessRights.GENERIC_EXECUTE
    GENERIC_ALL = GenericAccessRights.GENERIC_ALL
    DELETE = GenericAccessRights.STANDARD_DELETE
    READ_CONTROL = GenericAccessRights.READ_CONTROL
    WRITE_DAC = GenericAccessRights.WRITE_DAC
    WRITE_OWNER = GenericAccessRights.WRITE_OWNER
    SYNCHRONIZE = GenericAccessRights.SYNCHRONIZE
    MAXIMUM_ALLOWED = GenericAccessRights.MAXIMUM_ALLOWED
    ACCESS_SYSTEM_SECURITY = GenericAccessRights.ACCESS_SYSTEM_SECURITY


class KeyAccessRights(IntEnum):
    KEY_QUERY_VALUE = GenericAccessRights.CREATE_CHILD
    KEY_SET_VALUE = GenericAccessRights.DELETE_CHILD
    KEY_CREATE_SUB_KEY = GenericAccessRights.LIST_CHILDREN
    KEY_ENUMERATE_SUB_KEYS = GenericAccessRights.SELF_WRITE
    KEY_NOTIFY = GenericAccessRights.READ_PROPERTY
    KEY_CREATE_LINK = GenericAccessRights.WRITE_PROPERTY
    GENERIC_READ = GenericAccessRights.GENERIC_READ
    GENERIC_WRITE = GenericAccessRights.GENERIC_WRITE
    GENERIC_EXECUTE = GenericAccessRights.GENERIC_EXECUTE
    GENERIC_ALL = GenericAccessRights.GENERIC_ALL
    DELETE = GenericAccessRights.STANDARD_DELETE
    READ_CONTROL = GenericAccessRights.READ_CONTROL
    WRITE_DAC = GenericAccessRights.WRITE_DAC
    WRITE_OWNER = GenericAccessRights.WRITE_OWNER
    SYNCHRONIZE = GenericAccessRights.SYNCHRONIZE
    MAXIMUM_ALLOWED = GenericAccessRights.MAXIMUM_ALLOWED
    ACCESS_SYSTEM_SECURITY = GenericAccessRights.ACCESS_SYSTEM_SECURITY


class MutantAccessRights(IntEnum):
    MUTANT_MODIFY_STATE = GenericAccessRights.CREATE_CHILD
    GENERIC_READ = GenericAccessRights.GENERIC_READ
    GENERIC_WRITE = GenericAccessRights.GENERIC_WRITE
    GENERIC_EXECUTE = GenericAccessRights.GENERIC_EXECUTE
    GENERIC_ALL = GenericAccessRights.GENERIC_ALL
    DELETE = GenericAccessRights.STANDARD_DELETE
    READ_CONTROL = GenericAccessRights.READ_CONTROL
    WRITE_DAC = GenericAccessRights.WRITE_DAC
    WRITE_OWNER = GenericAccessRights.WRITE_OWNER
    SYNCHRONIZE = GenericAccessRights.SYNCHRONIZE
    MAXIMUM_ALLOWED = GenericAccessRights.MAXIMUM_ALLOWED
    ACCESS_SYSTEM_SECURITY = GenericAccessRights.ACCESS_SYSTEM_SECURITY


class MemoryPartitionAccessRights(IntEnum):
    MEMORY_PARTITION_QUERY_ACCESS = GenericAccessRights.CREATE_CHILD
    MEMORY_PARTITION_MODIFY_ACCESS = GenericAccessRights.DELETE_CHILD
    GENERIC_READ = GenericAccessRights.GENERIC_READ
    GENERIC_WRITE = GenericAccessRights.GENERIC_WRITE
    GENERIC_EXECUTE = GenericAccessRights.GENERIC_EXECUTE
    GENERIC_ALL = GenericAccessRights.GENERIC_ALL
    DELETE = GenericAccessRights.STANDARD_DELETE
    READ_CONTROL = GenericAccessRights.READ_CONTROL
    WRITE_DAC = GenericAccessRights.WRITE_DAC
    WRITE_OWNER = GenericAccessRights.WRITE_OWNER
    SYNCHRONIZE = GenericAccessRights.SYNCHRONIZE
    MAXIMUM_ALLOWED = GenericAccessRights.MAXIMUM_ALLOWED
    ACCESS_SYSTEM_SECURITY = GenericAccessRights.ACCESS_SYSTEM_SECURITY


class ProcessAccessRights(IntEnum):
    PROCESS_TERMINATE = GenericAccessRights.CREATE_CHILD
    PROCESS_CREATE_THREAD = GenericAccessRights.DELETE_CHILD
    PROCESS_SET_SESSIONID = GenericAccessRights.LIST_CHILDREN
    PROCESS_VM_OPERATION = GenericAccessRights.SELF_WRITE
    PROCESS_VM_READ = GenericAccessRights.READ_PROPERTY
    PROCESS_VM_WRITE = GenericAccessRights.WRITE_PROPERTY
    PROCESS_DUP_HANDLE = GenericAccessRights.DELETE_TREE
    PROCESS_CREATE_PROCESS = GenericAccessRights.LIST_OBJECT
    PROCESS_SET_QUOTA = GenericAccessRights.CONTROL_ACCESS
    PROCESS_SET_INFORMATION = GenericAccessRights.ACCESS9
    PROCESS_QUERY_INFORMATION = GenericAccessRights.ACCESS10
    PROCESS_SUSPEND_RESUME = GenericAccessRights.ACCESS11
    PROCESS_QUERY_LIMITED_INFORMATION = GenericAccessRights.ACCESS12
    PROCESS_SET_LIMITED_INFORMATION = GenericAccessRights.ACCESS13
    GENERIC_READ = GenericAccessRights.GENERIC_READ
    GENERIC_WRITE = GenericAccessRights.GENERIC_WRITE
    GENERIC_EXECUTE = GenericAccessRights.GENERIC_EXECUTE
    GENERIC_ALL = GenericAccessRights.GENERIC_ALL
    DELETE = GenericAccessRights.STANDARD_DELETE
    READ_CONTROL = GenericAccessRights.READ_CONTROL
    WRITE_DAC = GenericAccessRights.WRITE_DAC
    WRITE_OWNER = GenericAccessRights.WRITE_OWNER
    SYNCHRONIZE = GenericAccessRights.SYNCHRONIZE
    MAXIMUM_ALLOWED = GenericAccessRights.MAXIMUM_ALLOWED
    ACCESS_SYSTEM_SECURITY = GenericAccessRights.ACCESS_SYSTEM_SECURITY

    AllAccess = (0x1FFFFF,)


class RegistryTransactionAccessRights(IntEnum):
    TRANSACTION_QUERY_INFORMATION = GenericAccessRights.CREATE_CHILD
    TRANSACTION_SET_INFORMATION = GenericAccessRights.DELETE_CHILD
    TRANSACTION_ENLIST = GenericAccessRights.LIST_CHILDREN
    TRANSACTION_COMMIT = GenericAccessRights.SELF_WRITE
    TRANSACTION_ROLLBACK = GenericAccessRights.READ_PROPERTY
    TRANSACTION_PROPAGATE = GenericAccessRights.WRITE_PROPERTY
    GENERIC_READ = GenericAccessRights.GENERIC_READ
    GENERIC_WRITE = GenericAccessRights.GENERIC_WRITE
    GENERIC_EXECUTE = GenericAccessRights.GENERIC_EXECUTE
    GENERIC_ALL = GenericAccessRights.GENERIC_ALL
    DELETE = GenericAccessRights.STANDARD_DELETE
    READ_CONTROL = GenericAccessRights.READ_CONTROL
    WRITE_DAC = GenericAccessRights.WRITE_DAC
    WRITE_OWNER = GenericAccessRights.WRITE_OWNER
    SYNCHRONIZE = GenericAccessRights.SYNCHRONIZE
    MAXIMUM_ALLOWED = GenericAccessRights.MAXIMUM_ALLOWED
    ACCESS_SYSTEM_SECURITY = GenericAccessRights.ACCESS_SYSTEM_SECURITY


class ResourceManagerAccessRights(IntEnum):
    RESOURCEMANAGER_QUERY_INFORMATION = GenericAccessRights.CREATE_CHILD
    RESOURCEMANAGER_SET_INFORMATION = GenericAccessRights.DELETE_CHILD
    RESOURCEMANAGER_RECOVER = GenericAccessRights.LIST_CHILDREN
    RESOURCEMANAGER_ENLIST = GenericAccessRights.SELF_WRITE
    RESOURCEMANAGER_GET_NOTIFICATION = GenericAccessRights.READ_PROPERTY
    RESOURCEMANAGER_REGISTER_PROTOCOL = GenericAccessRights.WRITE_PROPERTY
    RESOURCEMANAGER_COMPLETE_PROPAGATION = GenericAccessRights.DELETE_TREE
    GENERIC_READ = GenericAccessRights.GENERIC_READ
    GENERIC_WRITE = GenericAccessRights.GENERIC_WRITE
    GENERIC_EXECUTE = GenericAccessRights.GENERIC_EXECUTE
    GENERIC_ALL = GenericAccessRights.GENERIC_ALL
    DELETE = GenericAccessRights.STANDARD_DELETE
    READ_CONTROL = GenericAccessRights.READ_CONTROL
    WRITE_DAC = GenericAccessRights.WRITE_DAC
    WRITE_OWNER = GenericAccessRights.WRITE_OWNER
    SYNCHRONIZE = GenericAccessRights.SYNCHRONIZE
    MAXIMUM_ALLOWED = GenericAccessRights.MAXIMUM_ALLOWED
    ACCESS_SYSTEM_SECURITY = GenericAccessRights.ACCESS_SYSTEM_SECURITY


class SectionAccessRights(IntEnum):
    SECTION_QUERY = GenericAccessRights.CREATE_CHILD
    SECTION_MAP_WRITE = GenericAccessRights.DELETE_CHILD
    SECTION_MAP_READ = GenericAccessRights.LIST_CHILDREN
    SECTION_MAP_EXECUTE = GenericAccessRights.SELF_WRITE
    SECTION_EXTEND_SIZE = GenericAccessRights.READ_PROPERTY
    SECTION_MAP_EXECUTE_EXPLICIT = GenericAccessRights.WRITE_PROPERTY
    GENERIC_READ = GenericAccessRights.GENERIC_READ
    GENERIC_WRITE = GenericAccessRights.GENERIC_WRITE
    GENERIC_EXECUTE = GenericAccessRights.GENERIC_EXECUTE
    GENERIC_ALL = GenericAccessRights.GENERIC_ALL
    DELETE = GenericAccessRights.STANDARD_DELETE
    READ_CONTROL = GenericAccessRights.READ_CONTROL
    WRITE_DAC = GenericAccessRights.WRITE_DAC
    WRITE_OWNER = GenericAccessRights.WRITE_OWNER
    SYNCHRONIZE = GenericAccessRights.SYNCHRONIZE
    MAXIMUM_ALLOWED = GenericAccessRights.MAXIMUM_ALLOWED
    ACCESS_SYSTEM_SECURITY = GenericAccessRights.ACCESS_SYSTEM_SECURITY


class SemaphoreAccessRights(IntEnum):
    SEMAPHORE_QUERY_STATE = GenericAccessRights.CREATE_CHILD
    SEMAPHORE_MODIFY_STATE = GenericAccessRights.DELETE_CHILD
    GENERIC_READ = GenericAccessRights.GENERIC_READ
    GENERIC_WRITE = GenericAccessRights.GENERIC_WRITE
    GENERIC_EXECUTE = GenericAccessRights.GENERIC_EXECUTE
    GENERIC_ALL = GenericAccessRights.GENERIC_ALL
    DELETE = GenericAccessRights.STANDARD_DELETE
    READ_CONTROL = GenericAccessRights.READ_CONTROL
    WRITE_DAC = GenericAccessRights.WRITE_DAC
    WRITE_OWNER = GenericAccessRights.WRITE_OWNER
    SYNCHRONIZE = GenericAccessRights.SYNCHRONIZE
    MAXIMUM_ALLOWED = GenericAccessRights.MAXIMUM_ALLOWED
    ACCESS_SYSTEM_SECURITY = GenericAccessRights.ACCESS_SYSTEM_SECURITY


class SessionAccessRights(IntEnum):
    SESSION_QUERY = GenericAccessRights.CREATE_CHILD
    SESSION_MODIFY = GenericAccessRights.DELETE_CHILD
    GENERIC_READ = GenericAccessRights.GENERIC_READ
    GENERIC_WRITE = GenericAccessRights.GENERIC_WRITE
    GENERIC_EXECUTE = GenericAccessRights.GENERIC_EXECUTE
    GENERIC_ALL = GenericAccessRights.GENERIC_ALL
    DELETE = GenericAccessRights.STANDARD_DELETE
    READ_CONTROL = GenericAccessRights.READ_CONTROL
    WRITE_DAC = GenericAccessRights.WRITE_DAC
    WRITE_OWNER = GenericAccessRights.WRITE_OWNER
    SYNCHRONIZE = GenericAccessRights.SYNCHRONIZE
    MAXIMUM_ALLOWED = GenericAccessRights.MAXIMUM_ALLOWED
    ACCESS_SYSTEM_SECURITY = GenericAccessRights.ACCESS_SYSTEM_SECURITY


class SymbolicLinkAccessRights(IntEnum):
    SYMBOLIC_LINK_QUERY = GenericAccessRights.CREATE_CHILD
    SYMBOLIC_LINK_SET = GenericAccessRights.DELETE_CHILD
    GENERIC_READ = GenericAccessRights.GENERIC_READ
    GENERIC_WRITE = GenericAccessRights.GENERIC_WRITE
    GENERIC_EXECUTE = GenericAccessRights.GENERIC_EXECUTE
    GENERIC_ALL = GenericAccessRights.GENERIC_ALL
    DELETE = GenericAccessRights.STANDARD_DELETE
    READ_CONTROL = GenericAccessRights.READ_CONTROL
    WRITE_DAC = GenericAccessRights.WRITE_DAC
    WRITE_OWNER = GenericAccessRights.WRITE_OWNER
    SYNCHRONIZE = GenericAccessRights.SYNCHRONIZE
    MAXIMUM_ALLOWED = GenericAccessRights.MAXIMUM_ALLOWED
    ACCESS_SYSTEM_SECURITY = GenericAccessRights.ACCESS_SYSTEM_SECURITY


class ThreadAccessRights(IntEnum):
    THREAD_TERMINATE = GenericAccessRights.CREATE_CHILD
    THREAD_SUSPEND_RESUME = GenericAccessRights.DELETE_CHILD
    THREAD_ALERT = GenericAccessRights.LIST_CHILDREN
    THREAD_GET_CONTEXT = GenericAccessRights.SELF_WRITE
    THREAD_SET_CONTEXT = GenericAccessRights.READ_PROPERTY
    THREAD_SET_INFORMATION = GenericAccessRights.WRITE_PROPERTY
    THREAD_QUERY_INFORMATION = GenericAccessRights.DELETE_TREE
    THREAD_SET_THREAD_TOKEN = GenericAccessRights.LIST_OBJECT
    THREAD_IMPERSONATE = GenericAccessRights.CONTROL_ACCESS
    THREAD_DIRECT_IMPERSONATION = GenericAccessRights.ACCESS9
    THREAD_SET_LIMITED_INFORMATION = GenericAccessRights.ACCESS10
    THREAD_QUERY_LIMITED_INFORMATION = GenericAccessRights.ACCESS11
    THREAD_RESUME = GenericAccessRights.ACCESS12
    GENERIC_READ = GenericAccessRights.GENERIC_READ
    GENERIC_WRITE = GenericAccessRights.GENERIC_WRITE
    GENERIC_EXECUTE = GenericAccessRights.GENERIC_EXECUTE
    GENERIC_ALL = GenericAccessRights.GENERIC_ALL
    DELETE = GenericAccessRights.STANDARD_DELETE
    READ_CONTROL = GenericAccessRights.READ_CONTROL
    WRITE_DAC = GenericAccessRights.WRITE_DAC
    WRITE_OWNER = GenericAccessRights.WRITE_OWNER
    SYNCHRONIZE = GenericAccessRights.SYNCHRONIZE
    MAXIMUM_ALLOWED = GenericAccessRights.MAXIMUM_ALLOWED
    ACCESS_SYSTEM_SECURITY = GenericAccessRights.ACCESS_SYSTEM_SECURITY
    THREAD_ALL_ACCESS = 0x1FFFFF


class TimerAccessRights(IntEnum):
    TIMER_QUERY_STATE = GenericAccessRights.CREATE_CHILD
    TIMER_SET_STATE = GenericAccessRights.DELETE_CHILD
    GENERIC_READ = GenericAccessRights.GENERIC_READ
    GENERIC_WRITE = GenericAccessRights.GENERIC_WRITE
    GENERIC_EXECUTE = GenericAccessRights.GENERIC_EXECUTE
    GENERIC_ALL = GenericAccessRights.GENERIC_ALL
    DELETE = GenericAccessRights.STANDARD_DELETE
    READ_CONTROL = GenericAccessRights.READ_CONTROL
    WRITE_DAC = GenericAccessRights.WRITE_DAC
    WRITE_OWNER = GenericAccessRights.WRITE_OWNER
    SYNCHRONIZE = GenericAccessRights.SYNCHRONIZE
    MAXIMUM_ALLOWED = GenericAccessRights.MAXIMUM_ALLOWED
    ACCESS_SYSTEM_SECURITY = GenericAccessRights.ACCESS_SYSTEM_SECURITY


class TokenAccessRights(IntEnum):
    TOKEN_ASSIGN_PRIMARY = GenericAccessRights.CREATE_CHILD
    TOKEN_DUPLICATE = GenericAccessRights.DELETE_CHILD
    TOKEN_IMPERSONATE = GenericAccessRights.LIST_CHILDREN
    TOKEN_QUERY = GenericAccessRights.SELF_WRITE
    TOKEN_QUERY_SOURCE = GenericAccessRights.READ_PROPERTY
    TOKEN_ADJUST_PRIVILEGES = GenericAccessRights.WRITE_PROPERTY
    TOKEN_ADJUST_GROUPS = GenericAccessRights.DELETE_TREE
    TOKEN_ADJUST_DEFAULT = GenericAccessRights.LIST_OBJECT
    TOKEN_ADJUST_SESSIONID = GenericAccessRights.CONTROL_ACCESS
    GENERIC_READ = GenericAccessRights.GENERIC_READ
    GENERIC_WRITE = GenericAccessRights.GENERIC_WRITE
    GENERIC_EXECUTE = GenericAccessRights.GENERIC_EXECUTE
    GENERIC_ALL = GenericAccessRights.GENERIC_ALL
    DELETE = GenericAccessRights.STANDARD_DELETE
    READ_CONTROL = GenericAccessRights.READ_CONTROL
    WRITE_DAC = GenericAccessRights.WRITE_DAC
    WRITE_OWNER = GenericAccessRights.WRITE_OWNER
    SYNCHRONIZE = GenericAccessRights.SYNCHRONIZE
    MAXIMUM_ALLOWED = GenericAccessRights.MAXIMUM_ALLOWED
    ACCESS_SYSTEM_SECURITY = GenericAccessRights.ACCESS_SYSTEM_SECURITY


class TraceAccessRights(IntEnum):
    WMIGUID_QUERY = GenericAccessRights.CREATE_CHILD
    WMIGUID_SET = GenericAccessRights.DELETE_CHILD
    WMIGUID_NOTIFICATION = GenericAccessRights.LIST_CHILDREN
    WMIGUID_READ_DESCRIPTION = GenericAccessRights.SELF_WRITE
    WMIGUID_EXECUTE = GenericAccessRights.READ_PROPERTY
    TRACELOG_CREATE_REALTIME = GenericAccessRights.WRITE_PROPERTY
    TRACELOG_CREATE_ONDISK = GenericAccessRights.DELETE_TREE
    TRACELOG_GUID_ENABLE = GenericAccessRights.LIST_OBJECT
    TRACELOG_ACCESS_KERNEL_LOGGER = GenericAccessRights.CONTROL_ACCESS
    TRACELOG_LOG_EVENT = GenericAccessRights.ACCESS9
    TRACELOG_ACCESS_REALTIME = GenericAccessRights.ACCESS10
    TRACELOG_REGISTER_GUIDS = GenericAccessRights.ACCESS11
    TRACELOG_JOIN_GROUP = GenericAccessRights.ACCESS12
    GENERIC_READ = GenericAccessRights.GENERIC_READ
    GENERIC_WRITE = GenericAccessRights.GENERIC_WRITE
    GENERIC_EXECUTE = GenericAccessRights.GENERIC_EXECUTE
    GENERIC_ALL = GenericAccessRights.GENERIC_ALL
    DELETE = GenericAccessRights.STANDARD_DELETE
    READ_CONTROL = GenericAccessRights.READ_CONTROL
    WRITE_DAC = GenericAccessRights.WRITE_DAC
    WRITE_OWNER = GenericAccessRights.WRITE_OWNER
    SYNCHRONIZE = GenericAccessRights.SYNCHRONIZE
    MAXIMUM_ALLOWED = GenericAccessRights.MAXIMUM_ALLOWED
    ACCESS_SYSTEM_SECURITY = GenericAccessRights.ACCESS_SYSTEM_SECURITY


class TransactionManagerAccessRights(IntEnum):
    TRANSACTIONMANAGER_QUERY_INFORMATION = GenericAccessRights.CREATE_CHILD
    TRANSACTIONMANAGER_SET_INFORMATION = GenericAccessRights.DELETE_CHILD
    TRANSACTIONMANAGER_RECOVER = GenericAccessRights.LIST_CHILDREN
    TRANSACTIONMANAGER_RENAME = GenericAccessRights.SELF_WRITE
    TRANSACTIONMANAGER_CREATE_RM = GenericAccessRights.READ_PROPERTY
    TRANSACTIONMANAGER_BIND_TRANSACTION = GenericAccessRights.WRITE_PROPERTY
    GENERIC_READ = GenericAccessRights.GENERIC_READ
    GENERIC_WRITE = GenericAccessRights.GENERIC_WRITE
    GENERIC_EXECUTE = GenericAccessRights.GENERIC_EXECUTE
    GENERIC_ALL = GenericAccessRights.GENERIC_ALL
    DELETE = GenericAccessRights.STANDARD_DELETE
    READ_CONTROL = GenericAccessRights.READ_CONTROL
    WRITE_DAC = GenericAccessRights.WRITE_DAC
    WRITE_OWNER = GenericAccessRights.WRITE_OWNER
    SYNCHRONIZE = GenericAccessRights.SYNCHRONIZE
    MAXIMUM_ALLOWED = GenericAccessRights.MAXIMUM_ALLOWED
    ACCESS_SYSTEM_SECURITY = GenericAccessRights.ACCESS_SYSTEM_SECURITY


class TransactionAccessRights(IntEnum):
    TRANSACTION_QUERY_INFORMATION = GenericAccessRights.CREATE_CHILD
    TRANSACTION_SET_INFORMATION = GenericAccessRights.DELETE_CHILD
    TRANSACTION_ENLIST = GenericAccessRights.LIST_CHILDREN
    TRANSACTION_COMMIT = GenericAccessRights.SELF_WRITE
    TRANSACTION_ROLLBACK = GenericAccessRights.READ_PROPERTY
    TRANSACTION_PROPAGATE = GenericAccessRights.WRITE_PROPERTY
    TRANSACTION_RIGHT_RESERVED1 = GenericAccessRights.DELETE_TREE
    GENERIC_READ = GenericAccessRights.GENERIC_READ
    GENERIC_WRITE = GenericAccessRights.GENERIC_WRITE
    GENERIC_EXECUTE = GenericAccessRights.GENERIC_EXECUTE
    GENERIC_ALL = GenericAccessRights.GENERIC_ALL
    DELETE = GenericAccessRights.STANDARD_DELETE
    READ_CONTROL = GenericAccessRights.READ_CONTROL
    WRITE_DAC = GenericAccessRights.WRITE_DAC
    WRITE_OWNER = GenericAccessRights.WRITE_OWNER
    SYNCHRONIZE = GenericAccessRights.SYNCHRONIZE
    MAXIMUM_ALLOWED = GenericAccessRights.MAXIMUM_ALLOWED
    ACCESS_SYSTEM_SECURITY = GenericAccessRights.ACCESS_SYSTEM_SECURITY


class WindowStationAccessRights(IntEnum):
    WINSTA_ENUMDESKTOPS = GenericAccessRights.CREATE_CHILD
    WINSTA_READATTRIBUTES = GenericAccessRights.DELETE_CHILD
    WINSTA_ACCESSCLIPBOARD = GenericAccessRights.LIST_CHILDREN
    WINSTA_CREATEDESKTOP = GenericAccessRights.SELF_WRITE
    WINSTA_WRITEATTRIBUTES = GenericAccessRights.READ_PROPERTY
    WINSTA_ACCESSGLOBALATOMS = GenericAccessRights.WRITE_PROPERTY
    WINSTA_EXITWINDOWS = GenericAccessRights.DELETE_TREE
    WINSTA_ENUMERATE = GenericAccessRights.CONTROL_ACCESS
    WINSTA_READSCREEN = GenericAccessRights.ACCESS9
    GENERIC_READ = GenericAccessRights.GENERIC_READ
    GENERIC_WRITE = GenericAccessRights.GENERIC_WRITE
    GENERIC_EXECUTE = GenericAccessRights.GENERIC_EXECUTE
    GENERIC_ALL = GenericAccessRights.GENERIC_ALL
    DELETE = GenericAccessRights.STANDARD_DELETE
    READ_CONTROL = GenericAccessRights.READ_CONTROL
    WRITE_DAC = GenericAccessRights.WRITE_DAC
    WRITE_OWNER = GenericAccessRights.WRITE_OWNER
    SYNCHRONIZE = GenericAccessRights.SYNCHRONIZE
    MAXIMUM_ALLOWED = GenericAccessRights.MAXIMUM_ALLOWED
    ACCESS_SYSTEM_SECURITY = GenericAccessRights.ACCESS_SYSTEM_SECURITY


class WnfAccessRights(IntEnum):
    WNF_READ_DATA = GenericAccessRights.CREATE_CHILD
    WNF_WRITE_DATA = GenericAccessRights.DELETE_CHILD
    WNF_UNKNOWN_10 = GenericAccessRights.READ_PROPERTY
    GENERIC_READ = GenericAccessRights.GENERIC_READ
    GENERIC_WRITE = GenericAccessRights.GENERIC_WRITE
    GENERIC_EXECUTE = GenericAccessRights.GENERIC_EXECUTE
    GENERIC_ALL = GenericAccessRights.GENERIC_ALL
    DELETE = GenericAccessRights.STANDARD_DELETE
    READ_CONTROL = GenericAccessRights.READ_CONTROL
    WRITE_DAC = GenericAccessRights.WRITE_DAC
    WRITE_OWNER = GenericAccessRights.WRITE_OWNER
    SYNCHRONIZE = GenericAccessRights.SYNCHRONIZE
    MAXIMUM_ALLOWED = GenericAccessRights.MAXIMUM_ALLOWED
    ACCESS_SYSTEM_SECURITY = GenericAccessRights.ACCESS_SYSTEM_SECURITY


class FirewallAccessRights(IntEnum):
    FWPM_ACTRL_ADD = GenericAccessRights.CREATE_CHILD
    FWPM_ACTRL_ADD_LINK = GenericAccessRights.DELETE_CHILD
    FWPM_ACTRL_BEGIN_READ_TXN = GenericAccessRights.LIST_CHILDREN
    FWPM_ACTRL_BEGIN_WRITE_TXN = GenericAccessRights.SELF_WRITE
    FWPM_ACTRL_CLASSIFY = GenericAccessRights.READ_PROPERTY
    FWPM_ACTRL_ENUM = GenericAccessRights.WRITE_PROPERTY
    FWPM_ACTRL_OPEN = GenericAccessRights.DELETE_TREE
    FWPM_ACTRL_READ = GenericAccessRights.LIST_OBJECT
    FWPM_ACTRL_READ_STATS = GenericAccessRights.CONTROL_ACCESS
    FWPM_ACTRL_SUBSCRIBE = GenericAccessRights.ACCESS9
    FWPM_ACTRL_WRITE = GenericAccessRights.ACCESS10
    GENERIC_READ = GenericAccessRights.GENERIC_READ
    GENERIC_WRITE = GenericAccessRights.GENERIC_WRITE
    GENERIC_EXECUTE = GenericAccessRights.GENERIC_EXECUTE
    GENERIC_ALL = GenericAccessRights.GENERIC_ALL
    DELETE = GenericAccessRights.STANDARD_DELETE
    READ_CONTROL = GenericAccessRights.READ_CONTROL
    WRITE_DAC = GenericAccessRights.WRITE_DAC
    WRITE_OWNER = GenericAccessRights.WRITE_OWNER
    MAXIMUM_ALLOWED = GenericAccessRights.MAXIMUM_ALLOWED
    ACCESS_SYSTEM_SECURITY = GenericAccessRights.ACCESS_SYSTEM_SECURITY


class FirewallFilterAccessRights(IntEnum):
    FWP_ACTRL_MATCH_FILTER = GenericAccessRights.CREATE_CHILD
    GENERIC_READ = GenericAccessRights.GENERIC_READ
    GENERIC_WRITE = GenericAccessRights.GENERIC_WRITE
    GENERIC_EXECUTE = GenericAccessRights.GENERIC_EXECUTE
    GENERIC_ALL = GenericAccessRights.GENERIC_ALL
    DELETE = GenericAccessRights.STANDARD_DELETE
    READ_CONTROL = GenericAccessRights.READ_CONTROL
    WRITE_DAC = GenericAccessRights.WRITE_DAC
    WRITE_OWNER = GenericAccessRights.WRITE_OWNER
    MAXIMUM_ALLOWED = GenericAccessRights.MAXIMUM_ALLOWED
    ACCESS_SYSTEM_SECURITY = GenericAccessRights.ACCESS_SYSTEM_SECURITY


class DirectoryServiceAccessRights(IntEnum):
    ACTRL_DS_CREATE_CHILD = GenericAccessRights.CREATE_CHILD
    ACTRL_DS_DELETE_CHILD = GenericAccessRights.DELETE_CHILD
    ACTRL_DS_LIST = GenericAccessRights.LIST_CHILDREN
    ACTRL_DS_SELF = GenericAccessRights.SELF_WRITE
    ACTRL_DS_READ_PROP = GenericAccessRights.READ_PROPERTY
    ACTRL_DS_WRITE_PROP = GenericAccessRights.WRITE_PROPERTY
    ACTRL_DS_DELETE_TREE = GenericAccessRights.DELETE_TREE
    ACTRL_DS_LIST_OBJECT = GenericAccessRights.LIST_OBJECT
    ACTRL_DS_CONTROL_ACCESS = GenericAccessRights.CONTROL_ACCESS
    GENERIC_READ = GenericAccessRights.GENERIC_READ
    GENERIC_WRITE = GenericAccessRights.GENERIC_WRITE
    GENERIC_EXECUTE = GenericAccessRights.GENERIC_EXECUTE
    GENERIC_ALL = GenericAccessRights.GENERIC_ALL
    DELETE = GenericAccessRights.STANDARD_DELETE
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
    SERVER_ACCESS_ADMINISTER = GenericAccessRights.CREATE_CHILD
    SERVER_ACCESS_ENUMERATE = GenericAccessRights.DELETE_CHILD
    PRINTER_ACCESS_ADMINISTER = GenericAccessRights.LIST_CHILDREN
    PRINTER_ACCESS_USE = GenericAccessRights.SELF_WRITE
    JOB_ACCESS_ADMINISTER = GenericAccessRights.READ_PROPERTY
    JOB_ACCESS_READ = GenericAccessRights.WRITE_PROPERTY
    PRINTER_ACCESS_MANAGE_LIMITED = GenericAccessRights.DELETE_TREE
    GENERIC_READ = GenericAccessRights.GENERIC_READ
    GENERIC_WRITE = GenericAccessRights.GENERIC_WRITE
    GENERIC_EXECUTE = GenericAccessRights.GENERIC_EXECUTE
    GENERIC_ALL = GenericAccessRights.GENERIC_ALL
    DELETE = GenericAccessRights.STANDARD_DELETE
    READ_CONTROL = GenericAccessRights.READ_CONTROL
    WRITE_DAC = GenericAccessRights.WRITE_DAC
    WRITE_OWNER = GenericAccessRights.WRITE_OWNER
    MAXIMUM_ALLOWED = GenericAccessRights.MAXIMUM_ALLOWED
    ACCESS_SYSTEM_SECURITY = GenericAccessRights.ACCESS_SYSTEM_SECURITY


class AuditAccessRights(IntEnum):
    AUDIT_SET_SYSTEM_POLICY = GenericAccessRights.CREATE_CHILD
    AUDIT_QUERY_SYSTEM_POLICY = GenericAccessRights.DELETE_CHILD
    AUDIT_SET_USER_POLICY = GenericAccessRights.LIST_CHILDREN
    AUDIT_QUERY_USER_POLICY = GenericAccessRights.SELF_WRITE
    AUDIT_ENUMERATE_USERS = GenericAccessRights.READ_PROPERTY
    AUDIT_SET_MISC_POLICY = GenericAccessRights.WRITE_PROPERTY
    AUDIT_QUERY_MISC_POLICY = GenericAccessRights.DELETE_TREE
    GENERIC_READ = GenericAccessRights.GENERIC_READ
    GENERIC_WRITE = GenericAccessRights.GENERIC_WRITE
    GENERIC_EXECUTE = GenericAccessRights.GENERIC_EXECUTE
    GENERIC_ALL = GenericAccessRights.GENERIC_ALL
    DELETE = GenericAccessRights.STANDARD_DELETE
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
    ACCOUNT_VIEW = GenericAccessRights.CREATE_CHILD
    ACCOUNT_ADJUST_PRIVILEGES = GenericAccessRights.DELETE_CHILD
    ACCOUNT_ADJUST_QUOTAS = GenericAccessRights.LIST_CHILDREN
    ACCOUNT_ADJUST_SYSTEM_ACCESS = GenericAccessRights.SELF_WRITE
    GENERIC_READ = GenericAccessRights.GENERIC_READ
    GENERIC_WRITE = GenericAccessRights.GENERIC_WRITE
    GENERIC_EXECUTE = GenericAccessRights.GENERIC_EXECUTE
    GENERIC_ALL = GenericAccessRights.GENERIC_ALL
    DELETE = GenericAccessRights.STANDARD_DELETE
    READ_CONTROL = GenericAccessRights.READ_CONTROL
    WRITE_DAC = GenericAccessRights.WRITE_DAC
    WRITE_OWNER = GenericAccessRights.WRITE_OWNER
    MAXIMUM_ALLOWED = GenericAccessRights.MAXIMUM_ALLOWED
    ACCESS_SYSTEM_SECURITY = GenericAccessRights.ACCESS_SYSTEM_SECURITY


class LsaPolicyAccessRights(IntEnum):
    POLICY_VIEW_LOCAL_INFORMATION = GenericAccessRights.CREATE_CHILD
    POLICY_VIEW_AUDIT_INFORMATION = GenericAccessRights.DELETE_CHILD
    POLICY_GET_PRIVATE_INFORMATION = GenericAccessRights.LIST_CHILDREN
    POLICY_TRUST_ADMIN = GenericAccessRights.SELF_WRITE
    POLICY_CREATE_ACCOUNT = GenericAccessRights.READ_PROPERTY
    POLICY_CREATE_SECRET = GenericAccessRights.WRITE_PROPERTY
    POLICY_CREATE_PRIVILEGE = GenericAccessRights.DELETE_TREE
    POLICY_SET_DEFAULT_QUOTA_LIMITS = GenericAccessRights.LIST_OBJECT
    POLICY_SET_AUDIT_REQUIREMENTS = GenericAccessRights.CONTROL_ACCESS
    POLICY_AUDIT_LOG_ADMIN = GenericAccessRights.ACCESS9
    POLICY_SERVER_ADMIN = GenericAccessRights.ACCESS10
    POLICY_LOOKUP_NAMES = GenericAccessRights.ACCESS11
    POLICY_NOTIFICATION = GenericAccessRights.ACCESS12
    GENERIC_READ = GenericAccessRights.GENERIC_READ
    GENERIC_WRITE = GenericAccessRights.GENERIC_WRITE
    GENERIC_EXECUTE = GenericAccessRights.GENERIC_EXECUTE
    GENERIC_ALL = GenericAccessRights.GENERIC_ALL
    DELETE = GenericAccessRights.STANDARD_DELETE
    READ_CONTROL = GenericAccessRights.READ_CONTROL
    WRITE_DAC = GenericAccessRights.WRITE_DAC
    WRITE_OWNER = GenericAccessRights.WRITE_OWNER
    MAXIMUM_ALLOWED = GenericAccessRights.MAXIMUM_ALLOWED
    ACCESS_SYSTEM_SECURITY = GenericAccessRights.ACCESS_SYSTEM_SECURITY


class LsaSecretAccessRights(IntEnum):
    SECRET_SET_VALUE = GenericAccessRights.CREATE_CHILD
    SECRET_QUERY_VALUE = GenericAccessRights.DELETE_CHILD
    GENERIC_READ = GenericAccessRights.GENERIC_READ
    GENERIC_WRITE = GenericAccessRights.GENERIC_WRITE
    GENERIC_EXECUTE = GenericAccessRights.GENERIC_EXECUTE
    GENERIC_ALL = GenericAccessRights.GENERIC_ALL
    DELETE = GenericAccessRights.STANDARD_DELETE
    READ_CONTROL = GenericAccessRights.READ_CONTROL
    WRITE_DAC = GenericAccessRights.WRITE_DAC
    WRITE_OWNER = GenericAccessRights.WRITE_OWNER
    MAXIMUM_ALLOWED = GenericAccessRights.MAXIMUM_ALLOWED
    ACCESS_SYSTEM_SECURITY = GenericAccessRights.ACCESS_SYSTEM_SECURITY


class LsaTrustedDomainAccessRights(IntEnum):
    TRUSTED_QUERY_DOMAIN_NAME = GenericAccessRights.CREATE_CHILD
    TRUSTED_QUERY_CONTROLLERS = GenericAccessRights.DELETE_CHILD
    TRUSTED_SET_CONTROLLERS = GenericAccessRights.LIST_CHILDREN
    TRUSTED_QUERY_POSIX = GenericAccessRights.SELF_WRITE
    TRUSTED_SET_POSIX = GenericAccessRights.READ_PROPERTY
    TRUSTED_SET_AUTH = GenericAccessRights.WRITE_PROPERTY
    TRUSTED_QUERY_AUTH = GenericAccessRights.DELETE_TREE
    GENERIC_READ = GenericAccessRights.GENERIC_READ
    GENERIC_WRITE = GenericAccessRights.GENERIC_WRITE
    GENERIC_EXECUTE = GenericAccessRights.GENERIC_EXECUTE
    GENERIC_ALL = GenericAccessRights.GENERIC_ALL
    DELETE = GenericAccessRights.STANDARD_DELETE
    READ_CONTROL = GenericAccessRights.READ_CONTROL
    WRITE_DAC = GenericAccessRights.WRITE_DAC
    WRITE_OWNER = GenericAccessRights.WRITE_OWNER
    MAXIMUM_ALLOWED = GenericAccessRights.MAXIMUM_ALLOWED
    ACCESS_SYSTEM_SECURITY = GenericAccessRights.ACCESS_SYSTEM_SECURITY


class SamAliasAccessRights(IntEnum):
    ALIAS_ADD_MEMBER = GenericAccessRights.CREATE_CHILD
    ALIAS_REMOVE_MEMBER = GenericAccessRights.DELETE_CHILD
    ALIAS_LIST_MEMBERS = GenericAccessRights.LIST_CHILDREN
    ALIAS_READ_INFORMATION = GenericAccessRights.SELF_WRITE
    ALIAS_WRITE_ACCOUNT = GenericAccessRights.READ_PROPERTY
    GENERIC_READ = GenericAccessRights.GENERIC_READ
    GENERIC_WRITE = GenericAccessRights.GENERIC_WRITE
    GENERIC_EXECUTE = GenericAccessRights.GENERIC_EXECUTE
    GENERIC_ALL = GenericAccessRights.GENERIC_ALL
    DELETE = GenericAccessRights.STANDARD_DELETE
    READ_CONTROL = GenericAccessRights.READ_CONTROL
    WRITE_DAC = GenericAccessRights.WRITE_DAC
    WRITE_OWNER = GenericAccessRights.WRITE_OWNER
    MAXIMUM_ALLOWED = GenericAccessRights.MAXIMUM_ALLOWED
    ACCESS_SYSTEM_SECURITY = GenericAccessRights.ACCESS_SYSTEM_SECURITY


class SamDomainAccessRights(IntEnum):
    DOMAIN_READ_PASSWORD_PARAMETERS = GenericAccessRights.CREATE_CHILD
    DOMAIN_WRITE_PASSWORD_PARAMS = GenericAccessRights.DELETE_CHILD
    DOMAIN_READ_OTHER_PARAMETERS = GenericAccessRights.LIST_CHILDREN
    DOMAIN_WRITE_OTHER_PARAMETERS = GenericAccessRights.SELF_WRITE
    DOMAIN_CREATE_USER = GenericAccessRights.READ_PROPERTY
    DOMAIN_CREATE_GROUP = GenericAccessRights.WRITE_PROPERTY
    DOMAIN_CREATE_ALIAS = GenericAccessRights.DELETE_TREE
    DOMAIN_GET_ALIAS_MEMBERSHIP = GenericAccessRights.LIST_OBJECT
    DOMAIN_LIST_ACCOUNTS = GenericAccessRights.CONTROL_ACCESS
    DOMAIN_LOOKUP = GenericAccessRights.ACCESS9
    DOMAIN_ADMINISTER_SERVER = GenericAccessRights.ACCESS10
    GENERIC_READ = GenericAccessRights.GENERIC_READ
    GENERIC_WRITE = GenericAccessRights.GENERIC_WRITE
    GENERIC_EXECUTE = GenericAccessRights.GENERIC_EXECUTE
    GENERIC_ALL = GenericAccessRights.GENERIC_ALL
    DELETE = GenericAccessRights.STANDARD_DELETE
    READ_CONTROL = GenericAccessRights.READ_CONTROL
    WRITE_DAC = GenericAccessRights.WRITE_DAC
    WRITE_OWNER = GenericAccessRights.WRITE_OWNER
    MAXIMUM_ALLOWED = GenericAccessRights.MAXIMUM_ALLOWED
    ACCESS_SYSTEM_SECURITY = GenericAccessRights.ACCESS_SYSTEM_SECURITY


class SamGroupAccessRights(IntEnum):
    GROUP_READ_INFORMATION = GenericAccessRights.CREATE_CHILD
    GROUP_WRITE_ACCOUNT = GenericAccessRights.DELETE_CHILD
    GROUP_ADD_MEMBER = GenericAccessRights.LIST_CHILDREN
    GROUP_REMOVE_MEMBER = GenericAccessRights.SELF_WRITE
    GROUP_LIST_MEMBERS = GenericAccessRights.READ_PROPERTY
    GENERIC_READ = GenericAccessRights.GENERIC_READ
    GENERIC_WRITE = GenericAccessRights.GENERIC_WRITE
    GENERIC_EXECUTE = GenericAccessRights.GENERIC_EXECUTE
    GENERIC_ALL = GenericAccessRights.GENERIC_ALL
    DELETE = GenericAccessRights.STANDARD_DELETE
    READ_CONTROL = GenericAccessRights.READ_CONTROL
    WRITE_DAC = GenericAccessRights.WRITE_DAC
    WRITE_OWNER = GenericAccessRights.WRITE_OWNER
    MAXIMUM_ALLOWED = GenericAccessRights.MAXIMUM_ALLOWED
    ACCESS_SYSTEM_SECURITY = GenericAccessRights.ACCESS_SYSTEM_SECURITY


class SamServerAccessRights(IntEnum):
    SAM_SERVER_CONNECT = GenericAccessRights.CREATE_CHILD
    SAM_SERVER_SHUTDOWN = GenericAccessRights.DELETE_CHILD
    SAM_SERVER_INITIALIZE = GenericAccessRights.LIST_CHILDREN
    SAM_SERVER_CREATE_DOMAIN = GenericAccessRights.SELF_WRITE
    SAM_SERVER_ENUMERATE_DOMAINS = GenericAccessRights.READ_PROPERTY
    SAM_SERVER_LOOKUP_DOMAIN = GenericAccessRights.WRITE_PROPERTY
    GENERIC_READ = GenericAccessRights.GENERIC_READ
    GENERIC_WRITE = GenericAccessRights.GENERIC_WRITE
    GENERIC_EXECUTE = GenericAccessRights.GENERIC_EXECUTE
    GENERIC_ALL = GenericAccessRights.GENERIC_ALL
    DELETE = GenericAccessRights.STANDARD_DELETE
    READ_CONTROL = GenericAccessRights.READ_CONTROL
    WRITE_DAC = GenericAccessRights.WRITE_DAC
    WRITE_OWNER = GenericAccessRights.WRITE_OWNER
    MAXIMUM_ALLOWED = GenericAccessRights.MAXIMUM_ALLOWED
    ACCESS_SYSTEM_SECURITY = GenericAccessRights.ACCESS_SYSTEM_SECURITY


class SamUserAccessRights(IntEnum):
    USER_READ_GENERAL = GenericAccessRights.CREATE_CHILD
    USER_READ_PREFERENCES = GenericAccessRights.DELETE_CHILD
    USER_WRITE_PREFERENCES = GenericAccessRights.LIST_CHILDREN
    USER_READ_LOGON = GenericAccessRights.SELF_WRITE
    USER_READ_ACCOUNT = GenericAccessRights.READ_PROPERTY
    USER_WRITE_ACCOUNT = GenericAccessRights.WRITE_PROPERTY
    USER_CHANGE_PASSWORD = GenericAccessRights.DELETE_TREE
    USER_FORCE_PASSWORD_CHANGE = GenericAccessRights.LIST_OBJECT
    USER_LIST_GROUPS = GenericAccessRights.CONTROL_ACCESS
    USER_READ_GROUP_INFORMATION = GenericAccessRights.ACCESS9
    USER_WRITE_GROUP_INFORMATION = GenericAccessRights.ACCESS10
    GENERIC_READ = GenericAccessRights.GENERIC_READ
    GENERIC_WRITE = GenericAccessRights.GENERIC_WRITE
    GENERIC_EXECUTE = GenericAccessRights.GENERIC_EXECUTE
    GENERIC_ALL = GenericAccessRights.GENERIC_ALL
    DELETE = GenericAccessRights.STANDARD_DELETE
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
