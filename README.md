# Install
```
pip3 install sddl-parser
```

# Usage
Parse an SDDL string

```py
>> from sddl_parser import parse_sddl
>> sddl = "O:SYG:SYD:AI(A;ID;GA;;;SY)"
>> parse_sddl(sddl)
SDDL(
    owner="LOCAL_SYSTEM",
    group="LOCAL_SYSTEM",
    dacl=DACL(
        flags=["SDDL_AUTO_INHERITED"],
        aces=[
            ACE(
                type=AceType.ACCESS_ALLOWED,
                flags=["INHERITED"],
                object_guid="",
                rights_int=268435456,
                inherit_object_guid="",
                sid="LOCAL_SYSTEM",
                conditional_ace=None,
                rights={GenericAccessRights.GENERIC_ALL},
            )
        ],
    ),
    sacl=None,
)
```

Parse an ACE

```py
>> from sddl_parser import parse_ace
>> ace = "(A;ID;0x10030;;;AC)"
>> parse_ace(ace)
ACE(
    type=AceType.ACCESS_ALLOWED,
    flags=["INHERITED"],
    object_guid="",
    rights_int=65584,
    inherit_object_guid="",
    sid="ALL_APP_PACKAGES",
    conditional_ace=None,
    rights={
        GenericAccessRights.ACCESS4,
        GenericAccessRights.DELETE,
        GenericAccessRights.ACCESS5,
    },
)
```

See that `GenericAccessRights.ACCESS4` is returned. That's an indication that the SDDL type should be specified. To get more accurate rights, use `.as_type()` on the object or pass the Rights object to the parse_ace function

```py
>> from sddl_parser import parse_ace, FileAccessRights
>> ace = "(A;ID;0x1200a9;;;AC)"
>> # alternatively, run parse_ace(ace, FileAccessRights)
>> parse_ace(ace).as_type(FileAccessRights)
ACE(
    type=AceType.ACCESS_ALLOWED,
    flags=["INHERITED"],
    object_guid="",
    rights_int=65584,
    inherit_object_guid="",
    sid="ALL_APP_PACKAGES",
    conditional_ace=None,
    rights={
        FileAccessRights.FILE_WRITE_EA,
        FileAccessRights.DELETE,
        FileAccessRights.FILE_EXECUTE,
    },
)
```

All rights are IntEnums, so if you want to check for generic rights, `FileAccessRights.DELETE` is equivalent to `GenericAccessRights.DELETE`

# Access Rights Available

All right enums are given here

```
>> from sddl_parser import rights_enums
>> for x in dir(rights_enums):
>>   print(i)
AlpcAccessRights
AuditAccessRights
DebugAccessRights
DesktopAccessRights
DirectoryAccessRights
DirectoryServiceAccessRights
EnlistmentAccessRights
EventAccessRights
FileAccessRights
FileDirectoryAccessRights
FilterConnectionPortAccessRights
FirewallAccessRights
FirewallFilterAccessRights
GenericAccessRights
IoCompletionAccessRights
JobAccessRights
KeyAccessRights
LsaAccountAccessRights
LsaPolicyAccessRights
LsaSecretAccessRights
LsaTrustedDomainAccessRights
MemoryPartitionAccessRights
MutantAccessRights
PrintSpoolerAccessRights
ProcessAccessRights
RegistryKeyAccessRights
RegistryTransactionAccessRights
ResourceManagerAccessRights
SamAliasAccessRights
SamDomainAccessRights
SamGroupAccessRights
SamServerAccessRights
SamUserAccessRights
SemaphoreAccessRights
ServiceAccessRights
ServiceControlManagerAccessRights
SessionAccessRights
SymbolicLinkAccessRights
ThreadAccessRights
TimerAccessRights
TokenAccessRights
TraceAccessRights
TransactionAccessRights
TransactionManagerAccessRights
WindowStationAccessRights
WnfAccessRights
```

# Shoulders of Giants
[An0ther0ne]: https://github.com/An0ther0ne
[James Forshaw]: https://twitter.com/tiraniddo
