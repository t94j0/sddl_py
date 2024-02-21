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
    owner=<SIDEnum.LOCAL_SYSTEM: 'S-1-5-18'>,
    group=<SIDEnum.LOCAL_SYSTEM: 'S-1-5-18'>,
    dacl=ACL(
        flags={<SDDLFlags.SDDL_AUTO_INHERITED: 2>},
        aces=[
            ACE(type=<AceType.ACCESS_ALLOWED: 0>,
                flags={<AceFlags.INHERITED: 16>},
                object_guid='',
                rights_int=268435456,
                inherit_object_guid='',
                sid=<SIDEnum.LOCAL_SYSTEM: 'S-1-5-18'>,
                conditional_ace_string=None,
                conditional_ace=None,
                rights={<GenericAccessRights.GENERIC_ALL: 268435456>}
            )
        ]),
    sacl=None
)
```

Parse an ACE

```py
>> from sddl_parser import parse_ace
>> ace = "(A;ID;0x10030;;;AC)"
>> parse_ace(ace)
ACE(type=<AceType.ACCESS_ALLOWED: 0>,
    flags={<AceFlags.INHERITED: 16>},
    object_guid='',
    rights_int=65584,
    inherit_object_guid='',
    sid=<SIDEnum.ALL_APP_PACKAGES: 'S-1-15-2-1'>,
    conditional_ace_string=None,
    conditional_ace=None,
    rights={
        <GenericAccessRights.READ_PROPERTY: 16>,
        <GenericAccessRights.WRITE_PROPERTY: 32>,
        <GenericAccessRights.STANDARD_DELETE: 65536>
    }
)
```

See that `GenericAccessRights.ACCESS4` is returned. That's an indication that the SDDL type should be specified. To get more accurate rights, use `.as_type()` on the object or pass the Rights object to the parse_ace function

```py
>> from sddl_parser import parse_ace, FileAccessRights
>> ace = "(A;ID;0x1200a9;;;AC)"
>> # alternatively, run parse_ace(ace, FileAccessRights)
>> parse_ace(ace).as_type(FileAccessRights)
ACE(type=<AceType.ACCESS_ALLOWED: 0>,
    flags={<AceFlags.INHERITED: 16>},
    object_guid='',
    rights_int=1179817,
    inherit_object_guid='',
    sid=<SIDEnum.ALL_APP_PACKAGES: 'S-1-15-2-1'>,
    conditional_ace_string=None,
    conditional_ace=None,
    rights={
        <FileAccessRights.FILE_READ_DATA: 1>,
        <FileAccessRights.FILE_READ_EA: 8>,
        <FileAccessRights.FILE_EXECUTE: 32>,
        <FileAccessRights.FILE_READ_ATTRIBUTES: 128>,
        <FileAccessRights.READ_CONTROL: 131072>,
        <FileAccessRights.SYNCHRONIZE: 1048576>,
        <FileAccessRights.FILE_GENERIC_READ: 1179785>,
        <FileAccessRights.FILE_GENERIC_EXECUTE: 1179808>
    }
)
```

All rights are IntEnums, so if you want to check for generic rights, `FileAccessRights.DELETE` is equivalent to `GenericAccessRights.DELETE`

If you want to map SIDs to strings, you can pass in `sidmap`:

```py
>>> from sddl_parser import api
>>> test = "O:S-1-20-20-20G:SYD:"
>>> sidmap = {"S-1-20-20-20": "DOMAIN\\user"}
>>> api.parse_sddl(test, sidmap=sidmap)
SDDL(
    owner="DOMAIN\\user",
    group=SIDEnum.LOCAL_SYSTEM,
    dacl=ACL(flags={SDDLFlags.NO_ACCESS_CONTROL}, aces=[]),
    sacl=None,
)
```

## Conditional ACE

From MS docs:
> A Conditional ACE allows a conditional expression to be evaluated when an access check

The sddl_parser library will return the conditional ACE string as well as a custom intermediate language representation of the conditional ACE. It's not the prettiest IL. I'm open to suggestions.

The ABNF definition for conditional ACEs is defined in [[MS-DYP] - 2.5.1.1](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/f4296d69-1c0f-491f-9587-a960b292d070).

```py
>>> from pprint import pprint
>>> test = '(XA;ID;0x1200a9;;;BU;(WIN://SYSAPPID Contains "MICROSOFT.MICROSOFTEDGE.STABLE_ABC123"))'
>>> parse_ace(test)
ACE(type=<AceType.ACCESS_ALLOWED_CALLBACK: 9>,
    flags={<AceFlags.INHERITED: 16>},
    object_guid='',
    rights_int=1179817,
    inherit_object_guid='',
    sid=<SIDEnum.BUILTIN_USERS: 'S-1-5-32-545'>,
    conditional_ace_string='(WIN://SYSAPPID Contains "MICROSOFT.MICROSOFTEDGE.STABLE_ABC123")',
    conditional_ace=[
        ('ATTRNAME', 'WIN://SYSAPPID'),
        ('OPERATION', 'Contains'),
        ('VALUE', 'MICROSOFT.MICROSOFTEDGE.STABLE_ABC123')
    ],
    rights={
        <GenericAccessRights.CREATE_CHILD: 1>,
        <GenericAccessRights.SELF_WRITE: 8>,
        <GenericAccessRights.WRITE_PROPERTY: 32>,
        <GenericAccessRights.LIST_OBJECT: 128>,
        <GenericAccessRights.READ_CONTROL: 131072>,
        <GenericAccessRights.SYNCHRONIZE: 1048576>
    }
)
>>> test = '(XA;ID;0x1200a9;;;BU;(@User.Title=="PM" && (@User.Division=="Finance" || @User.Division == "Sales")))'
>>> parse_ace(test)
ACE(type=<AceType.ACCESS_ALLOWED_CALLBACK: 9>,
    flags={<AceFlags.INHERITED: 16>},
    object_guid='',
    rights_int=1179817,
    inherit_object_guid='',
    sid=<SIDEnum.BUILTIN_USERS: 'S-1-5-32-545'>,
    conditional_ace_string='(@User.Title=="PM" && (@User.Division=="Finance" || @User.Division == "Sales")',
    conditional_ace={
        'TYPE': 'AND',
        'VALUES': [
            [('ATTRNAME', '@user.Title'), ('OPERATION', '=='), ('VALUE', 'PM')],
            {
                'TYPE': 'GROUP', 'VALUE': {
                    'TYPE': 'OR',
                    'VALUES': [
                        [('ATTRNAME', '@user.Division'), ('OPERATION', '=='), ('VALUE', 'Finance')],
                        [('ATTRNAME', '@user.Division'), ('OPERATION', '=='), ('VALUE', 'Sales')]
                    ]
                }
            }
        ]
    },
    rights={
        <GenericAccessRights.CREATE_CHILD: 1>,
        <GenericAccessRights.SELF_WRITE: 8>,
        <GenericAccessRights.WRITE_PROPERTY: 32>,
        <GenericAccessRights.LIST_OBJECT: 128>,
        <GenericAccessRights.READ_CONTROL: 131072>,
        <GenericAccessRights.SYNCHRONIZE: 1048576>
    }
)
```

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
- [An0ther0ne]
- [James Forshaw]

[An0ther0ne]: https://github.com/An0ther0ne
[James Forshaw]: https://twitter.com/tiraniddo
