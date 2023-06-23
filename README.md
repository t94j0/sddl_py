# Install
```
pip3 install sddl-parser
```

# Usage
Parse an SDDL string

```py
>> from sddl_parser import parse_sddl, SDDL, DACL, ACE
>> sddl = "O:SYG:SYD:AI(A;ID;FA;;;SY)"
>> parse_sddl(sddl)

SDDL(
    owner='LOCAL_SYSTEM',
    group='LOCAL_SYSTEM',
    dacl=DACL(
        flags=['SDDL_AUTO_INHERITED'],
        aces=[
            ACE(
                type='ACCESS_ALLOWED',
                flags=['INHERITED'],
                rights=['FILE_ALL'],
                object_guid='',
                inherit_object_guid='',
                sid='LOCAL_SYSTEM',
                conditional_ace=None
            )
        ]
    ), sacl=None)
```

Parse an ACE

```py
>> from sddl_parser import parse_ace, ACE
>> ace = "(A;ID;0x1200a9;;;AC)"
>> parse_ace(ace)
ACE(
    type="ACCESS_ALLOWED",
    flags=["INHERITED"],
    rights=["FILE_READ", "WRITE_PROPERTY"],
    object_guid="",
    inherit_object_guid="",
    sid="ALL_APP_PACKAGES",
)
```

# TODO
1. Convert rights and types to enum

Instead of the ACE example, I'd really like to have an enum for all the common properties so that mispellings become a compile time error

```py
ACE(
    type=AceType.ACCESS_ALLOWED,
    flags=[AceFlags.INHERITED],
    ...
)
```

2. Allow identifiers (D:, O:, S:) to be out of order. I haven't run into this on any SDDLs on my system, but I'm sure it exists somewhere out there

# Thanks
Thanks to An0ther0ne for compiling the constants for ACEs