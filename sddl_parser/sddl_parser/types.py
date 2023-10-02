from typing import List, Optional, Set, Type, Union
from dataclasses import dataclass, field
from sddl_parser.ace_rights_enums import AllRightsT
from sddl_parser.enums import AceFlags, AceType, SDDLFlags
from sddl_parser.sid_enum import SIDEnum

SID = Union[SIDEnum, str]


def rights_to_type(rights: int, access_map: Type[AllRightsT]) -> Set[AllRightsT]:
    rs = set()
    for r in access_map:
        if (rights & r) == r:
            rs.add(access_map(r))
    return rs


@dataclass
class ACE:
    """
    https://learn.microsoft.com/en-us/windows/win32/secauthz/ace-strings
    """

    type: AceType
    flags: Set[AceFlags]
    object_guid: str
    rights_int: int
    inherit_object_guid: str
    sid: SID
    conditional_ace: Optional[str] = None
    rights: Set[AllRightsT] = field(default_factory=set)

    def as_type(self, access_mask: Type[AllRightsT]):
        self.rights = rights_to_type(self.rights_int, access_mask)
        return self

    def pformat(self, indent: int = 0) -> str:
        flags = "|".join([f.name for f in self.flags])
        rights = "|".join([r.name for r in self.rights])
        sid = self.sid.name if isinstance(self.sid, SIDEnum) else self.sid
        return f"{' '*indent}{self.type.name} {flags} {rights} {sid}"

    def asdict(self) -> dict:
        return {
            "type": self.type.name,
            "flags": [f.name for f in self.flags],
            "rights": [r.name for r in self.rights],
            "sid": self.sid.name if isinstance(self.sid, SIDEnum) else self.sid,
        }


@dataclass
class ACL:
    flags: Set[SDDLFlags]
    aces: List[ACE]

    def pformat(self, indent: int = 0) -> str:
        return (
            f"{' '*indent}{' '.join([f'{f.name}' for f in self.flags])}\n"
            + "\n".join([ace.pformat(indent + 2) for ace in self.aces])
        )

    def asdict(self) -> dict:
        return {
            "flags": [f.name for f in self.flags],
            "aces": [ace.asdict() for ace in self.aces],
        }


@dataclass
class SDDL:
    owner: SID
    group: SID
    dacl: Optional[ACL] = None
    sacl: Optional[ACL] = None

    def as_type(self, access_mask: Type[AllRightsT]):
        if self.dacl is not None:
            for ace in self.dacl.aces:
                ace.rights = rights_to_type(ace.rights_int, access_mask)
        if self.sacl is not None:
            for ace in self.sacl.aces:
                ace.rights = rights_to_type(ace.rights_int, access_mask)
        return self

    def pformat(self, indent: int = 0) -> str:
        owner = self.owner.name if isinstance(self.owner, SIDEnum) else self.owner
        group = self.group.name if isinstance(self.group, SIDEnum) else self.group
        return (
            f"{' '*indent}Owner: {owner}\n"
            + f"{' '*indent}Group: {group}\n"
            + f"{' '*indent}DACL:\n{self.dacl.pformat(indent+2) if self.dacl is not None else ''}\n"
            + f"{' '*indent}SACL:\n{self.sacl.pformat(indent+2) if self.sacl is not None else ''}"
        )

    def asdict(self) -> dict:
        return {
            "owner": self.owner.name if isinstance(self.owner, SIDEnum) else self.owner,
            "group": self.group.name if isinstance(self.group, SIDEnum) else self.group,
            "dacl": self.dacl.asdict() if self.dacl is not None else None,
            "sacl": self.sacl.asdict() if self.sacl is not None else None,
        }
