from typing import List, Optional, Set
from enum import IntEnum
from dataclasses import dataclass, field


def rights_to_type(rights: int, access_map: IntEnum) -> List[int]:
    rs = set()
    for r in access_map.__members__.values():
        if (rights & r) == r:
            rs.add(access_map(r))
    return rs


@dataclass
class ACE:
    """
    https://learn.microsoft.com/en-us/windows/win32/secauthz/ace-strings
    """

    type: str
    flags: List[str]
    object_guid: str
    rights_int: int
    inherit_object_guid: str
    sid: str
    conditional_ace: Optional[str] = None
    rights: Set[int] = field(default_factory=set)

    def as_type(self, access_mask: IntEnum):
        self.rights = rights_to_type(self.rights_int, access_mask)
        return self


@dataclass
class DACL:
    flags: List[str]
    aces: List[ACE]


@dataclass
class SACL:
    flags: List[str]
    aces: List[ACE]


@dataclass
class SDDL:
    owner: str
    group: str
    dacl: Optional[DACL] = None
    sacl: Optional[SACL] = None

    def as_type(self, access_mask: IntEnum):
        if self.dacl is not None:
            for ace in self.dacl.aces:
                ace.rights = rights_to_type(ace.rights_int, access_mask)
        if self.sacl is not None:
            for ace in self.sacl.aces:
                ace.rights = rights_to_type(ace.rights_int, access_mask)
        return self
