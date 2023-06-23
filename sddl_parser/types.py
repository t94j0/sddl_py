from typing import List, Union, Optional
from dataclasses import dataclass


@dataclass
class ACE:
    """
    https://learn.microsoft.com/en-us/windows/win32/secauthz/ace-strings
    """

    type: str
    flags: List[str]
    rights: List[Union[str, int]]
    object_guid: str
    inherit_object_guid: str
    sid: str
    conditional_ace: Optional[str] = None


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
