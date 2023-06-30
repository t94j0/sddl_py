from sddl_parser.types import SDDL, ACE
from sddl_parser.parser import sddl_item, parse_ace_entry
from sddl_parser.ace_rights_enums import GenericAccessRights, AllRightsT
from typing import Dict


def convert_sddl_sids(sddl: SDDL, sids: Dict[str, str]) -> SDDL:
    if sids == {}:
        return sddl
    if type(sddl.owner) == str:
        sddl.owner = sids.get(sddl.owner, sddl.owner)
    if type(sddl.group) == str:
        sddl.group = sids.get(sddl.group, sddl.group)
    if sddl.dacl is not None:
        for ace in sddl.dacl.aces:
            if type(ace.sid) == str:
                ace.sid = sids.get(ace.sid, ace.sid)
    if sddl.sacl is not None:
        for ace in sddl.sacl.aces:
            if type(ace.sid) == str:
                ace.sid = sids.get(ace.sid, ace.sid)
    return sddl


def convert_ace_sids(sddl: ACE, sids: Dict[str, str]) -> ACE:
    if sids == {}:
        return sddl
    if type(sddl.sid) == str:
        sddl.sid = sids.get(sddl.sid, sddl.sid)
    return sddl


def parse_sddl(
    sddl: str,
    as_type: type[AllRightsT] = GenericAccessRights,
    sidmap: Dict[str, str] = {},
) -> SDDL:
    sddl_entry: SDDL = sddl_item.parse(sddl)
    return convert_sddl_sids(sddl_entry, sidmap).as_type(as_type)


def parse_ace(
    ace: str,
    as_type: type[AllRightsT] = GenericAccessRights,
    sidmap: Dict[str, str] = {},
) -> ACE:
    ace_entry: ACE = parse_ace_entry().parse(ace)
    return convert_ace_sids(ace_entry, sidmap).as_type(as_type)
