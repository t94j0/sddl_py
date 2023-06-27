from sddl_parser.types import SDDL, ACE
from sddl_parser.parser import sddl_item, parse_ace_entry
from sddl_parser.rights_enums import GenericAccessRights
from enum import IntEnum


def parse_sddl(sddl: str, as_type: IntEnum = GenericAccessRights) -> SDDL:
    sddl_entry: SDDL = sddl_item.parse(sddl)
    return sddl_entry.as_type(as_type)


def parse_ace(ace: str, as_type: IntEnum = GenericAccessRights) -> ACE:
    ace_entry: ACE = parse_ace_entry().parse(ace)
    return ace_entry.as_type(as_type)
