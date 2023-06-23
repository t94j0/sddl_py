from sddl_parser.types import SDDL, ACE
from sddl_parser.parser import sddl_item


def parse_sddl(sddl: str) -> SDDL:
    return sddl_item.parse(sddl)


def parse_ace(ace: str) -> ACE:
    return parse_ace().parse(ace)
