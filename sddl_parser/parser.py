from parsy import string, regex, char_from, seq, test_char, Parser, generate
from functools import reduce
from operator import or_
from typing import List, Dict, Any, Callable
from functools import partial
from sddl_parser.dictionary import (
    SDDL_SIDS,
    SDDL_FLAGS,
    ACE_TYPE,
    ACE_FLAGS,
    ACE_RIGHTS,
)
from sddl_parser.types import ACE, DACL, SDDL, SACL


def parser_from_list(xs: List[str]) -> Parser:
    if not xs:
        raise ValueError("list is empty")
    return reduce(or_, map(string, xs))


def create_parser_from_dict(
    mx: Dict[str, Any],
    collect: Callable[[Dict[str, Any], str], Any] = lambda xs, k: xs[k],
) -> Parser:
    """
    Map a value from a dictionary. The dictionary is passed as an argument to the function.
    Optional argument `collect` is used to collect the value from the dictionary.
    """
    return parser_from_list(list(mx.keys())).map(partial(collect, mx))


def take_till(cond: Callable[[str], bool], description: str) -> Parser:
    return (
        test_char(lambda x: not cond(x), description)
        .many()
        .combine(lambda *x: "".join(x))
    )


def take_till_char(c: str) -> Parser:
    return take_till(lambda x: x == c, f"not {c}")


def take_till_paren() -> Parser:
    return take_till(lambda x: x == "(" or x == ")", "not ( or )")


def parse_sid() -> Parser:
    return regex(r"S-1(?:-\d+)*")


def parse_sid_field() -> Parser:
    well_known_sid = create_parser_from_dict(SDDL_SIDS)
    return well_known_sid | parse_sid()


def parse_owner() -> Parser:
    owner_identifier = string("O:")
    return owner_identifier >> parse_sid_field()


def parse_group() -> Parser:
    group_identifier = string("G:")
    return group_identifier >> parse_sid_field()


sacl_identifier = string("S:")
dacl_identifier = string("D:")
sddl_flags = create_parser_from_dict(SDDL_FLAGS).map(lambda x: x.split("|"))

ace_types = create_parser_from_dict(ACE_TYPE, lambda xs, k: xs[k])


def parse_ace_flags() -> Parser:
    def flags_map(x: str) -> List[str]:
        split_by_two = map("".join, zip(*[iter(x)] * 2))
        return list(map(lambda x: ACE_FLAGS[x][0], split_by_two))

    # TODO: Actually parse here instead of just grabbing till ;
    return (take_till_char(";").map(flags_map)) | string("")


def parse_ace_rights() -> Parser:
    hex_ace_rights = regex(r"0x[0-9a-fA-F]+").map(lambda x: int(x, 16))

    well_known_ace_rights = (
        parser_from_list(list(ACE_RIGHTS.keys()))
        .many()
        .map(lambda xs: sum(map(lambda x: ACE_RIGHTS[x], xs)))
    )
    return hex_ace_rights | well_known_ace_rights


# I've never not seen these empty, but they're in the spec
object_guid = string("")
inherit_object_guid = string("")


def parse_conditional_ace() -> Parser:
    """
    Conditional ACEs are wrapped in a parenthetical. This parser will parse the
    contents of the parenthetical.  Inside the parenthesis, there can be multiple
    parentheticals, so we need to parse until we reach the end of the
    parenthetical, but not go over into the next ACE. This means we need to
    match up every open paren with a close paren and only consume a single group

    https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-definition-language-for-conditional-aces-
    """
    junk = take_till_paren()

    @generate
    def group():
        c1 = yield junk
        c2 = yield string("(")
        c3 = yield expr
        c4 = yield string(")")
        c5 = yield junk
        return c1 + c2 + c3 + c4 + c5

    expr = group | junk | string("")
    return string(";").then(expr)


def parse_ace_entry() -> Parser:
    """
    https://learn.microsoft.com/en-us/windows/win32/secauthz/ace-strings
    Example: (A;;CCLCSWLOCRRC;;;SU)
    """
    return string("(") >> (
        seq(
            type=ace_types << char_from(";"),
            flags=parse_ace_flags() << char_from(";"),
            rights_int=parse_ace_rights() << char_from(";"),
            object_guid=object_guid << char_from(";"),
            inherit_object_guid=inherit_object_guid << char_from(";"),
            sid=parse_sid_field(),
            conditional_ace=parse_conditional_ace().optional(),
        )
        << string(")")
    ).combine_dict(ACE)


dacl = seq(
    flags=dacl_identifier >> sddl_flags, aces=parse_ace_entry().many()
).combine_dict(DACL)

sacl = seq(
    flags=sacl_identifier >> sddl_flags, aces=parse_ace_entry().many()
).combine_dict(SACL)


# https://learn.microsoft.com/en-us/windows/win32/secauthz/sid-strings?source=recommendations
# Example: O:SYG:SYD:(A;ID;FA;;;SY)
# TODO: Allow entries to be out of order.
# Something like sddl_item = parse_owner() | parse_group() | dacl | sacl
# Then sddl_entry = sddl_item.many(), then just map each type to a single object
# Not sure how you ensure only one of each type. Maybe just post-processing,
# but I feel like that could be done in the parser
sddl_item = seq(
    owner=parse_owner(), group=parse_group(), dacl=dacl.optional(), sacl=sacl.optional()
).combine_dict(SDDL)
