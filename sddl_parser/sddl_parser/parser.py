from parsy import (
    string,
    peek,
    regex,
    char_from,
    seq,
    test_char,
    Parser,
    generate,
    decimal_digit,
)
import parsy
from functools import reduce
from operator import or_
from typing import List, Dict, Any, Callable
from functools import partial
from sddl_parser.well_known_dictionary import (
    SDDL_SIDS,
    SDDL_FLAGS,
    ACE_TYPE,
    ACE_FLAGS,
    ACE_RIGHTS,
)
from sddl_parser.types import ACE, SDDL, ACL
from sddl_parser.enums import SDDLFlags
from sddl_parser.parser_sid import parse_sid
from sddl_parser.parser_conditional_ace import parse_conditional_ace_entry


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


def parse_sddl_flags() -> Parser:
    def map_flags(xs: List[str]):
        if xs == []:
            return {SDDLFlags.NO_ACCESS_CONTROL}
        return {SDDL_FLAGS[x] for x in xs}

    return parser_from_list(list(SDDL_FLAGS)).many().map(map_flags)


ace_types = create_parser_from_dict(ACE_TYPE, lambda xs, k: xs[k])


def parse_ace_flags() -> Parser:
    return (
        parser_from_list(list(ACE_FLAGS.keys()))
        .many()
        .map(lambda xs: set(map(lambda x: ACE_FLAGS[x], xs)))
    )


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
    @generate
    def parse_cace():
        yield string(";")
        cas = yield peek(regex(r"\(.*?\)").map(str))
        data = yield parse_conditional_ace_entry()
        return cas, data

    return parse_cace


def parse_ace_entry() -> Parser:
    # Use a generate function to construct the final ACE dictionary
    @generate
    def wrapped_parser():
        yield string("(")
        types = yield ace_types << char_from(";")
        flags = yield parse_ace_flags() << char_from(";")
        rights_int = yield parse_ace_rights() << char_from(";")
        oguid = yield object_guid << char_from(";")
        ioguid = yield inherit_object_guid << char_from(";")
        sid = yield parse_sid_field()
        conditional_ace = yield parse_conditional_ace().optional()

        ca_str = conditional_ace[0] if conditional_ace else None
        ca_o = conditional_ace[1] if conditional_ace else None

        yield string(")")

        return {
            "type": types,
            "flags": flags,
            "rights_int": rights_int,
            "object_guid": oguid,
            "inherit_object_guid": ioguid,
            "sid": sid,
            "conditional_ace_string": ca_str,
            "conditional_ace": ca_o,
        }

    return wrapped_parser.combine_dict(ACE)


dacl = seq(
    flags=dacl_identifier >> parse_sddl_flags(), aces=parse_ace_entry().many()
).combine_dict(ACL)

sacl = seq(
    flags=sacl_identifier >> parse_sddl_flags(), aces=parse_ace_entry().many()
).combine_dict(ACL)


# https://learn.microsoft.com/en-us/windows/win32/secauthz/sid-strings?source=recommendations
# Example: O:SYG:SYD:(A;ID;FA;;;SY)
# Something like sddl_item = parse_owner() | parse_group() | dacl | sacl
# Then sddl_entry = sddl_item.many(), then just map each type to a single object
# Not sure how you ensure only one of each type. Maybe just post-processing,
# but I feel like that could be done in the parser
sddl_item = seq(
    owner=parse_owner(), group=parse_group(), dacl=dacl.optional(), sacl=sacl.optional()
).combine_dict(SDDL)
