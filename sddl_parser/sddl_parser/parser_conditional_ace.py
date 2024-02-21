from parsy import (
    Parser,
    whitespace,
    regex,
    string,
    letter,
    decimal_digit,
    seq,
    forward_declaration,
)
from sddl_parser.parser_sid import parse_sid


def parse_conditional_ace_entry() -> Parser:
    wspace = whitespace

    inside_quotes = regex(r'\\.|[^"]')
    # char-string = DQUOTE *(CHAR) DQUOTE
    char_string = string('"') >> inside_quotes.many().optional().concat().skip(
        string('"')
    )
    hexdig = regex(r"[0-9a-fA-F]")
    # value = int-64 / char-string / octet-string
    # int-64 = ["+" / "-"] ("0x" 1*HEXDIG) / ("0" 1*%x30-37) / 1*DIGIT
    # octet-string = "#" *(2HEXDIG)
    # Haven't seen other options, if you run into it, write it
    value = char_string
    # value-array = value [wspace] / "{" [wspace] value [wspace] *("," [wspace] value [wspace]) "}"
    # Haven't seen other options, if you run into it, write it
    value_array = value << wspace.optional()
    hexstr = string("%") >> hexdig.times(4)

    # Not copying
    lit_char = (
        string("#")
        | string("$")
        | string("'")
        | string("*")
        | string("+")
        | string("-")
        | string(".")
        | string("/")
        | string(":")
        | string(";")
        | string("?")
        | string("@")
        | string("[")
        | string("\\")
        | string("]")
        | string("^")
        | string("_")
        | string("`")
        | string("{")
        | string("}")
        | string("~")
        | hexstr
    )

    # attr-char1 = 1*(ALPHA / DIGIT / ":" / "." / "/" / "_")
    attr_char_1 = (
        letter | decimal_digit | string(":") | string(".") | string("/") | string("_")
    )

    # attr-name1 = attr-char1 *(attr-char1 / "@")
    attr_name_1 = (
        attr_char_1.at_least(1).concat() + (attr_char_1 | string("@")).many().concat()
    )

    # attr-char2 = attr-char1 / lit-char
    attr_char_2 = attr_char_1 | lit_char

    # attr-name2 = ("@user." / "@device." / "@resource.") 1*attr-char2
    attr_name_2 = (
        string("@user.", transform=lambda s: s.upper())
        | string("@device.", transform=lambda s: s.upper())
        | string("@resource.", transform=lambda s: s.upper())
    ) + attr_char_2.many().concat()

    # attr-name = attr-name1 / attr-name2
    attr_name = attr_name_1 | attr_name_2

    # contains-op = attr-name wspace ("Contains" / "Not_Contains") wspace (attr-name2 / valuearray)
    contains_op = seq(
        attr_name.tag("ATTRNAME") << wspace,
        (string("Contains") | string("Not_Contains")).tag("OPERATION") << wspace,
        (attr_name_2 | value_array).tag("VALUE"),
    )

    # rel-op = attr-name [wspace] ("<" / "<=" / ">" / ">=") [wspace] (attr-name2 / value)
    rel_op = seq(
        attr_name.tag("ATTRNAME") << wspace.optional(),
        (string("<") | string("<=") | string(">") | string(">=")).tag("OPERATION")
        << wspace.optional(),
        (attr_name_2 | value).tag("VALUE"),
    )

    # rel_op2 is defined, but not referenced in the spec
    rel_op_2 = seq(
        attr_name.tag("ATTRNAME") << wspace.optional(),
        (string("==") | string("!=")).tag("OPERATION") << wspace.optional(),
        (attr_name_2 | value_array).tag("VALUE"),
    )

    # exists-op = ( "Exists" / "Not_exists") wspace attr-name
    exists_op = seq(
        (string("Exists") | string("Not_exists")).tag("OPERATION") << wspace,
        attr_name.tag("ATTRNAME"),
    )

    # anyof-op = attr-name wspace ("Any_of" / "Not_Any_of") wspace (attr-name2 / value-array)
    anyof_op = seq(
        attr_name.tag("ATTRNAME") << wspace,
        (string("Any_of") | string("Not_Any_of")).tag("OPERATION") << wspace,
        (attr_name_2 | value_array).tag("VALUE"),
    )

    # literal-SID = "SID(" sid-string ")"
    literal_sid = string("SID(") >> parse_sid() << string(")")
    # sid-array = "{" [wspace] literal-SID [wspace] *( "," [wspace] literal-SID [wspace]) "}"
    sid_array = string("{").skip(wspace.optional()) >> literal_sid.sep_by(
        string(",") << wspace, min=1
    ).skip(wspace.optional()).skip(string("}"))

    # memberof-op = ( "Member_of" / "Not_Member_of" / "Member_of_Any" / "Not_Member_of_Any" / "Device_Member_of" / "Device_Member_of_Any" / "Not_Device_Member_of" / "Not_Device_Member_of_Any" ) wspace sid-array
    memberof_op = seq(
        (
            string("Member_of")
            | string("Not_Member_of")
            | string("Member_of_Any")
            | string("Not_Member_of_Any")
            | string("Device_Member_of")
            | string("Device_Member_of_Any")
            | string("Not_Device_Member_of")
            | string("Not_Device_Member_of_Any")
        ).tag("OPERATION")
        << wspace.at_least(1),
        sid_array.tag("VALUE"),
    )

    # term = [wspace] (memberof-op / exists-op / rel-op / contains-op / anyof-op / attr-name / relop2) [wspace]
    term = (
        wspace.optional()
        >> (
            memberof_op
            | exists_op
            | rel_op
            | contains_op
            | anyof_op
            # rel_op_2 should be after attr_name by definition, but lit_char has @ and can be the first character of an attribute. This breaks parsing.
            | rel_op_2
            | attr_name
        )
        << wspace.optional()
    )

    expr = forward_declaration()

    factor = term
    factor |= (
        string("(") >> wspace.optional() >> expr << wspace.optional() << string(")")
    ).map(lambda x: {"TYPE": "GROUP", "VALUE": x})
    factor |= (string("!") >> wspace.optional() >> factor).map(
        lambda x: {"TYPE": "NOT", "VALUE": x}
    )

    def combine_and(values):
        return {"TYPE": "AND", "VALUES": values} if len(values) > 1 else values[0]

    def combine_or(values):
        return {"TYPE": "OR", "VALUES": values} if len(values) > 1 else values[0]

    # Have to do yucky combine_and and combine_or. There's probably a better way to do that
    super_term = factor.sep_by(string("&&") << wspace.optional()).map(combine_and)
    expr.become(super_term.sep_by(string("||") << wspace.optional()).map(combine_or))

    nested = string("(") >> expr << string(")")

    return nested
