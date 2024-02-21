from parsy import Parser, regex


def parse_sid() -> Parser:
    """
    SID= "S-1-" IdentifierAuthority 1*SubAuthority
    IdentifierAuthority= IdentifierAuthorityDec / IdentifierAuthorityHex
    ; If the identifier authority is < 2^32, the
    ; identifier authority is represented as a decimal
    ; number
    ; If the identifier authority is >= 2^32,
    ; the identifier authority is represented in
    ; hexadecimal
    IdentifierAuthorityDec = 1*10DIGIT
    ; IdentifierAuthorityDec, top level authority of a
    ; security identifier is represented as a decimal number
    IdentifierAuthorityHex = "0x" 12HEXDIG
    ; IdentifierAuthorityHex, the top-level authority of a
    ; security identifier is represented as a hexadecimal number
    SubAuthority= "-" 1*10DIGIT
    ; Sub-Authority is always represented as a decimal number
    ; No leading "0" characters are allowed when IdentifierAuthority
    ; or SubAuthority is represented as a decimal number
    ; All hexadecimal digits must be output in string format,
    ; pre-pended by "0x"
    """
    # I'm lazy
    return regex(r"S-1(?:-\d+)*")
