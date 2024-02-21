from sddl_parser import parser_conditional_ace as parser


def test_Contains():
    test = '(WIN://SYSAPPID Contains "MICROSOFT.MICROSOFTEDGE.STABLE_8WEKYB3D8BBWE")'
    parsed = parser.parse_conditional_ace_entry().parse(test)
    assert parsed == [
        ("ATTRNAME", "WIN://SYSAPPID"),
        ("OPERATION", "Contains"),
        ("VALUE", "MICROSOFT.MICROSOFTEDGE.STABLE_8WEKYB3D8BBWE"),
    ]


def test_complex():
    test = '(@User.Title=="PM" && (@User.Division=="Finance" || @User.Division == "Sales"))'
    parsed = parser.parse_conditional_ace_entry().parse(test)
    assert parsed == {
        "TYPE": "AND",
        "VALUES": [
            [("ATTRNAME", "@user.Title"), ("OPERATION", "=="), ("VALUE", "PM")],
            {
                "TYPE": "GROUP",
                "VALUE": {
                    "TYPE": "OR",
                    "VALUES": [
                        [
                            ("ATTRNAME", "@user.Division"),
                            ("OPERATION", "=="),
                            ("VALUE", "Finance"),
                        ],
                        [
                            ("ATTRNAME", "@user.Division"),
                            ("OPERATION", "=="),
                            ("VALUE", "Sales"),
                        ],
                    ],
                },
            },
        ],
    }


def test_not():
    test = '(!(WIN://SYSAPPID Contains "MICROSOFT.MICROSOFTEDGE.STABLE_8WEKYB3D8BBWE"))'
    parsed = parser.parse_conditional_ace_entry().parse(test)
    assert parsed == {
        "TYPE": "NOT",
        "VALUE": {
            "TYPE": "GROUP",
            "VALUE": [
                ("ATTRNAME", "WIN://SYSAPPID"),
                ("OPERATION", "Contains"),
                ("VALUE", "MICROSOFT.MICROSOFTEDGE.STABLE_8WEKYB3D8BBWE"),
            ],
        },
    }


def test_anyof():
    test = "(@User.Project Any_of @Resource.Project)"
    parsed = parser.parse_conditional_ace_entry().parse(test)
    assert parsed == [
        ("ATTRNAME", "@user.Project"),
        ("OPERATION", "Any_of"),
        ("VALUE", "@resource.Project"),
    ]


def test_memberof():
    test = "(Member_of {SID(S-1-5-5-0-16948695), SID(S-1-5-5-0-16948696)})"
    parsed = parser.parse_conditional_ace_entry().parse(test)
    assert parsed == [
        ("OPERATION", "Member_of"),
        ("VALUE", ["S-1-5-5-0-16948695", "S-1-5-5-0-16948696"]),
    ]
