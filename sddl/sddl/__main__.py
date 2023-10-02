from argparse import ArgumentParser
import json
import sys
from sddl_parser import api, ace_rights_enums

# Usage:
# sddl 'O:BAG:BAD:(A;;GA;;;WD)'
# echo 'O:BAG:BAD:(A;;GA;;;WD)' | sddl
# sddl 'O:BAG:BAD:(A;;GA;;;WD)' --type AlpcAccessRights
# sddl 'O:BAG:BAD:(A;;GA;;;WD)' --json
# sddl --list-types


def get_arguments():
    parser = ArgumentParser(
        description="Read SDDL strings",
        epilog="Example: `sddl 'O:BAG:BAD:(A;;GA;;;WD)'` or `echo 'O:BAG:BAD:(A;;GA;;;WD)' | sddl`",
    )
    parser.add_argument(
        "sddl",
        nargs="?",
        type=str,
        help="SDDL string to parse. If not provided, read from stdin.",
    )
    parser.add_argument(
        "--type",
        type=str,
        default="GenericAccessRights",
        help="Type of ACE to parse. Default: GenericAccessRights",
    )
    parser.add_argument(
        "--list-types",
        action="store_true",
        help="List available ACE types",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output as JSON",
    )
    return parser.parse_args()


def main():
    args = get_arguments()

    if args.list_types:
        print("Available ACE types:")
        for ace_type in dir(ace_rights_enums):
            if ace_type.endswith("Rights"):
                print(f"  {ace_type}")
        exit(0)

    if args.sddl is None:
        args.sddl = sys.stdin.read().strip()

    result = api.parse_sddl(args.sddl, as_type=getattr(ace_rights_enums, args.type))

    if args.json:
        print(json.dumps(result.asdict()))
    else:
        print(result.pformat())


if __name__ == "__main__":
    sys.exit(main())
