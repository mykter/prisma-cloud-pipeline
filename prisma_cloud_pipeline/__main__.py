"""CLI to retrieve container findings from Prisma Cloud and apply local triage rules"""

import sys
import os
import json
import argparse

import yaml

from .lib import Results, Api, TriageRules
from . import rules_validator


def make_parser() -> argparse.ArgumentParser:
    """ return a parser """
    parser = argparse.ArgumentParser(
        description="Report untriaged issues identified by Prisma Cloud Compute"
    )
    parser.add_argument(
        "--rules",
        type=argparse.FileType("r"),
        metavar="TRIAGE.yaml",
        help="Triage rules file, see example.yaml for the format",
    )
    parser.add_argument(
        "--results",
        type=argparse.FileType("w"),
        metavar="F.json",
        help="Save details of untriaged findings to this file",
    )
    parser.add_argument(
        "--triaged-findings",
        type=argparse.FileType("w"),
        metavar="T.json",
        help="Save details of findings that were matched by each triage rule to this file",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="If set and there are any untriaged issues, the exit code will be the count of "
        "containers with issues. Use this to have a job fail on untriaged issues.",
    )
    parser.add_argument(
        "--finding-stats",
        action="store_true",
        help="Report occurrence counts for each vulnerability and compliance issue",
    )
    cache_group = parser.add_argument_group(
        title="Cached mode",
        description="Don't fetch data from the API, use a local file",
    )
    cache_group.add_argument(
        "--data",
        type=argparse.FileType("r"),
        metavar="DATA.json",
        help="JSON file with a cache of the retrieved data",
    )

    fetch_group = parser.add_argument_group(title="Fetch mode")
    fetch_group.add_argument(
        "--api",
        help="The Prisma Cloud Compute base API URL, e.g. https://twistlock.example.com:8083/api",
    )
    fetch_group.add_argument(
        "--collections",
        type=str,
        nargs="?",
        default="",
        help="Comma separated list of collection IDs to retrieve. "
        "If not specified, all collections are retrieved.",
    )
    fetch_group.add_argument(
        "--save",
        type=argparse.FileType("w"),
        metavar="DATA.json",
        help="Save the retrieved data to the specified file",
    )
    fetch_group.add_argument(
        "--save-only",
        action="store_true",
        help="Don't process triage rules, just save the data for later processing",
    )
    return parser


def validate_args(args: argparse.Namespace) -> None:
    """ Check that the args passed are ok, exiting if not """

    if args.data:
        if args.collections or args.save or args.save_only or args.api:
            sys.exit(
                "You cannot specify --api, --save, --save-only, or --collections when using --data"
            )
    else:
        if not args.api:
            sys.exit(
                "You must specify at least one of --data (to use cached data) "
                "or --api (to fetch data from the api)"
            )

        if args.save_only:
            if not args.save:
                sys.exit("You must specify --save when using --save-only")
            if args.rules or args.results or args.check or args.finding_stats:
                sys.exit(
                    "You cannot specify --rules, --results, --check, or --finding-stats"
                    "when using --save-only"
                )

    if not args.save_only:
        if not args.rules:
            sys.exit("You must specify a --rules file")


def get_results(args) -> Results:
    """ get the results data from the API or a local cached file """

    if args.data:  # cached
        # destructure the saved data into params, then convert
        results = Results()
        results.containers = json.load(args.data)
    else:  # fetch
        if "TOKEN" in os.environ:
            token = os.environ["TOKEN"]
        else:
            sys.exit(
                f"Set the TOKEN environment variable, e.g.: "
                f"export TOKEN=$(http {args.api}/authenticate "
                f"username=<user> password=$(cat pass) | jq -r .token)"
            )

        results = Api(args.api, token, args.collections).fetch_results()

        if args.save:
            json.dump(results.containers, args.save, indent=2)
            if args.save_only:
                print("Saved data, exiting. (re-run without --save-only to see untriaged issues)")
                sys.exit(0)

    return results


def main() -> None:
    """ handle the commandline request """

    args = make_parser().parse_args()
    validate_args(args)

    results = get_results(args)

    containers, vulns, issues = results.count()
    print(
        f"Prior to triage filter, got {containers} distinct running containers with findings, "
        f"{vulns} vulnerabilities, {issues} compliance issues"
    )

    try:
        rules: TriageRules = yaml.safe_load(args.rules)
    except yaml.scanner.ScannerError as err:
        sys.exit(f"Failed to load triage rules file; is it valid yaml? Error was: {err}")
    if not rules_validator.is_valid(rules):
        print("The provided triage rules weren't in the valid format:")
        for error in rules_validator.iter_errors(rules):
            print(f'At {"/".join(map(str,error.path))}: {error.message}')
        sys.exit(1)

    results.triage(rules)

    containers, vulns, issues = results.count()
    print(
        f"After triage filter, got {containers} distinct running containers with findings, "
        f"{vulns} vulnerabilities, {issues} compliance issues"
    )

    print()
    if args.results:
        json.dump(results.containers, args.results, indent=2)
        print("Saved untriaged findings")

    if args.triaged_findings:
        json.dump(results.triaged(), args.triaged_findings, indent=2)
        print("Saved triaged findings")

    print()
    results.print(args.finding_stats)

    rule_issues = [
        rule["issue"]
        for rule in (rules["containers"] + rules["vulnerabilities"] + rules["complianceIssues"])
        if "issue" in rule
    ]
    if len(rule_issues) > 0:
        print("\nOutstanding issues in triage rules: ")
        print("\t" + "\n\t".join(rule_issues))
        print(
            "Once an issue is closed, the corresponding triage rule "
            "should be removed so regressions will be detected."
        )

    if args.check:
        sys.exit(min(len(results.containers), 255))


if __name__ == "__main__":
    main()
