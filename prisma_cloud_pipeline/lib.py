"""Library to retrieve container findings from Prisma Cloud and apply local triage rules"""

import sys
from urllib.parse import urljoin
from typing import Tuple, List, Sequence, Any, Mapping, TypedDict, DefaultDict
from enum import Enum
from collections import defaultdict
from dataclasses import dataclass
import textwrap
import operator

import requests
import jq  # type: ignore
from tabulate import tabulate

# width of columns in the results table
CONTAINER_COL_WIDTH = 35
VULN_COL_WIDTH = 60
COMPLIANCE_COL_WIDTH = 85


class TriageRule(TypedDict, total=False):  # pylint: disable=E0239,R0903 # false positive
    """ type of a triage rule """

    matches: str
    containerFilter: str
    vulnFilter: str
    complianceFilter: str
    rationale: str
    issue: str


class TriageRules(TypedDict, total=False):  # pylint: disable=E0239,R0903 # false positive
    """ type of the triage rules file """

    containers: List[TriageRule]
    vulnerabilities: List[TriageRule]
    complianceIssues: List[TriageRule]


Container = Mapping[str, Any]


class RuleType(Enum):
    """ what a rule filters """

    Container = 1
    Vuln = 2
    Compliance = 3


class MatchedFindings(TypedDict, total=False):  # pylint: disable=E0239,R0903 # false positive
    """ Record of what findings were suppressed by a given rule """

    name: str
    vulnerabilities: List[str]
    complianceIssues: List[str]


@dataclass
class RuleStat:
    """ stats on what matched a particular triage rule """

    rule_type: RuleType
    rule: TriageRule
    container_count: int
    vuln_count: int
    compliance_count: int

    # list of container names, for Container rules
    containers: List[str]
    # for non-Container rules
    findings: List[MatchedFindings]


RuleStats = List[RuleStat]


def label_value(label: str, container: Container) -> str:
    """ Returns the value of the first matching label from container if it exists, or "" """

    if "labels" not in container:
        return ""

    labels: List[str] = container["labels"]
    matches = [lab for lab in labels if lab.startswith(label + ":")]
    if len(matches) == 0:
        return ""

    return matches[0].split(":", maxsplit=1)[1]


class ContainerID:
    """Retrieves useful identifier information from a container,
    and renders it ready for table output.
    Potentially configurable in future."""

    sha: str
    namespace: str
    image_name: str
    account_id: str
    container_name: str
    pod_name: str

    def __init__(self, container: Container):
        self.sha = container["_id"]
        if "namespace" in container:
            self.namespace = container["namespace"].strip()
        else:
            self.namespace = ""
        if "imageName" in container:
            self.image_name = self.image_short_name(container["imageName"]).strip()
        else:
            self.image_name = ""
        if "accountID" in container:
            self.account_id = container["accountID"].strip()
        else:
            self.account_id = ""
        self.container_name = label_value("io.kubernetes.container.name", container).strip()
        self.pod_name = label_value("io.kubernetes.pod.name", container).strip()

    name_wrap = textwrap.TextWrapper(  # this is the first entry, so is simpler to wrap
        width=CONTAINER_COL_WIDTH,
    ).fill
    wrap = textwrap.TextWrapper(
        width=CONTAINER_COL_WIDTH,
        replace_whitespace=True,
        drop_whitespace=True,
        subsequent_indent=(" " * len("acct: ")),
        tabsize=2,
    ).fill

    def __str__(self):
        # There is a very careful mix of the TextWrapper and manual line breaks here.
        # Using the wrapper by itself results in non-ideal output.
        # Only show an entry if the cid has a corresponding entry, to cope with non-k8s use etc
        if self.container_name:
            entries = [f"{ContainerID.name_wrap(self.container_name)}"]
        else:
            entries = [f"{ContainerID.wrap(self.sha)}"]
        if self.namespace:
            entries.append(f"ns:   {ContainerID.wrap(self.namespace)}")
        if self.image_name:
            entries.append(f"img:  {ContainerID.wrap(self.image_wrap(self.image_name))}")
        if self.account_id:
            entries.append(f"acct: {ContainerID.wrap(self.account_id)}")

        return "\n".join(entries)

    @staticmethod
    def image_wrap(name: str):
        """wrap an image name on its version ":" if it's longer than the col width """
        if len(name) <= CONTAINER_COL_WIDTH or ":" not in name:
            return name

        split = name.split(":")
        return f"{split[0]}:\n{split[1]}"

    @staticmethod
    def image_short_name(full_name: str) -> str:
        """return the final component of a container image tag
        the version is included if present, but the hash is not"""
        return full_name.split("/")[-1].split("@")[0]


class Results:
    """Stores a modified version of the radar data from the API which can be filtered and printed"""

    containers: Sequence[Container]
    _rule_stats: RuleStats
    compliance_stats: DefaultDict[str, int]
    vuln_stats: DefaultDict[str, int]

    def __init__(self):
        self.containers = []
        self._rule_stats = []

    def triage(self, rules: TriageRules) -> None:
        """filter the data based on rules, updating the instance's data in place"""

        if "containers" in rules:
            for rule in rules["containers"]:
                container_count, vuln_count, compliance_count = self.count()

                try:
                    # filter out containers that matched
                    # and save the names of all the ones that matched
                    (self.containers, matched) = jq.all(  # pylint: disable=I1101
                        f"""
                        map(select({rule["containerFilter"]} | not)),
                        map(select({rule["containerFilter"]}) | (.namespace + "/" + .imageName))
                        """,
                        self.containers,
                    )
                except ValueError as err:
                    sys.exit(
                        f"Error whilst processing container triage rule '{rule['matches']}' - "
                        f"check the jq filter for this rule. Error was:\n{err}"
                    )

                new_container_count, new_vuln_count, new_compliance_count = self.count()
                assert container_count - new_container_count == len(matched)
                self._rule_stats.append(
                    RuleStat(
                        RuleType.Container,
                        rule,
                        container_count - new_container_count,
                        vuln_count - new_vuln_count,
                        compliance_count - new_compliance_count,
                        matched,
                        [],
                    )
                )

        # The vulns and compliance rules are structurally identical, so process them together
        if "vulnerabilities" not in rules:
            rules["vulnerabilities"] = []
        if "complianceIssues" not in rules:
            rules["complianceIssues"] = []
        for rule in rules["vulnerabilities"] + rules["complianceIssues"]:
            container_count, vuln_count, compliance_count = self.count()

            if "complianceFilter" in rule:
                rule_type = RuleType.Compliance
                compliance_filter = rule["complianceFilter"]
                # Treat the unspecified one as if it matches nothing
                vuln_filter = "false"
            else:
                rule_type = RuleType.Vuln
                vuln_filter = rule["vulnFilter"]
                compliance_filter = "false"

            if "containerFilter" in rule:
                # the entire container is bound to $container in the final query
                # only remove if the container filter matches and the vuln/issue filter matches.
                vuln_filter = f"(($container | {rule['containerFilter']}) and ({vuln_filter}))"
                compliance_filter = (
                    f"(($container | {rule['containerFilter']}) and ({compliance_filter}))"
                )

            # get two sets of results:
            #    1. filter out findings that match the corresponding filter
            #    2. the inverse: keep findings that match the filter
            # then remove containers with no findings from both these sets
            try:
                (self.containers, matched) = jq.first(  # pylint: disable=I1101
                    f"""
                    [
                        map(
                            . as $container |
                            .vulnerabilities |= map(select({vuln_filter} | not)) |
                            .complianceIssues |= map(select({compliance_filter} | not))
                        ),
                        map(
                            . as $container |
                            .vulnerabilities |= map(select({vuln_filter})) |
                            .complianceIssues |= map(select({compliance_filter}))
                        )
                    ]
                    |
                    map(map(select([.complianceIssues, .vulnerabilities | length] | add | . > 0)))
                    """,
                    self.containers,
                )
            except ValueError as err:
                sys.exit(
                    f"Error whilst processing triage rule '{rule['matches']}' "
                    f"check the jq filter(s) for this rule. Error was:\n{err}"
                )

            new_container_count, new_vuln_count, new_compliance_count = self.count()

            # sanity check that our query didn't go wrong
            if rule_type == RuleType.Vuln:
                assert compliance_count == new_compliance_count
            else:
                assert vuln_count == new_vuln_count
            self._rule_stats.append(
                RuleStat(
                    rule_type,
                    rule,
                    container_count - new_container_count,
                    vuln_count - new_vuln_count,
                    compliance_count - new_compliance_count,
                    [],
                    [
                        MatchedFindings(
                            name=container["namespace"] + "/" + container["imageName"],
                            vulnerabilities=container["vulnerabilities"],
                            complianceIssues=container["complianceIssues"],
                        )
                        for container in matched
                    ],
                )
            )

    def count(self) -> Tuple[int, int, int]:
        """ returns a tuple of (num containers, total vulns, total compliance issues) """
        return (
            len(self.containers),
            sum([len(c["vulnerabilities"]) for c in self.containers]),
            sum([len(c["complianceIssues"]) for c in self.containers]),
        )

    def print(self, finding_stats: bool) -> None:
        """ Output all the results """

        self.print_rule_stats()
        print()

        if len(self.containers) > 0:
            self.print_findings()
            print()

            if finding_stats:
                if len(self.compliance_stats) > 0:
                    print(
                        tabulate(
                            sorted(
                                self.compliance_stats.items(),
                                key=operator.itemgetter(1),
                                reverse=True,
                            ),
                            headers=["Untriaged Compliance Issue", "Occurrences"],
                            tablefmt="psql",
                        )
                    )
                    print()

                if len(self.vuln_stats) > 0:
                    print(
                        tabulate(
                            sorted(
                                self.vuln_stats.items(), key=operator.itemgetter(1), reverse=True
                            ),
                            headers=["Untriaged Vulnerability", "Occurrences"],
                            tablefmt="psql",
                        )
                    )
        else:
            print("No untriaged findings, nice!")

    def print_rule_stats(self) -> None:
        """ Print counts of how many findings each rule suppressed """

        print(
            tabulate(
                [
                    (
                        stat.rule["matches"],
                        stat.container_count,
                        stat.vuln_count,
                        stat.compliance_count,
                    )
                    for stat in self._rule_stats
                ],
                headers=[
                    "Triage Rule",
                    "Container\nMatches",
                    "Vulnerability\nMatches",
                    "Compliance Issue\nMatches",
                ],
                tablefmt="psql",
            )
        )
        print(
            "For container rules, the entries in the Vulnerabilities and Compliance "
            "Issues columns refer to the number of findings the matched containers had.\n"
            "For vuln/compliance rules, the entries in the Containers column "
            "refer to the number of containers that had no findings left after this rule was "
            "processed.\n"
            "For details on what each rule matched, review the file specified with the "
            "--triaged-findings flag."
        )

        # additionally report rules that didn't get used
        unused = []
        for stat in self._rule_stats:
            if stat.container_count + stat.vuln_count + stat.compliance_count == 0:
                issue = ""
                if "issue" in stat.rule and stat.rule["issue"]:
                    issue = f' - has issue {stat.rule["issue"]} been resolved?'
                unused.append(stat.rule["matches"] + issue)
        if len(unused) > 0:
            print(
                "\nWarning: the following rules didn't match any findings, "
                "you may want to check the filters are correct, and delete rules where the finding "
                "has been addressed:\n\t" + "\n\t".join(unused)
            )

    wrap_compliance = textwrap.TextWrapper(width=COMPLIANCE_COL_WIDTH, subsequent_indent="     ")
    wrap_vuln = textwrap.TextWrapper(width=VULN_COL_WIDTH, subsequent_indent="  ")

    def print_findings(self) -> None:
        """ Print compliance issues in a human-friendly manner """

        self.compliance_stats = defaultdict(int)
        self.vuln_stats = defaultdict(int)

        # findings[hash]=(ContainerID, issues,vulns)
        findings: List[Tuple[ContainerID, List[str], List[str]]] = []

        for result in self.containers:
            vulns = []
            for issue in result["complianceIssues"]:
                cve = package = ""
                if issue["cve"]:
                    cve = " - " + issue["cve"]
                if issue["packageName"]:
                    package = f' in {issue["packageName"]}'
                issue_str = f'{issue["id"]}: {issue["title"]}{cve}{package}'
                vulns.append(issue_str)
                self.compliance_stats[issue_str] += 1

            issues = []
            for vuln in result["vulnerabilities"]:
                vid = vuln["cve"]
                if not vid:
                    vid = f'no CVE; internal ID {vuln["id"]}'

                title = package = sev = status = ""
                if vuln["title"]:
                    title = f' - "{vuln["title"]}"'
                if vuln["packageName"]:
                    package = f' in {vuln["packageName"]}'
                if vuln["severity"]:
                    sev = f' ({vuln["severity"]})'
                if vuln["status"]:
                    status = " " + vuln["status"]
                issues.append(f"{vid}{title}{package}{sev}{status}")
                self.vuln_stats[f"{vid}{title}{package}"] += 1

            findings.append((ContainerID(result), vulns, issues))

        print(
            tabulate(
                [
                    (
                        str(cid),
                        "\n".join([Results.wrap_vuln.fill(vuln) for vuln in vulns]),
                        "\n".join([Results.wrap_compliance.fill(issue) for issue in issues]),
                    )
                    for (cid, issues, vulns) in sorted(
                        findings,
                        # exactly what is most helpful to sort on is unclear.
                        # namespace/name/account seems reasonable - findings are more closely
                        # correlated by container than by account, so this should put similar ones
                        # together. But it's helpful to review closely couple containers at the same
                        # time too, especially for compliance issues, so putting namespace first
                        # makes sense. This also makes name clashes less of a problem.
                        # Making this user-configurable would offload this problem to the user!
                        key=lambda finding: finding[0].namespace
                        + finding[0].container_name
                        + finding[0].account_id,
                    )
                ],
                headers=["Container", "Untriaged Vulnerabilities", "Untriaged Compliance Issues"],
                tablefmt="fancy_grid",
            )
        )

    def triaged(self) -> Mapping[str, Any]:
        """ Return all of the findings that each rule matched """

        return {
            "containers": [
                {"rule": stat.rule["matches"], "containers": stat.containers}
                for stat in self._rule_stats
                if stat.rule_type == RuleType.Container
            ],
            "vulnerabilities": [
                {"rule": stat.rule["matches"], "findings": stat.findings}
                for stat in self._rule_stats
                if stat.rule_type == RuleType.Vuln
            ],
            "complianceIssues": [
                {"rule": stat.rule["matches"], "findings": stat.findings}
                for stat in self._rule_stats
                if stat.rule_type == RuleType.Compliance
            ],
        }


class Api:
    """Prisma Cloud API accessor"""

    def __init__(self, url, token, collections):
        self.base = url
        self.token = token
        if collections:
            self.collections = collections.split(",")
            self.validate_collections()
        else:
            self.collections = []

    def get(self, endpoint: str) -> dict:
        """Return the JSON response from the given endpoint
        with this instances collections if it has any"""
        params = {}
        if self.collections:
            params["collections"] = self.collections

        return self._get(endpoint, params)

    def _get(self, endpoint: str, params: dict) -> dict:
        url = urljoin(urljoin(self.base + "/", "v1/"), endpoint)
        req = requests.get(url, params=params, headers={"Authorization": "Bearer " + self.token})
        req.raise_for_status()
        return req.json()

    def validate_collections(self) -> None:
        """Exit with an error if any of the instance's collections don't exist"""
        valid_collections = [col["name"] for col in self._get("current/collections", {})]
        for col in self.collections:
            if col not in valid_collections:
                sys.exit(
                    f"Error: collection {col} doesn't exist. Valid collections: \n\t"
                    + "\n\t".join(sorted(valid_collections))
                )

    def fetch_results(self) -> Results:
        """get data from the API and convert it into Results form

        Results are built by adding image and compliance findings to the radar data,
        and removing any containers that have no findings
        """

        radar = self.get("radar/container")  # list
        images = {v["id"]: v for v in self.get("images")}
        containers = {v["info"]["profileID"]: v for v in self.get("containers")}

        radar = radar["radar"]
        for i, container in enumerate(radar):
            image_id = container["imageID"]
            profile_id = container["_id"]

            # add image vulnerability findings.
            # If no corresponding image is found, an empty list is assigned
            vulns: List[dict] = []
            if image_id in images:
                vulns = images[image_id]["vulnerabilities"] or []
            else:
                print(
                    "Warning: no image data found for container {} with image ID {}".format(
                        profile_id, image_id
                    )
                )
            radar[i]["vulnerabilities"] = vulns

            # add compliance data
            issues: List[dict] = []
            if profile_id in containers:
                issues = containers[profile_id]["info"]["complianceIssues"] or []
            else:
                print(
                    "Warning: no container data found for container {} with image ID {}".format(
                        profile_id, image_id
                    )
                )
            radar[i]["complianceIssues"] = issues

        # only return containers that have findings
        results = Results()
        results.containers = [
            container
            for container in radar
            if (len(container["complianceIssues"]) + len(container["vulnerabilities"]) > 0)
        ]
        return results
