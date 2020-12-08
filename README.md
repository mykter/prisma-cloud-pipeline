# Prisma Cloud Pipeline Triage

Export Prisma Cloud container findings to a CI pipeline, and identify un-triaged findings.

Prisma Cloud's container scanning feature (formerly called Twistlock) has a web UI to review findings in. You can also
define
[triage rules](https://docs.twistlock.com/docs/compute_edition/vulnerability_management/vuln_management_rules.html) to
(temporarily) ignore findings. There are a number of
[example integrations](https://github.com/twistlock/sample-code/blob/master/CI/) into CI pipelines, which all follow the
same pattern: scan a specific docker image that is present in the pipeline, report any issues found, and optionally fail
if a certain 'badness' threshold is met.

The motivation for this project is to get security findings closer to developers, and integrate the entire process with
existing project CI pipelines. All findings (for specified collections) are retrieved from the Prisma Cloud API, and a
set of locally defined triage rules are applied to suppress specific findings or containers from the main output.

This:

1.  Provides clear visibility of any new un-triaged findings, and optionally allows the pipeline to fail if there are
    any.

2.  Enables triage of issues to follow the usual merge/pull request approach. If there are any new findings or false
    positives, they need to be either fixed or added to the triage rules file before the pipeline passes again.

3.  Means development teams don't need to use or learn the web UI unless they want the extra functionality it offers.

## Example

Triage rules look like this:

```yaml
- matches: GKE system components
  containerFilter: .namespace == "kube-system"
  rationale:
    We use an auto-updating GKE instance that gets patches - these will either be false positives or will get patched
    shortly by Google. There's nothing we can do about them.

- matches: Limit memory
  complianceFilter: .id == 510
  rationale: We don't run untrusted containers; whilst this is a nice to have, it is very low priority.

- matches: twistlock defender privileges
  containerFilter: .namespace == "twistlockdefender"
  complianceFilter: .id | IN([599,515,59,520,525,531,55,528,521,51][])
  rationale: >-
    The defender needs full access to the host to monitor everything.

     Issues ignored: 599-root; 515-host PID ns; 59-host network ns; 520-host UTS ns; 525-extra privs; 
     531-docker socket; 55-sensitive dir mounts; 528-pid cgroup limit; 521-default seccomp profile; 51-apparmor profile

     The PID cgroup limit could be implemented, but it's of negligible importance given the rest.

- matches: heartbleed for the proj/foo-* containers
  containerFilter: .imageName | test("gcr.io/proj/foo-")
  vulnFilter: .cve == "CVE-2014-0160"
  rationale:
    We aren't exposed to heartbleed in foo-x, foo-y, or foo-zzz because we manually disable heartbeats. Raised an issue
    to fix it anyway.
  issue: JIRA-1234
```

After filtering out any findings that match any of these rules, a summary of the remaining findings are presented in a
condensed textual output:

```
Prior to triage filter, got 146 distinct running containers with findings, 45 vulnerabilities, 862 compliance issues
After triage filter, got 2 distinct running containers with findings, 1 vulnerabilities, 15 compliance issues

+-------------------------------------------------+-------------+-----------------+--------------------+
| Triage Rule                                     |   Container |   Vulnerability |   Compliance Issue |
|                                                 |     Matches |         Matches |            Matches |
|-------------------------------------------------+-------------+-----------------+--------------------|
| GKE system components                           |          24 |               4 |                158 |
| Limit memory                                    |           0 |               0 |                 17 |
| heartbleed for the foo containers               |           0 |               3 |                  0 |
.                                                 .             .                 .                    .
.                                                 .             .                 .                    .
+-------------------------------------------------+-------------+-----------------+--------------------+
For container rules, the entries in the Vulnerabilities and Compliance Issues columns refer to the number of findings the matched containers had.
For vuln/compliance rules, the entries in the Containers column refer to the number of containers that had no findings left after this rule was processed.
For details on what each rule matched, review the file specified with the --triaged-findings flag.

╒═════════════════════════════════════════╤════════════════════════════════════════════╤════════════════════════════════════════════════════════════════════════════════════╕
│ Container                               │ Vulnerabilities                            │ Compliance Issues                                                                  │
╞═════════════════════════════════════════╪════════════════════════════════════════════╪════════════════════════════════════════════════════════════════════════════════════╡
│ tmp-shell                               │ CVE-2020-11984 in apache2 (critical) fixed │ 599: Container is running as root                                                  │
│ ns:   debug                             │  in 2.4.46-r0                              │ 512: (CIS_Docker_CE_v1.1.0 - 5.12) Mount container's root filesystem as read only  │
│ img:  netshoot:latest                   │                                            │ 521: (CIS_Docker_CE_v1.1.0 - 5.21) Do not disable default seccomp profile          │
│ acct: proj-dev-eu-1                     │                                            │ 525: (CIS_Docker_CE_v1.1.0 - 5.25) Restrict container from acquiring additional    │
│                                         │                                            │   privileges                                                                       │
│                                         │                                            │ 528: (CIS_Docker_CE_v1.1.0 - 5.28) Use PIDs cgroup limit                           │
├─────────────────────────────────────────┼────────────────────────────────────────────┼────────────────────────────────────────────────────────────────────────────────────┤
│ twistlock-defender                      │                                            │ 599: Container is running as root                                                  │
│ ns:   twistlockdefender                 │                                            │ 51: (CIS_Docker_CE_v1.1.0 - 5.1) Verify AppArmor profile, if applicable            │
│ img:  defender:defender_20_04_163       │                                            │ 515: (CIS_Docker_CE_v1.1.0 - 5.15) Do not share the host's process namespace       │
│ acct: proj-prod-eu-1                    │                                            │ 59: (CIS_Docker_CE_v1.1.0 - 5.9) Do not share the host's network namespace         │
│                                         │                                            │ 520: (CIS_Docker_CE_v1.1.0 - 5.20) Do not share the host's UTS namespace           │
│                                         │                                            │ 521: (CIS_Docker_CE_v1.1.0 - 5.21) Do not disable default seccomp profile          │
│                                         │                                            │ 525: (CIS_Docker_CE_v1.1.0 - 5.25) Restrict container from acquiring additional    │
│                                         │                                            │   privileges                                                                       │
│                                         │                                            │ 528: (CIS_Docker_CE_v1.1.0 - 5.28) Use PIDs cgroup limit                           │
│                                         │                                            │ 531: (CIS_Docker_CE_v1.1.0 - 5.31) Do not mount the Docker socket inside any       │
│                                         │                                            │   containers                                                                       │
│                                         │                                            │ 55: (CIS_Docker_CE_v1.1.0 - 5.5) Do not mount sensitive host system directories on │
│                                         │                                            │   containers                                                                       │
╘═════════════════════════════════════════╧════════════════════════════════════════════╧════════════════════════════════════════════════════════════════════════════════════╛

Outstanding issues in triage rules:
    PROJ-321
Once an issue is closed, the corresponding triage rule should be removed so regressions will be detected.
```

## Usage

To run the tool locally, try this from a directory that contains a `triage.yaml` file with your rules:

```sh
export TOKEN=$(http $API/v1/authenticate username=$USER password=$PASS | jq -r .token)
docker run --rm -e TOKEN=$TOKEN -v $(pwd):/mnt prisma-cloud-pipeline --api=$API --rules=triage.yaml --collections=mycol,anothercol --results=results.json
```

Full usage can be found with `docker run --rm prisma-cloud-pipeline --help`.

The recommended way to run the tool is via the docker container in your pipeline. Here's an example Gitlab job
definition, where USER and PASS are predefined CI variables for an account that can read from the API:

```yaml
scan:
  image:
    name: prisma-cloud-pipeline
    entrypoint: [''] # allow gitlab to run its own commands
  variables:
    API: https//twistlock.example.com:8083/api
  script:
    - export TOKEN=$(http --ignore-stdin $API/v1/authenticate username="$USER" password="$PASS" | jq -r .token)
    # this command and hence job will fail (due to --check) if there are any findings in the col1 or col2 collections
    # that are not matched by a rule in prisma-triage.yaml in the repo
    - prisma-cloud-pipeline --api=$API --collections=col1,col2 --rules=prisma-triage.yaml --check
      --results=untriaged-findings.json --triaged-findings=triaged-findings.json
  artifacts:
    when: always
    paths:
      - untriaged-findings.json # refer to this artifact or the Prisma Cloud Compute UI if the summary output in the job is insufficient
      - triaged-findings.json # refer to this artifact to validate that the triage rules aren't ignoring more than they should
  allow_failure: true # we want to be alerted if there is a new finding, but we don't want it to stop the pipeline from working
```

The text output from the tool provides a summary of all of the untriaged findings; the full details (as returned by the
API) are saved to the file specified by the --results flag (if present).

You can also use it in an offline manner, where it doesn't have direct access to the twistlock API. One invocation with
`--save` is used to retrieve the results, and a later invocation with `--data` can process that file, instead of
accessing the API.

If your API has a certificate from an untrusted root, set the REQUESTS_CA_BUNDLE environment variable, e.g.:
`REQUESTS_CA_BUNDLE=mycert.pem prisma-cloud-pipeline $API ...`

Specify `--finding-stats` to get a count of how many times each untriaged finding occurred.

## Triage Rules

You'll want to write triage rules for various reasons:

1.  A finding doesn't apply - it's a false positive, or it doesn't matter in the circumstances of a particular
    container.
2.  It's a valid finding, but you don't care: it's for a container you can't control; it's not serious.
3.  You're going to fix a finding, but haven't yet, and in the mean time don't want your pipeline failing.

A triage rules file has up to three keys: `containers`, `vulnerabilities`, and `complianceIssues`. Each key can have any
number of rules associated with it.

The basic format of a triage rule is:

```yaml
- matches: <a title for the rule>
  rationale: <why this rule exists, for example why a reported vulnerability isn't a problem in this case>
  issue: <an optional reference to an issue to fix this finding, e.g. in Jira or GitHub>
  containerFilter: <see below>
  vulnFilter:
  complianceFilter:
  expires: <date in YYYY-MM-DD format>
```

The rules under the `containers` key can only contain a `containerFilter`. Any container that matches this filter will
be excluded, so be very sure you don't care about any possible finding before using this.

The rules under `vulnerabilities` and `complianceIssues` must include either a `vulnFilter` or a `complianceFilter`
respectively, and both can optionally include a `containerFilter`. If a `containerFilter` is not specified, then such a
rule matches _every_ occurrence of a matching vulnerability or compliance issue, wherever it is found. If a
`containerFilter` is specified, then the rule will only exclude findings from those containers that match.

Any rule can have an `expires` key; this tells the tool to ignore the rule after it has expired. This is useful for when
you have fixed an issue, but the fix hasn't propagated across the whole system yet (or across any of it) - you want to
temporarily ignore that finding, on the assumption that it is going to go away shortly. Once the rule expires, if the
finding is still present then you will be notified - apparently the fix didn't work or took longer than you expected to
propagate.

### Writing Filters

The format of the filters is a [jq filter](https://stedolan.github.io/jq/manual/) that outputs `true` if the filter
matches (i.e. the container/finding has been triaged) and `false` otherwise.

The input to the filters - the value of `.` - is data taken directly from the Prisma Cloud Compute API - this means you
can filter on any attributes that Prisma reports. The container filter input is an entry from the `radar/containers` API
endpoint; the vulnerability filter input is the matching `vulnerabilities` field from the `images` API endpoint; the
compliance issues filter input is the matching `info/complianceIssues` field from the `containers` API endpoint. To see
the full set of data on which the filters operate, run the tool with the `--results=file.json` option, and inspect the
results file.

Here are some more example filter combinations to show what you can do (note that a valid rule also needs a `rationale`
entry, and must be under one of the three top-level keys in the rules file):

```yaml
- matches: All containers in staging
  containerFilter: .accountID | test("my-staging-AWS-account")

- matches: Running a particular set of containers as root
  containerFilter: .imageName | test("datadog/cluster-agent")
  complianceFilter: .id == 599

- matches: Any compliance issue coming from a particular pod
  containerFilter: .labels | map(test("^io.kubernetes.pod.name:verycompliantpod-")) | any
  complianceFilter: 'true'

- matches: All low sev compliance issues
  complianceFilter: .severity == "low"

- matches: all python vulnerabilities
  vulnFilter: '.packageName | test("^python[.0-9]+$")'
```

Be careful when writing filters - if your filter is overly broad you can easily lose findings you care about. The output
reports how many containers/findings each rule suppressed - you can review this to check it matches your expectations.
For a more thorough review, use the `--triaged-findings` flag to specify a file to save details on what each rule
matched.

## Limitations

This tool does not handle "runtime events" findings. Whilst they could be incorporated in the same manner that
vulnerabilities and compliance issues are currently handled, runtime events are inherently more ephemeral and thus less
well suited to being managed in the same pipeline that builds and deployment use. If you want to follow a similar
approach to triage and handling of runtime events, perhaps running it in a dedicated secops pipeline, PRs are welcome!
