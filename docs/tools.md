# Tool reference

Stratinet exposes four read-only tools. Every answer is computed by fixed rules over catalogued
data; no language model decides a result. The same input at the same `data_version` returns the
same answer.

- [`advisory_exposure`](#advisory_exposure) — is this software version exposed to a vendor security advisory?
- [`translate_diagnostic`](#translate_diagnostic) — the same read-only check in another vendor's CLI.
- [`troubleshoot_start`](#troubleshoot_start) — the ordered read-only checks to run for a symptom.
- [`troubleshoot_analyze`](#troubleshoot_analyze) — read pasted command output and find the cause.

The input tables below are generated from the server's own tool definitions by
`scripts/gen_tool_docs.py`; CI fails if they drift from the code. Everything else on this page is
written by hand.

## Common to every tool

**How results come back.** A tool result has one text content item holding JSON, and the same
object as `structuredContent`. A successful answer has `isError: false`. A rejected input or a
failure has `isError: true` and an `error` object (see [Errors](#errors)) — an error is never a
verdict.

**Fields on every answer.**

| Field | Meaning |
|---|---|
| `basis` | A fixed sentence naming how the answer was reached. It is never free text. |
| `data_version` | `{kb_generation, rules_hash}`. `rules_hash` identifies the rule and catalogue data; `kb_generation` identifies the advisory data (it is `null` for tools that do not read advisories). Keep it with an answer if you want to reproduce or report it. |
| `limits` | `response_truncated` is `true` when list fields were shortened to fit the size budget. `troubleshoot_analyze` adds `outputs_truncated`. |

**A next step on anything short of certain.** When an answer is not definite it carries what
would settle it: `check_commands`, `what_would_settle_it`, `need` or `available_for`, depending on
the tool.

**Read-only.** No tool runs anything on a device or changes anything. Commands the tools return
are read-only show-style commands; the server refuses to return anything else.

## advisory_exposure

Says whether an Arista EOS or Fortinet FortiOS software version is exposed to a vendor security
advisory. Give `cve_id` to ask about one CVE, or leave it out to list every CVE that applies to
the version.

### Input

<!-- BEGIN GENERATED: advisory_exposure -->
> Says whether an Arista EOS or Fortinet FortiOS software version is exposed to a vendor security advisory. Give vendor and version; add cve_id for one CVE, or omit it to list every CVE that applies to that version. Optionally add running_config or feature_facts to settle whether the vulnerable feature is in use. Answers are deterministic and never guess 'not affected': when unsure the answer says what would settle it.

| Field | Type | Required | Notes |
|---|---|---|---|
| `vendor` | string | yes | one of: `arista_eos`, `fortinet_fortios`. |
| `version` | string | yes |  |
| `cve_id` | string | no |  |
| `hardware_model` | string | no |  |
| `running_config` | string | no |  |
| `feature_facts` | object of strings | no | values: `present`, `absent`, `explicitly_disabled`, `hardened`. |

<!-- END GENERATED: advisory_exposure -->

Notes on the inputs:

- `version` is the full release, for example `7.0.3` or `4.28.1F` (at most 64 bytes).
- `cve_id` must look like `CVE-YYYY-NNNN` (4 to 7 digits after the year); it is upper-cased
  before use.
- `hardware_model` (at most 128 bytes) is accepted. The current release does not use it to
  change an answer.
- `running_config` is at most 256 KB. Use the vendor's full listing — `show running-config` on
  Arista EOS, `show full-configuration` on FortiOS (plain `show` omits settings left at their
  default). See [Privacy](../README.md#privacy) for how it is handled.
- `feature_facts` lets you report what a feature looks like instead of sending configuration.
  Keys are feature ids — the `feature` values returned in earlier answers (for example
  `ssl_vpn`). Values:

  | Value | Means |
  |---|---|
  | `present` | The feature is configured and active. |
  | `absent` | The feature does not appear in the configuration. |
  | `explicitly_disabled` | The configuration has an explicit line turning the feature off. |
  | `hardened` | The vendor's hardening line for the feature is in place. |

  A value that does not apply to that feature on that vendor is rejected with
  `invalid_feature_fact`. When both `feature_facts` and `running_config` are given,
  `feature_facts` is used and `running_config` is ignored.

### Verdicts

Single-CVE answers, and each row of a list answer, carry exactly one of six verdicts.

| `verdict` | Meaning | Also carries |
|---|---|---|
| `not_affected` | Proven not exposed: the version is outside every affected range, the vendor's advisory states this version or product is not affected, or the configuration shows the vulnerable feature is not in use. | Always a proof: `fixed_in`, `ranges_checked` and `cleared_by` for the version path, or `evidence` for the configuration path. `cleared_by` is `affected_range` when the version was compared with the affected ranges, or `vendor_statement` when the vendor lists it as not affected; then `ranges_checked` holds the vendor's not-affected spans that cover the version, and is empty when the statement covers the whole product (`assessed.version_compared` is then `false`). |
| `vulnerable` | The version is affected and the configuration shows the vulnerable feature in use. | `feature`, `evidence`, `vulnerable_commands`, `fixed_in` |
| `depends_on_configuration` | The version is affected; whether you are exposed depends on a feature the answer could not see. | `feature`, `feature_label`, `vulnerable_commands`, `check_commands`, `check_source`, `decides`, `fixed_in`; `conditions` when the CVE involves several features |
| `likely_vulnerable_unless_disabled` | The version is affected and the feature is on by default, per a cited vendor source; you are exposed unless it has been turned off. | As above, plus `default_state`, `default_on_source{quote, url}` and, where the advisory publishes a workaround, `hardening_commands` |
| `affected_version_configuration_not_assessed` | The version is in the affected range; there is no configuration rule for this CVE, so configuration was not assessed. This does not mean safe. | `fixed_in`, `ranges_checked`, `no_rule_reason` |
| `cannot_determine` | The answer cannot be reached reliably from the data and inputs given. | `reason` and `what_would_settle_it` |

`reason` on `cannot_determine` is one of:

| `reason` | Meaning |
|---|---|
| `version_unparseable` | The version string could not be parsed. |
| `version_lines_not_comparable` | The version is on a release train the advisory's ranges cannot be compared with. |
| `affected_range_unreadable` | The advisory's affected-version data could not be read reliably, or the vendor lists only other release trains as not affected. |
| `no_advisory_data` | There is no advisory data for this CVE on this product. |
| `platform_dependent` | Exposure depends on the platform or hardware and cannot be read from configuration. |
| `feature_not_readable_for_vendor` | The vulnerable feature cannot be read from this vendor's configuration. |

`decides` tells you what each possible result of the check would change the verdict to, for
example `{"if_present": "vulnerable", "if_absent": "not_affected"}`. A key appears only for an
outcome the configuration can actually settle; when absence proves nothing, there is no
`if_absent`. `check_source` is `advisory` when `check_commands` come from the vendor advisory, or
`config_listing` when the advisory gives no check and the answer points you at the full
configuration listing instead.

Every single-CVE answer also carries `cve_id`, `vendor`, `version`, `advisory{id, url, published,
severity}` (or `null` when there is no advisory data), `reason` and
`assessed{version_compared, configuration_assessed}`, which says which half of the question was
answered. `advisory.published` is an ISO date or `null` when the vendor's date is missing or
cannot be read; it is never guessed.

`evidence` rows carry `feature`, `label`, `matched_config_snippet` (at most 240 characters),
`detector_pattern`, `vulnerable_commands` and `note`.

### List mode

Without `cve_id` the answer has `mode: "list"`, `vendor`, `version`, `checked` (how many CVEs were
examined for this product), `total` (how many apply), `returned`, `truncated`, `basis`,
`data_version` and `findings`. Each finding is the single-CVE answer without the `vendor`,
`version`, `basis` and `data_version` fields, which appear once at the top.

CVEs cleared by version alone are counted in `checked` but not returned. Findings are ordered by
severity (critical first), then by CVE id. In list mode a version that cannot be compared is a
`version_unparseable` error on `version`, because there is nothing to sweep.

### Size caps

| | Limit |
|---|---|
| `running_config` | 256 KB |
| Single-CVE answer | 8 KB, at most 5 `evidence` rows |
| List answer | 64 KB, at most 25 findings |
| `matched_config_snippet` | 240 characters |
| `vulnerable_commands`, `check_commands`, `hardening_commands` | 8 each, in every answer and finding |
| `ranges_checked` | 16, those on the version's own release train first |

When a cap or the size budget shortens a list, `limits.response_truncated` is `true`. The verdict,
the `evidence` rows and at least one entry of `ranges_checked`, `check_commands` and
`vulnerable_commands` are never dropped.

### Example

```json
{"vendor": "fortinet_fortios", "version": "7.0.3", "cve_id": "CVE-2024-21762"}
```

The answer is one single-CVE object as described above. Which verdict it carries depends on the
data at the current `data_version`. When the verdict turns on configuration, the answer names the
`feature` and gives `check_commands` and `decides`; repeating the call with that feature in
`feature_facts`, for example
`{"vendor": "fortinet_fortios", "version": "7.0.3", "cve_id": "CVE-2024-21762", "feature_facts": {"ssl_vpn": "explicitly_disabled"}}`,
lets the tool settle it. `{"vendor": "arista_eos", "version": "4.28.1F"}` returns a list answer.

## translate_diagnostic

Gives the catalogued command for a read-only diagnostic on one or more vendors.

### Input

<!-- BEGIN GENERATED: translate_diagnostic -->
> Translate a read-only network diagnostic into another vendor's CLI. Give a capability such as check-bgp-summary and one or more target vendors; get the catalogued command for each vendor, whether it has been run on real hardware, and which vendors have it. If the capability is unknown, returns close capability names. Never returns configuration commands. Vendors: arista_eos, cisco_ios, fortinet_fortianalyzer, fortinet_fortimanager, fortinet_fortios, fortinet_fortiswitch, juniper_junos, paloalto_panos.

| Field | Type | Required | Notes |
|---|---|---|---|
| `capability` | string | yes | Capability key, for example check-bgp-summary; 1 to 200 characters. |
| `target_vendor` | string or list of strings | yes | One vendor slug, or a list of them; one of: `arista_eos`, `cisco_ios`, `fortinet_fortianalyzer`, `fortinet_fortimanager`, `fortinet_fortios`, `fortinet_fortiswitch`, `juniper_junos`, `paloalto_panos`; 1 to 8 items; no repeats. |

<!-- END GENERATED: translate_diagnostic -->

### Statuses

| `status` | Meaning | Also carries |
|---|---|---|
| `translated` | At least one requested vendor has the command catalogued. | `capability`, `description`, `kind: "check"`, `commands[{vendor, command, params, hardware_verified}]`, `coverage{vendors_available, vendors_requested}` |
| `no_equivalent` | No command is catalogued for the requested vendors. This means none is catalogued, not that none exists. | `capability`, `requested_vendor`, `available_for` (the vendors that do have it), `reason` |
| `unknown_capability` | The capability name is not in the catalogue. | `did_you_mean` — close names found by prefix and substring matching |
| `refused_not_read_only` | The capability is not a read-only check, so no command is returned. | `capability`, `reason` |

`hardware_verified` is `true` only for commands that have been run on a real device. Most
catalogued commands have not been, so check the flag before relying on exact syntax. `params`
names placeholders in the command that you fill in.

Caps: at most 8 commands, answer at most 8 KB.

### Example

```json
{"capability": "check-bgp-summary", "target_vendor": "juniper_junos"}
```

Returns `translated` with one `commands` row for `juniper_junos` if the command is catalogued,
or `no_equivalent` with `available_for` otherwise. A misspelt name such as `check-bgp-sum`
returns `unknown_capability` with suggestions in `did_you_mean`.

## troubleshoot_start

Gives the ordered read-only checks to run for a symptom on a device. Run them, then pass the
output to `troubleshoot_analyze`.

### Input

<!-- BEGIN GENERATED: troubleshoot_start -->
> Start troubleshooting a network problem: give a symptom and a vendor, get the ordered read-only checks to run on the device, each with its command, what it can show and whether the command has run on real hardware. Symptoms: bgp-session-down, ospf-neighbor-down, interface-degraded (only procedures verified on real devices are accepted). Vendors: arista_eos, cisco_ios, juniper_junos. Optional context fills the interface or peer address into the commands; a command that still holds a {placeholder} lists it in placeholders, with the context field that fills it or null when the value must be typed in by hand. Run the checks, then pass their output to troubleshoot_analyze.

| Field | Type | Required | Notes |
|---|---|---|---|
| `symptom` | string | yes | bgp-session-down, ospf-neighbor-down or interface-degraded; 1 to 200 characters. |
| `vendor` | string | yes | one of: `arista_eos`, `cisco_ios`, `juniper_junos`. |
| `context` | object | no | no other keys. |
| `context.interface` | string | no | at most 200 characters. |
| `context.peer_ip` | string | no | at most 200 characters. |

<!-- END GENERATED: troubleshoot_start -->

`symptom` is one of `bgp-session-down`, `ospf-neighbor-down` or `interface-degraded`, or a fixed
alias of one of them; matching ignores case and extra spaces. Only symptoms whose procedure is
marked verified in the server's data bundle are served (today `interface-degraded` and
`ospf-neighbor-down`); anything else is rejected with `unsupported_symptom` and the list of
supported symptoms. `context.interface` must be an interface
name such as `Ethernet1` or `GigabitEthernet0/1`; `context.peer_ip` must be an IPv4 or IPv6
address.

### Statuses

| `status` | Meaning | Also carries |
|---|---|---|
| `checks` | The checks to run, in order. | `issue{key, label, verified, sop_refs}`, `checks[{order, capability, command, description, why, reads, hardware_verified}]`, `total_steps`, `readable_steps`, `note` |
| `no_commands_for_vendor` | The symptom is supported, but no read-only command is catalogued for this vendor. | `issue`, `vendor` |

`readable_steps` and `total_steps` show how much of the procedure the tool can read back:
steps without an evidence rule are left out, and `note` says how many and why. `reads` lists
what each check can show.

Caps: at most 16 checks, answer at most 12 KB.

### Example

```json
{"symptom": "ospf-neighbor-down", "vendor": "arista_eos", "context": {"interface": "Ethernet1", "peer_ip": "192.0.2.2"}}
```

Returns `checks`, with the interface and peer address filled into the commands that take them.

## troubleshoot_analyze

Reads pasted output of read-only commands for one problem and says what it proves.

### Input

<!-- BEGIN GENERATED: troubleshoot_analyze -->
> Analyze pasted output of read-only troubleshooting commands for one network problem. Give the vendor, the symptom (bgp-session-down, ospf-neighbor-down or interface-degraded; only procedures verified on real devices are accepted) and up to 8 outputs, each with the command that produced it and whether it came from the local or the peer device. Returns root_cause with the proving line, need_more_evidence with the strongest reading so far and up to 3 commands to run next, or cannot_determine with what would settle it. Outputs that could not be read are listed in unread and never count as health. A next command that still holds a {placeholder} lists it in placeholders, with the context field that fills it or null when the value must be typed in by hand. Vendors: arista_eos, cisco_ios, juniper_junos. Set evidence_complete when the device cannot be reached again; the answer then says which checks were missing.

| Field | Type | Required | Notes |
|---|---|---|---|
| `vendor` | string | yes | one of: `arista_eos`, `cisco_ios`, `juniper_junos`. |
| `symptom` | string | yes | bgp-session-down, ospf-neighbor-down or interface-degraded; 1 to 200 characters. |
| `outputs` | list of objects | yes | 1 to 8 items. |
| `outputs[].command` | string | yes | 1 to 256 characters. |
| `outputs[].output` | string | yes |  |
| `outputs[].device_role` | string | yes | one of: `local`, `peer`. |
| `context` | object | no | at most 8 keys; no other keys. |
| `context.interface` | string | no | at most 200 characters. |
| `context.peer_ip` | string | no | at most 200 characters. |
| `evidence_complete` | boolean | no | default `false`. |
| `include_remediation` | boolean | no | default `false`. |

<!-- END GENERATED: troubleshoot_analyze -->

Notes on the inputs:

- `outputs[].command` is matched against the catalogue, not guessed from the output. Common
  abbreviations such as `sh ip ospf nei` are understood.
- Each `outputs[].output` is cut to 64 KB if longer: log-style output keeps its last lines, tables
  keep their first lines, and `limits.outputs_truncated` is set. All outputs together may be at
  most 256 KB.
- `symptom` and `context` accept the same values as in `troubleshoot_start`.
- Set `evidence_complete` to `true` when you cannot collect more output. A cause is then reported
  even if checks that could have outranked it are missing; `basis` says how many, and `need`
  still lists them.
- `include_remediation` adds a `remediation_options` list to a root-cause finding. The current
  release returns it empty: the tools never propose configuration changes.

### Statuses

| `status` | Meaning | Also carries |
|---|---|---|
| `root_cause` | The output proves a cause. | `finding{cause, means, explanation, evidence{command, line}, symptoms, also_found, basis}` |
| `need_more_evidence` | There is a leading reading, but it is not proven yet. | `leading_finding{cause, line, note}` and `need` — up to 3 `{command, why}` rows to run next; when none can be named, `need` is empty and `what_would_settle_it` says what is missing |
| `cannot_determine` | Nothing is provable from this output. This is not the same as the device being healthy. | `reason` and `need`; when no next command can be named, `need` is empty and `what_would_settle_it` says what is missing |

Every status also carries `read` (up to 12 `{command, read_as, line}` rows: what was read from the
output) and `unread` (`{command, why}` for every output that could not be read). Output in
`unread` never counts as evidence of health. Log lines are aged against the latest line of the
same paste; a line whose time cannot be placed, such as one in a paste of year-less stamps that
spans more than half a year, is never taken as a current fault. An empty output is listed in
`unread` and is not asked for again: its `why` says to confirm on the device that what the check
reads is not there, for example because the feature is not configured. When `context.interface`
is given, a log line that names only other interfaces is not read as evidence about it. A flap
rate is read only over a time since counters were cleared that the output states, never over the
link's current up time, and only from four or more link status changes. Quoted lines are at most
400 characters.

When the counters give no such window, a flap rate is also read from a log output supplied with
the interface detail whose command states its own window (for example `show logging last 1 hours`):
the lines that record that interface changing state to down are counted over that window, from
two or more of them, and only when every line of the paste falls inside it. An OSPF neighbour's
state changes are never turned into a rate, because the time since the adjacency was established
is not the window they accumulated over. The quoted line is always one that matched the reading,
and when `context.interface` is given, a status table is read from that interface's row only.
When the output shows a condition this symptom does not cover, such as a link that is down or
administratively shut down while the symptom is a degraded link that is up, `reason` names that
condition instead of saying nothing was found, and the output is not asked for again as if it
had shown no fault. A next command that differs from a supplied one only in how the interface is
abbreviated is not asked for.

Caps: 8 outputs, 64 KB each, 256 KB in total; answer at most 16 KB. When the answer must be
shortened, `read` rows go first, then `also_found`, then `symptoms`; the verdict, the evidence line
and `need` are never dropped.

### Example

```json
{
  "vendor": "cisco_ios",
  "symptom": "ospf-neighbor-down",
  "outputs": [
    {
      "command": "show ip ospf neighbor",
      "output": "Neighbor ID     Pri   State           Dead Time   Address         Interface\n192.0.2.2         1   EXSTART/DR      00:00:33    192.0.2.2       GigabitEthernet0/1\n",
      "device_role": "local"
    }
  ]
}
```

The answer has one of the three statuses. `read` shows what was taken from the neighbor table;
if more output is needed, `need` names the commands to run next and why.

## Errors

A rejected input returns `isError: true` and a body like:

```json
{"error": {"code": "unsupported_vendor", "message": "This vendor is not supported by this tool.", "field": "target_vendor", "supported": ["arista_eos", "..."]}}
```

`field` names the input at fault when there is one; `supported` lists the accepted values for
`unsupported_vendor` and `unsupported_symptom`. The codes each tool can return:

| Tool | Codes |
|---|---|
| `advisory_exposure` | `missing_field`, `unknown_field`, `invalid_value`, `input_too_large`, `unsupported_vendor`, `malformed_cve_id`, `invalid_feature_fact`, `version_unparseable` |
| `translate_diagnostic` | `missing_field`, `unknown_field`, `invalid_value`, `input_too_large`, `unsupported_vendor` |
| `troubleshoot_start` | `missing_field`, `unknown_field`, `invalid_value`, `input_too_large`, `unsupported_vendor`, `unsupported_symptom` |
| `troubleshoot_analyze` | `missing_field`, `unknown_field`, `invalid_value`, `input_too_large`, `unsupported_vendor`, `unsupported_symptom` |

Any tool can also return `internal_error`, with no detail, when it cannot complete a request or
runs out of time, and `busy` when every tool worker is in use; nothing was run, so the call can be
sent again shortly. What each code means, and the HTTP-level errors for a missing key or a rate
limit, are listed in the [README](../README.md#errors).

Calling a tool name that does not exist returns a JSON-RPC error (`-32602`, `Unknown tool`)
rather than a tool result.
