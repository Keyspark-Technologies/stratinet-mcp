"""Turn raw device output into canonical FACTS.

Three layers, cheapest first:
  1a  native structured output — Arista EOS `| json` (typed, no template to rot)
  1b  TextFSM via ntc-templates (977 templates ship with Netmiko)
  Output neither layer can read stays `unparseable`; there is no model layer.

Returns {"status", "records", "evidence", "source"}. `status` distinguishes an
output that is genuinely empty (`ok_empty`) from one that says a feature is off
(`not_configured`) or unlicensed — a bare [] is never returned as a finding,
because both TextFSM and a large model were observed to call a populated
`Default gateway is …` output "no default route".

Records are normalised to the canonical field names of their `shape`, so a signal
predicate reads the same whether the facts came from JSON, a template or the model.
"""
from __future__ import annotations

import json
import logging
import re
from typing import Any

logger = logging.getLogger(__name__)

# ── statuses ─────────────────────────────────────────────────────────────────
OK, OK_EMPTY, OK_NO_ROWS, NOT_CONFIGURED, UNLICENSED, ERROR, UNPARSEABLE = (
    "ok", "ok_empty", "ok_no_rows", "not_configured", "unlicensed", "error", "unparseable")
#: Shape-specific verdicts. A ping and a clock read do not fit the table/record model:
#: their answer IS the status, so the extractor states it rather than emitting rows.
NO_LOSS, PARTIAL_LOSS, TOTAL_LOSS, CLOCK_LOCAL = (
    "no_loss", "partial_loss", "total_loss", "clock_local")
#: ok_no_rows vs ok_empty is a real distinction, not a nicety. A table that printed
#: its HEADER and no rows proves the feature is running and has nothing to report
#: (Arista's OSPF table when the adjacency dies). Output that is blank ENTIRELY
#: cannot tell "none present" from "not configured" (Cisco prints nothing at all
#: when OSPF is absent), so it stays indeterminate and asks for a follow-up.

# ntc-templates keys on the netmiko device_type, not our vendor slug.
_PLATFORM = {"fortios": "fortinet", "fortinet_fortios": "fortinet",
             "fortinet_fortiswitch": "fortinet", "paloalto_panos": "paloalto_panos"}

# Text the device emits when a feature is off rather than merely idle. Checked
# BEFORE any parse, because a parser turns all of these into [].
#: How many opening lines the feature-off scan may look at. A terse refusal
#: ("% BGP inactive", "OSPF instance is not running") is always at the top.
_STATUS_TEXT_LINES = 3

_STATUS_TEXT = [
    (UNLICENSED,      r"licen[sc]e key missing|requires '.*' licen[sc]e|not licensed|unlicensed"),
    (NOT_CONFIGURED,  r"%\s*bgp inactive|bgp is not running|ospf instance is not running"
                      r"|not enabled|is disabled|not running|no such process|process_status:\s*not up"
                      # Arista states 802.1X's master switch this way, and with it off no
                      # port can authenticate. Matched specifically rather than by a
                      # general `: disabled` — `show logging` prints "Persistent logging:
                      # disabled" in its own header, which a broad pattern would read as
                      # the device declining to answer.
                      r"|authentication control:\s*disabled"),
    (ERROR,           r"%\s*invalid|command parse error|unknown action|command fail"),
]

# ── canonical shapes ─────────────────────────────────────────────────────────
SHAPES: dict[str, tuple[str, ...]] = {
    # `state_changes`/`retransmits`/`changes_per_hour` come from the DETAIL form and are
    # what the reference SOP's stability table (§9.3.8) actually asks for: a flapping
    # adjacency is not a state, it is a rate. Absent from the brief form, which is fine —
    # a signal that needs them simply does not fire on a brief read.
    "peer_table":      ("peer", "peer_address", "state", "interface", "uptime", "area",
                        "priority", "state_changes", "changes_per_hour", "retransmits",
                        "peers_total", "peers_full"),
    "interface_table": ("port", "admin_state", "oper_state", "description", "speed", "duplex"),
    # `programmed` is SOP-RTG-005 §9.3.1 read directly off the device: "Is the route in
    # the RIB but not the FIB?" EOS answers it per route with `hardwareProgrammed`, and a
    # route the control plane knows but the forwarding plane never installed is a real,
    # self-contained fault — no knowledge of which prefixes are EXPECTED is needed, which
    # is what makes most of that SOP unreachable for an engine.
    "route_table":     ("destination", "next_hop", "interface", "protocol", "metric",
                        "programmed", "route_action"),
    "neighbor_table":  ("local_interface", "neighbor_name", "neighbor_interface"),
    "log_lines":       ("timestamp", "host", "facility", "severity", "mnemonic",
                        "message", "severity_class", "event_source", "age_minutes"),
    "status_kv":       ("version", "model", "uptime", "serial", "hostname"),
    "ping_result":     ("target", "loss_pct", "sent", "received", "rtt_avg"),
    "mac_table":       ("mac", "port", "vlan"),
    "policy_table":    ("policy_id", "name", "action", "src_intf", "dst_intf",
                        "src_addr", "dst_addr", "service", "nat", "status"),
    "counter_kv":      ("session_count", "setup_rate", "exp_count", "clash",
                        "memory_tension_drop", "ses_limit"),
    "acl_table":       ("acl_name", "seq", "action", "protocol", "source",
                        "destination", "matches", "dropping"),
    "vlan_table":      ("vlan_id", "vlan_name", "status", "ports"),
    "resource_kv":     ("mem_used_pct", "mem_free_pct", "cpu_idle_pct", "cpu_used_pct",
                        "uptime"),
    # One `show interfaces <if>` answers six of the reference SOP's seven physical-layer
    # questions plus MTU and subnet, so it replaces four separate reads.
    "interface_detail": ("port", "admin_state", "oper_state", "description", "mtu",
                         "duplex", "speed", "autoneg", "address", "prefix_len",
                         "flaps", "flaps_per_hour", "uptime", "uptime_hours",
                         "counters_cleared", "crc", "input_errors", "output_errors",
                         "input_discards", "output_discards", "runts", "giants",
                         "late_collisions", "collisions"),
    # Everything the reference SOP §5 asks to compare between both ends.
    "ospf_interface":   ("port", "area", "network_type", "cost", "state", "priority",
                         "hello", "dead", "retransmit", "auth", "address", "prefix_len",
                         "neighbor_count", "passive", "mtu"),
}

# Source field -> canonical field, per shape. Keys are matched loosely: the first
# source field present wins, so one map serves several vendors.
_FIELDS: dict[str, dict[str, tuple[str, ...]]] = {
    "peer_table": {
        "peer":      ("peer", "bgp_neigh", "neighbor_id", "neighbor", "router_id", "routerId", "ip_address"),
        "state":     ("state", "adjacencyState", "status", "session_state", "peer_state"),
        "interface": ("interface", "interfaceName", "local_interface"),
        "uptime":    ("uptime", "up_down", "dead_time"),
    },
    "interface_table": {
        "port":        ("port", "interface", "name", "ifName"),
        "oper_state":  ("oper_state", "status", "link_status", "proto", "lineProtocolStatus"),
        "admin_state": ("admin_state", "admin_status", "interfaceStatus", "enabled"),
        "description": ("description", "name", "ifAlias", "alias"),
        "speed":       ("speed", "bandwidth"),
        "duplex":      ("duplex",),
    },
    # `_read_resources` handles the text forms. This map is for the TEMPLATE path: IOS
    # `show processes memory sorted` parses cleanly via textfsm to memory_total /
    # memory_used / memory_free, and then produced NO signal, because every memory
    # predicate binds `mem_used_pct` and nothing derived it. Parsed, and still blind.
    "resource_kv": {
        "memory_total": ("memory_total", "mem_total", "total"),
        "memory_used":  ("memory_used", "mem_used", "used"),
        "memory_free":  ("memory_free", "mem_free", "free"),
    },
    "route_table": {
        # `_key` last: a keyed JSON collection carries the prefix as its key
        # (`"routes": {"0.0.0.0/0": {...}}`), which is the destination.
        "destination": ("destination", "network", "prefix", "route", "_key"),
        "next_hop":    ("next_hop", "gateway", "nexthop", "via"),
        "interface":   ("interface", "nexthop_if", "outgoing_interface"),
        "protocol":    ("protocol", "type", "routeType", "proto"),
        "metric":      ("metric", "distance", "cost"),
        "programmed":  ("programmed", "hardwareProgrammed"),
        "route_action": ("route_action", "routeAction"),
    },
    "neighbor_table": {
        "local_interface":    ("local_interface", "local_port", "localInterface", "interface"),
        "neighbor_name":      ("neighbor_name", "neighbor", "device_id", "systemName", "chassis_id"),
        "neighbor_interface": ("neighbor_interface", "neighbor_port", "port_id", "remote_port"),
    },
    "acl_table": {
        # ntc-templates' arista_eos_show_ip_access-lists yields name/sn/action/protocol.
        "acl_name":    ("acl_name", "name", "acl", "access_list"),
        "seq":         ("seq", "sn", "sequence", "line_num"),
        "action":      ("action", "permit_deny", "rule_action"),
        "protocol":    ("protocol", "proto"),
        "source":      ("source", "src", "source_address"),
        "destination": ("destination", "dst", "destination_address"),
        # the match counter is the diagnostic bit: a deny rule with hits is positive
        # evidence that an ACL is dropping traffic, not merely that one exists
        # ntc-templates leaves the hit counter inside the free-text `modifier`
        # ("[match 812 bytes in 9 packets, 0:00:03 ago]"); _derive_acl pulls the
        # packet count out of it.
        "matches":     ("matches", "match", "packets", "hit_count", "hits", "modifier"),
    },
    "vlan_table": {
        "vlan_id":   ("vlan_id", "vlan", "id"),
        "vlan_name": ("vlan_name", "name"),
        "status":    ("status", "state"),
        "ports":     ("ports", "interfaces", "interface"),
    },
    "mac_table": {
        # `moves` is why this shape is diagnostic and not just an inventory: a MAC
        # relearned repeatedly on different ports is a layer-2 loop or a duplicate
        # address, and ntc-templates already extracts the column.
        "moves": ("moves", "move_count"),
        "mac":  ("mac", "mac_address", "destination_address"),
        "port": ("port", "ports", "interface", "destination_port"),
        "vlan": ("vlan", "vlan_id"),
    },
    "status_kv": {
        "version":  ("version", "image", "os_version", "running_image", "softwareImage"),
        "model":    ("model", "platform", "hardware", "modelName"),
        "uptime":   ("uptime", "up_time"),
        "serial":   ("serial", "serial_number", "serialNumber"),
        "hostname": ("hostname", "host_name", "system_name"),
    },
}

# ── value normalisation ──────────────────────────────────────────────────────
# Real values are messy: Arista reports an OSPF adjacency as "FULL/BDR" and an
# interface as "connected"; FortiOS says "up". Predicates must not have to know.
_STATE_WORDS = ("full", "established", "idle", "active", "connect", "opensent",
                "openconfirm", "init", "2way", "exstart", "exchange", "loading", "down")


def _norm_state(v: str) -> str:
    """'FULL/BDR' -> 'full';  'Established' -> 'established';  '2 WAYS' -> '2way'.

    The OSPF state IS the branch point of the whole adjacency diagnosis (EXSTART points
    at MTU, INIT at a one-way hello), so the vendors' spellings have to collapse to one
    value or a signal matches on one platform and silently not the other: Arista prints
    `2 WAYS`, Cisco prints `2WAY`.
    """
    s = str(v or "").strip().lower()
    flat = s.replace(" ", "").replace("-", "")
    if flat.startswith("2way"):
        return "2way"
    # Arista renders ExStart as `EXCH START`; Cisco as `EXSTART`. Checked BEFORE
    # `exchange`, since both flatten to a leading "exch" and the two states point at the
    # same cause but are different states. Found on real hardware — the synthetic test
    # used `EXSTART`, a spelling this platform never prints.
    if flat.startswith("exchstart") or flat.startswith("exstart"):
        return "exstart"
    if flat.startswith("exchange"):
        return "exchange"
    for w in _STATE_WORDS:
        if s.startswith(w) or f"/{w}" in s or f" {w}" in s:
            return w
    return s


# One status word carries BOTH admin and operational state, and conflating them
# reports the wrong root cause: on Arista/Cisco `disabled` means someone shut the
# port, while `notconnect` means the port is up and the light is gone. Those need
# different fixes. Mapping both to "down" said interface-link-down for a port that
# had actually been administratively shut.
#   status word            -> (admin_state, oper_state)
_STATUS_STATES = (
    (r"^(connected|up|active|ok)\b",                    ("up",   "up")),
    (r"^(admin.?down|administratively down|disabled|shutdown)\b", ("down", "down")),
    (r"^(errdisabled|err.?disable)\b",                  ("up",   "down")),
    (r"^(notconnect|not ?connected|down|inactive|no ?carrier)\b", ("up", "down")),
    (r"^(monitoring|dormant|testing)\b",                ("up",   "unknown")),
)


def _derive_states(v: str) -> tuple[str, str]:
    """Split one vendor status word into (admin_state, oper_state)."""
    s = str(v or "").strip()
    for pat, states in _STATUS_STATES:
        if re.match(pat, s, re.I):
            return states
    return ("unknown", s.lower() or "unknown")


_SEVERITY_CLASS = {0: "critical", 1: "critical", 2: "critical", 3: "error",
                   4: "warning", 5: "notice", 6: "info", 7: "debug"}
_FORTI_LEVEL = {"emergency": "critical", "alert": "critical", "critical": "critical",
                "error": "error", "warning": "warning", "notice": "notice",
                "information": "info", "debug": "debug"}


#: Column words that identify a rendered table header per shape. Two or more present
#: on one line means the device DID print the table — so zero rows is "nothing to
#: report", not "we could not read this".
_HEADERS = {
    "peer_table":      ("neighbor", "peer", "state", "router id", "up/down", "dead time"),
    "interface_table": ("port", "interface", "status", "vlan", "duplex", "protocol"),
    "route_table":     ("destination", "gateway", "next hop", "network", "distance"),
    "neighbor_table":  ("neighbor", "local", "port id", "device id", "holdtme", "capability"),
}


def _header_line(text: str, shape: str) -> str:
    words = _HEADERS.get(shape, ())
    for line in text.splitlines():
        low = line.lower()
        if sum(1 for w in words if w in low) >= 2:
            return line.strip()[:200]
    return (text.strip().splitlines() or [""])[0][:200]


def _header_only(text: str, shape: str) -> bool:
    """The table header printed but no data rows followed."""
    words = _HEADERS.get(shape)
    if not words:
        return False
    lines = [l for l in text.splitlines() if l.strip()]
    if not lines:
        return False
    hdr = None
    for i, line in enumerate(lines):
        if sum(1 for w in words if w in line.lower()) >= 2:
            hdr = i
            break
    if hdr is None:
        return False
    # anything after the header that is not a separator rule counts as a data row
    rest = [l for l in lines[hdr + 1:] if set(l.strip()) - {"-", "=", " "}]
    return not rest


def _all_dashes(rec: dict) -> bool:
    """ntc-templates sometimes matches a table's ASCII underline as a record —
    e.g. {'neighbor_name': '------------------'}. Drop those."""
    vals = [str(v).strip() for v in rec.values() if str(v).strip()]
    return bool(vals) and all(set(v) <= {"-", "="} for v in vals)


#: The field a record is identified by, used to find its own line in the raw output
#: so `evidence` quotes the line that justifies the signal rather than the table header.
_IDENT = {"interface_table": ("port",), "peer_table": ("peer", "interface"),
          "route_table": ("destination",), "neighbor_table": ("neighbor_name", "local_interface"),
          "status_kv": ("hostname", "model")}


def _source_line(text: str, rec: dict, shape: str) -> str:
    """The output line this record came from. TextFSM does not report it, so match
    on the record's identifying value."""
    for field in _IDENT.get(shape, ()):
        val = str(rec.get(field) or "").strip()
        if len(val) < 2:
            continue
        for line in text.splitlines():
            if val in line and line.strip() and not line.strip().startswith("-"):
                return line.strip()
    return ""


def _canonical(records: list[dict], shape: str, text: str = "") -> list[dict]:
    fmap = _FIELDS.get(shape)
    if not fmap:
        return [r for r in records if not _all_dashes(r)]
    out = []
    for rec in records:
        if _all_dashes(rec):
            continue
        low = {k.lower(): v for k, v in rec.items()}
        c: dict[str, Any] = {}
        for canon, candidates in fmap.items():
            for src in candidates:
                if src.lower() in low and str(low[src.lower()]).strip() != "":
                    c[canon] = low[src.lower()]
                    break
        if "state" in c:
            c["state"] = _norm_state(c["state"])
        if shape == "acl_table":
            _derive_acl(c)
        if shape == "resource_kv":
            _derive_memory_pct(c)
        # A single vendor status word carries both admin and operational state.
        # Derive both from whichever field we found, so `disabled` (someone shut it)
        # is never reported as `notconnect` (the light went away).
        raw_status = c.get("oper_state") or c.get("admin_state")
        if raw_status is not None:
            admin, oper = _derive_states(raw_status)
            c["admin_state"], c["oper_state"] = admin, oper
            c["status_raw"] = str(raw_status).strip()
        if c:
            c["_raw"] = rec
            if text:
                c["_line"] = _source_line(text, c, shape)
            out.append(c)
    if shape == "route_table":
        _derive_install_state(out)
    return out


def _derive_install_state(records: list[dict]) -> None:
    """installed / superseded / not-installed, per destination.

    `route-not-programmed` confirms `route-not-installed`, so it can be named a ROOT
    CAUSE — and its predicate was `any: {programmed: "false"}`, which fires on any route
    sitting in the RIB outside the FIB. a lab firewall carries two default routes:

        S       0.0.0.0/0 [10/0] via 10.0.1.1, port2   distance 10, not in FIB
        S    *> 0.0.0.0/0 [5/0]  via 10.0.0.2, port1   distance  5, in FIB

    which is a FLOATING STATIC BACKUP working exactly as designed. Diagnosing that as a
    routing fault is a false positive on a healthy firewall, and it would have shipped the
    moment the FortiOS route reader started producing `programmed` at all.

    A route not in the FIB is only a fault when NOTHING is forwarding for that
    destination. Where a better route won, the loser is `superseded` — the table is
    correct and there is nothing to report.

    `any:` reads only its first key, so two conditions cannot be ANDed in a predicate
    without being silently dropped. Hence one derived field rather than a compound test.
    """
    def _yes(v) -> bool:
        # Arista's JSON carries `hardwareProgrammed` as a real BOOLEAN, so a bare
        # `== "true"` marked every Arista route not-installed and turned a healthy route
        # table into `route-not-programmed` — a root cause, on 17 correct routes.
        return v is True or str(v).strip().lower() in ("true", "yes", "1")

    installed: set[str] = {r["destination"] for r in records
                           if r.get("destination") and _yes(r.get("programmed"))}
    for r in records:
        if r.get("programmed") is None:
            continue
        if _yes(r["programmed"]):
            r["install_state"] = "installed"
        elif r.get("destination") in installed:
            r["install_state"] = "superseded"
        else:
            r["install_state"] = "not-installed"


# ── log parsing — regex, no model ────────────────────────────────────────────
#: `<ts> <host> <proc>: [anything] %FACILITY-N-MNEMONIC: message`
#:
#: The `[^%]*` before the `%` matters: Arista writes
#: `Ospf: Instance 1: %OSPF-4-OSPF_ADJACENCY_TEARDOWN: ...` — the process name is
#: followed by more text before the mnemonic, and requiring the `%` immediately after
#: the colon failed EVERY Arista OSPF line on the device.
_SYSLOG = re.compile(
    r"^(?P<timestamp>\w{3}\s+\d+\s+[\d:]+)\s+(?P<host>\S+)\s+(?P<proc>\S+?):"
    r"[^%]*"
    r"%(?P<facility>[A-Z0-9_]+)-(?P<severity>\d)-(?P<mnemonic>[A-Z0-9_]+):\s*(?P<message>.*)$")

#: The same line shape with NO mnemonic at all. Arista logs the most diagnostic OSPF
#: messages this way — `Ospf: Instance 1: OSPF RECV: discarding packet from router
#: 4.4.4.4: Authentication type mismatch` states the exact root cause and carries no
#: %FACILITY-SEVERITY-MNEMONIC, so it was invisible while the SYMPTOM line beside it
#: (`adjacency dropped: inactivity timer expired`) parsed fine.
#:
#: Severity is genuinely unknown on these, so it is recorded as such rather than
#: guessed — a severity-based signal must not fire on a line whose severity we invented.
_SYSLOG_PLAIN = re.compile(
    r"^(?P<timestamp>\w{3}\s+\d+\s+[\d:]+)\s+(?P<host>\S+)\s+(?P<proc>\S+?):\s*"
    r"(?P<message>\S.*)$")

#: THE DEVICE'S OWN BUFFER, which is not the same shape as syslog on the wire.
#:
#: Both patterns above require `<timestamp> <host> <proc>:` — the relay format a collector
#: RECEIVES. But the catalog dispatches `show logging`, and IOS prints its local buffer
#: with no hostname and no process, because the device knows which device it is:
#:
#:     *Sep 17 03:35:26.843: %LINEPROTO-5-UPDOWN: Line protocol on Interface Ethernet0/0…
#:
#: So `show logging` on a Cisco device parsed to ZERO records and the read was reported
#: `ok_empty` — "the device answered and had nothing to report" — on a buffer holding 38
#: lines. Arista escaped this only because its `show logging` DOES carry the hostname.
#:
#: The leading `*` is IOS stating its clock is not NTP-synchronised; `.843` is the
#: sub-second. Both are stripped for the timestamp, and the `*` is kept as
#: `clock_unsynced` because a device whose clock is adrift is a real finding about the
#: evidence itself — log correlation across devices cannot be trusted when it is set.
#: An optional leading sequence number covers `service sequence-numbers`.
_SYSLOG_DEVICE = re.compile(
    r"^(?:\d+:\s*)?(?P<unsynced>\*)?(?P<timestamp>\w{3}\s+\d+\s+\d+:\d+:\d+)(?:\.\d+)?:\s*"
    r"%(?P<facility>[A-Z0-9_]+)-(?P<severity>\d)-(?P<mnemonic>[A-Z0-9_]+):\s*"
    r"(?P<message>.*)$")
_KV = re.compile(r'(\w+)=("([^"]*)"|\S+)')


#: (vendor, command) -> the command name to look the TEMPLATE up under.
#:
#: Only for commands whose output is byte-for-byte the same shape as one that already has
#: a template. FortiOS prints `routing-table database` and `routing-table all` with the
#: identical `Codes:` header and the identical `S *> 0.0.0.0/0 [5/0] via 10.0.0.2, port1`
#: rows; ntc-templates simply ships no entry under the `database` name, so the catalog's
#: command returned `unparseable` while the near-identical one parsed to 8 records.
#:
#: `database` is the RIGHT command to dispatch and is kept: it lists routes that are in
#: the RIB but NOT in the FIB — fw01 has two default routes and only one carries `*>` —
#: which is exactly the distinction `route-not-programmed` tests. Aliasing the lookup
#: keeps that richer output and costs nothing.
_TEMPLATE_ALIAS: dict[tuple[str, str], str] = {
    ("fortinet_fortios", "get router info routing-table database"):
        "get router info routing-table all",
}


_ACL_PACKETS = re.compile(r"match\s+[\d,]+\s+bytes\s+in\s+([\d,]+)\s+packets", re.I)


def _derive_memory_pct(c: dict) -> None:
    """Turn a template's raw byte counts into the percentage every memory signal binds.

    IOS `show processes memory sorted` opens with

        Processor Pool Total:  998641408 Used:   47108376 Free:  951533032

    which textfsm parses perfectly — and then `memory-pressure`, `cpu-saturated` and
    `resources-ok` all test `mem_used_pct`, which nothing produced. The read was `ok`
    with one record and no signal: the most misleading state available, because it
    looks like a successful check of a healthy device.

    Units are irrelevant — bytes here, kB elsewhere — since the result is a ratio. The
    figures are the device's own, so nothing is inferred beyond the division.
    """
    total = c.get("memory_total")
    used, free = c.get("memory_used"), c.get("memory_free")
    try:
        t = float(str(total).replace(",", ""))
    except (TypeError, ValueError):
        return
    if t <= 0:
        return
    try:
        u = float(str(used).replace(",", "")) if used not in (None, "") else t - float(
            str(free).replace(",", ""))
    except (TypeError, ValueError):
        return
    c["mem_used_pct"] = f"{u / t * 100:.1f}"
    c["mem_free_pct"] = f"{(t - u) / t * 100:.1f}"
    c["_line_mem_used_pct"] = (f"Processor Pool Total: {total} Used: {used} "
                               f"-> {c['mem_used_pct']}% used")


def _derive_acl(c: dict) -> None:
    """Turn an ACL entry's free-text counter into a number, and derive `dropping`.

    A predicate can only test ONE field, and neither half alone is diagnostic: every
    real ACL contains a deny rule, so `action == deny` fires everywhere, while a hit
    count says nothing about whether the rule permits or denies. What matters is the
    conjunction — a deny rule that is being hit — so it is derived here as one field
    the SOP can ask about.

    Observed on a lab switch: rule 20 denies with 9 packets matched, rule 30 denies
    with no counter at all. Only the first is evidence of anything.
    """
    raw = str(c.get("matches") or "")
    m = _ACL_PACKETS.search(raw)
    pkts = int(m.group(1).replace(",", "")) if m else 0
    c["matches"] = str(pkts)
    c["dropping"] = "yes" if (str(c.get("action", "")).lower().startswith("deny")
                              and pkts > 0) else "no"


#: Our own SSH sessions write to the log we are reading. Each triage command leaves an
#: %ACCOUNTING-5-EXEC and an %ACCOUNTING-6-CMD line, so a run adds ~12 entries — measured
#: on a lab switch, 91 of the last 100 log lines were our own audit trail. That is why the
#: read is time-bounded rather than count-bounded (`show logging 100` would push a real
#: fault out of the window), and why a record has to say whether it came from the DEVICE
#: or from us: `log-clean` once meant "no fault in the log" while resting on eight lines
#: of our own `show` commands.
#:
#: A command audit for a WRITE is a device event, not noise — "recent interface changes"
#: is a question the reference SOP asks, and `cmd=config ...` is how it gets answered.
#:
#: SESSION SCAFFOLDING COUNTS AS OURS TOO. Every SSH session we open logs `cmd=terminal
#: width 511`, `cmd=terminal length 0`, `cmd=enable` and `cmd=exit` around the actual
#: read. Matching only read verbs classified all four as DEVICE events — measured over an
#: hour on the 14-device lab, 151 of 192 `ACCOUNTING-CMD` lines were our own scaffolding
#: read as device activity, a 79% miss. That is the same bug as `log-clean` resting on our
#: own footprints, just one layer down: these lines inflate the device-event count, so
#: `log-window-only-our-own-activity` cannot fire when it should and the fall-through
#: reports a device that "logged something" when all it logged was us arriving.
#:
#: `cmd=config ...` deliberately stays a DEVICE event — see the note above.
_SELF_READ_CMD = re.compile(
    r"cmd=(show|get|display|diagnose|execute log"
    r"|terminal|enable|exit|end|logout|quit|no paging|set cli)\b", re.I)


def _event_source(facility: str, message: str) -> str:
    if (facility or "").upper() != "ACCOUNTING":
        return "device"
    if _SELF_READ_CMD.search(message or ""):
        return "self"
    # an EXEC start/stop with no command is a session of ours; a cmd= that is not a read
    # is somebody changing the box
    return "self" if "cmd=" not in (message or "") else "device"


#: How far back a log line may be and still count as evidence for a CURRENT fault.
#:
#: Enforced here rather than in the command, because it has to hold on every vendor.
#: Arista takes `show logging last 1 hours`; Cisco IOS has no time filter in
#: `show logging` at all, and Juniper's `| match` is facility-only. Leaving those
#: unbounded means a fault resolved days ago can diagnose a live one — observed on the
#: lab: an authentication mismatch that had already been FIXED still matched from the
#: buffer, and only escaped being convicted because a healthy-adjacency signal happened
#: to run first and exclude the candidate.
#:
#: 60 minutes is the window an alert is plausibly about. Stage 0 of the plan replaces
#: this with the alert's own `fired_at`, which is the correct reference point — "recent"
#: should mean recent relative to the EVENT, not to now.
_LOG_WINDOW_MINUTES = 60

_SYSLOG_TS = re.compile(r"^(\w{3})\s+(\d+)\s+(\d{1,2}):(\d{2}):(\d{2})$")
_MONTHS = {m: i + 1 for i, m in enumerate(
    ("jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"))}


def _syslog_dt(ts: str):
    """Parse an RFC3164 timestamp to a naive datetime in the DEVICE's own frame.

    Syslog carries no year, so the current one is assumed; a result more than a day in
    the future means the line is from December read in January, so roll back.
    """
    from datetime import datetime, timedelta
    raw = (ts or "").strip()
    # FortiOS carries a full ISO date (`date=2026-09-16 time=23:02:03`), which is better
    # than RFC3164 — it has the year — but matched none of the patterns below, so every
    # FortiOS line got `age_minutes` of None and the recency window could not drop
    # anything. A year-old line was as current as a fresh one.
    if (iso := re.match(r"^(\d{4})-(\d{2})-(\d{2})[ T](\d{1,2}):(\d{2}):(\d{2})", raw)):
        try:
            return datetime(*(int(g) for g in iso.groups()))
        except ValueError:
            return None
    m = _SYSLOG_TS.match(raw)
    if not m:
        return None
    mon = _MONTHS.get(m.group(1).lower())
    if not mon:
        return None
    now = datetime.now()
    try:
        when = datetime(now.year, mon, int(m.group(2)), int(m.group(3)),
                        int(m.group(4)), int(m.group(5)))
    except ValueError:
        return None
    if when - now > timedelta(days=1):
        when = when.replace(year=now.year - 1)
    return when


def _log_age_minutes(ts: str, reference=None) -> float | None:
    """Minutes between a syslog timestamp and `reference` — BY DEFAULT THE NEWEST LINE IN
    THE SAME READ, not our own clock.

    RFC3164 carries no timezone, so comparing a device timestamp against `datetime.now()`
    compares two different frames. A brain running UTC reading a device logging IST sees
    every line as 5.5 hours old, the recency window drops all of them, and every
    log-based finding silently disappears — measured on the lab, log lines are 822 of
    1,836 evidence lines, so that is most of the evidence. It worked on the demo only
    because both happen to be UTC.

    The newest line in a read of `show logging last 10 minutes` is approximately "now" on
    the DEVICE, which makes the window immune to timezone and to clock drift. Freshness of
    the read itself is already guaranteed by the command, which is where it belongs; our
    arithmetic only has to order lines within it.
    """
    when = _syslog_dt(ts)
    if when is None:
        return None
    if reference is None:
        from datetime import datetime
        reference = datetime.now()
    now = reference
    return (now - when).total_seconds() / 60.0


def parse_logs(text: str) -> list[dict]:
    """Arista/Cisco '%FACILITY-SEVERITY-MNEMONIC:' and FortiOS 'key=value' lines.

    Every record carries `_line`, the source line it came from. Without it `evaluate`
    falls back to facts["evidence"], which for a log read is records[0]["message"] —
    so a signal that fired on record 6 was quoted with record 1. Measured on
    a lab firewall: `critical-logged` was CORRECT (two level="alert" admin-login
    failures) but the evidence read "Admin login successful", an `information` line.
    Right answer, wrong proof, which is the kind of evidence an engineer stops
    trusting.
    """
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        m = _SYSLOG.match(line)
        if m:
            d = m.groupdict()
            d["severity_class"] = _SEVERITY_CLASS.get(int(d["severity"]), "info")
            d["_line"] = line
            d["event_source"] = _event_source(d.get("facility"), d.get("message"))
            out.append(d)
            continue
        # Tried BEFORE _SYSLOG_PLAIN: that pattern's `<host> <proc>:` would otherwise
        # swallow a device-buffer line, reading the timestamp as the host and losing the
        # facility, severity and mnemonic that every log signal binds on.
        m = _SYSLOG_DEVICE.match(line)
        if m:
            d = m.groupdict()
            unsynced = d.pop("unsynced", None)
            d["severity_class"] = _SEVERITY_CLASS.get(int(d["severity"]), "info")
            d["host"] = ""          # the device's own buffer names no host
            d["proc"] = d["facility"]
            d["clock_unsynced"] = "true" if unsynced else "false"
            d["_line"] = line
            d["event_source"] = _event_source(d.get("facility"), d.get("message"))
            out.append(d)
            continue
        m = _SYSLOG_PLAIN.match(line)
        if m:
            d = m.groupdict()
            out.append({
                "timestamp": d["timestamp"], "host": d["host"], "proc": d["proc"],
                # the process IS the facility here; there is no mnemonic to report
                "facility": d["proc"], "mnemonic": "", "severity": "",
                "severity_class": "unknown", "event_source": "device",
                "message": d["message"].strip(),
                "_line": line,
            })
            continue
        if "=" in line and ("logid=" in line or "date=" in line):
            # `v.startswith('"')` decides whether the value WAS quoted — NOT
            # `g3 is not None`. `re.findall` returns '' for a group that did not
            # participate, never None, so the old test was always true and every
            # UNQUOTED field came back empty: date, time, srcip, dstip, duration and
            # every numeric counter. FortiOS quotes strings and leaves numbers and dates
            # bare, so exactly the fields a threshold or a timestamp needs were the ones
            # being dropped — and `timestamp` empty means `age_minutes` is empty, which
            # means the log recency window cannot drop anything and a year-old line can
            # be quoted as current evidence.
            kv = {k: (g3 if v.startswith('"') else v) for k, v, g3 in _KV.findall(line)}
            if kv:
                out.append({
                    "timestamp": f"{kv.get('date','')} {kv.get('time','')}".strip(),
                    "host": kv.get("devname", ""),
                    "facility": kv.get("type", ""),
                    "mnemonic": kv.get("logid", ""),
                    "severity": kv.get("level", ""),
                    "severity_class": _FORTI_LEVEL.get((kv.get("level") or "").lower(), "info"),
                    "event_source": "device",
                    "message": kv.get("logdesc") or kv.get("msg", ""),
                    "_raw": kv,
                    "_line": line,
                })
    # AGES ARE DEVICE-RELATIVE. The reference is the NEWEST timestamp in this read, not
    # our clock: RFC3164 carries no timezone, so comparing a device stamp to
    # `datetime.now()` compares two frames and a UTC brain reading an IST device drops
    # every line as stale. See _log_age_minutes. Falls back to our clock only when no
    # line in the read has a parseable timestamp, where there is nothing better.
    stamps = [dt for dt in (_syslog_dt(r.get("timestamp")) for r in out) if dt]
    ref = max(stamps) if stamps else None
    for r in out:
        age = _log_age_minutes(r.get("timestamp"), reference=ref)
        r["age_minutes"] = f"{age:.1f}" if age is not None else ""
    return out


#: Both vendors print the same statistics shape, with one word of difference:
#:   Arista  "5 packets transmitted, 5 received, 0% packet loss"
#:   FortiOS "5 packets transmitted, 5 packets received, 0% packet loss"
_PING = re.compile(r"(\d+) packets transmitted,\s*(\d+)(?: packets)? received,\s*(\d+)% packet loss", re.I)
_RTT = re.compile(r"(?:rtt|round-trip) min/avg/max(?:/mdev)?\s*=\s*[\d.]+/([\d.]+)/", re.I)
#: IOS does not print a Linux-style statistics line at all — it reports a SUCCESS RATE:
#:     Success rate is 100 percent (5/5), round-trip min/avg/max = 1/1/2 ms
#: so `ping-peer` on a Cisco device returned `unparseable`/`ping_no_stats`: the reachability
#: check that half the SOPs open with could not read the clearest answer a device gives.
#: Note the SENSE IS INVERTED — this is success, `_PING` captures loss — and IOS prints
#: `(5/5)` as received/sent, the reverse order of the Linux line.
_PING_IOS = re.compile(
    r"Success rate is (\d+) percent\s*\((\d+)/(\d+)\)", re.I)


def _read_ping(text: str) -> dict:
    """A ping's answer IS its verdict — reachable, lossy or dark."""
    m = _PING.search(text)
    if not m:
        if (ios := _PING_IOS.search(text)):
            recv, sent = int(ios.group(2)), int(ios.group(3))
            loss = 100 - int(ios.group(1))
            rtt = re.search(r"min/avg/max\s*=\s*[\d.]+/([\d.]+)/", text, re.I)
            return {"status": TOTAL_LOSS if loss >= 100 else
                              (NO_LOSS if loss == 0 else PARTIAL_LOSS),
                    "records": [{"sent": sent, "received": recv, "loss_pct": loss,
                                 "rtt_avg": rtt.group(1) if rtt else None,
                                 "_line": ios.group(0)}],
                    "evidence": ios.group(0), "source": "ping_ios"}
        # An immediate failure never reaches a statistics line, and THAT is the answer.
        # On a real fault Arista returned exactly "ping: connect: Network is unreachable"
        # — 37 characters, no statistics — and requiring statistics turned the clearest
        # possible evidence into "could not read it".
        fail = re.search(r"network is unreachable|no route to host|destination host "
                         r"unreachable|name or service not known|invalid (?:host|address)"
                         r"|connect: ", text, re.I)
        if fail:
            line = next((l.strip() for l in text.splitlines()
                         if fail.group(0).lower() in l.lower()), fail.group(0))
            return {"status": TOTAL_LOSS, "records": [],
                    "evidence": line[:200], "source": "ping_unreachable"}
        # genuinely no verdict: the command did not complete, which is NOT "unreachable"
        return {"status": UNPARSEABLE, "records": [],
                "evidence": (text.strip().splitlines() or [""])[0][:200], "source": "ping_no_stats"}
    sent, recv, loss = int(m.group(1)), int(m.group(2)), int(m.group(3))
    rtt = _RTT.search(text)
    status = TOTAL_LOSS if loss >= 100 else (NO_LOSS if loss == 0 else PARTIAL_LOSS)
    return {"status": status,
            "records": [{"sent": sent, "received": recv, "loss_pct": loss,
                         "rtt_avg": rtt.group(1) if rtt else None,
                         "_line": m.group(0)}],
            "evidence": m.group(0), "source": "ping"}


def _read_clock(text: str) -> dict | None:
    """Arista states its clock SOURCE, which is the diagnostic bit: a device running on
    its local clock has no NTP, and that silently breaks certs, auth and correlation."""
    m = re.search(r"Clock source:\s*(.+)", text, re.I)
    if not m:
        return None
    src = m.group(1).strip()
    if re.match(r"local", src, re.I):
        return {"status": CLOCK_LOCAL, "records": [],
                "evidence": m.group(0).strip(), "source": "clock_source"}
    return None


# ── the entry point ──────────────────────────────────────────────────────────
async def extract_layered(vendor: str, command: str, output: str, shape: str) -> dict:
    """extract(), deterministic layers only. Output they cannot read stays unparseable."""
    return extract(vendor, command, output, shape)


_EDIT   = re.compile(r"^\s*edit\s+\"?([^\"\s]+)\"?\s*$", re.I)
_SET    = re.compile(r"^\s*set\s+(\S+)\s+(.*?)\s*$", re.I)
_NEXT   = re.compile(r"^\s*(next|end)\s*$", re.I)
_POLICY_FIELD = {
    "name": "name", "action": "action", "srcintf": "src_intf", "dstintf": "dst_intf",
    "srcaddr": "src_addr", "dstaddr": "dst_addr", "service": "service",
    "nat": "nat", "status": "status",
}


def _read_fortios_config(text: str) -> dict | None:
    """FortiOS `show <table>` — `edit N` / `set k v` / `next` blocks, one record each.

    No TextFSM template covers this and it is perfectly regular, so it is parsed
    deterministically rather than reaching the model.

    FortiOS OMITS defaults, which matters for reading it correctly: a policy carries
    `set status disable` only when disabled, and `set nat enable` only when NAT is on.
    So absence is the default, not unknown — recorded explicitly here, because a signal
    asking `all: {status: enable}` cannot match a field that was never emitted.
    """
    recs: list[dict] = []
    cur: dict | None = None
    for raw in text.splitlines():
        m = _EDIT.match(raw)
        if m:
            cur = {"policy_id": m.group(1), "status": "enable", "nat": "disable",
                   "_line": raw.strip()}
            continue
        if _NEXT.match(raw):
            if cur:
                recs.append(cur)
            cur = None
            continue
        m = _SET.match(raw)
        if m and cur is not None:
            key = m.group(1).lower()
            if key in _POLICY_FIELD:
                cur[_POLICY_FIELD[key]] = m.group(2).strip().strip('"')
    if cur:
        recs.append(cur)
    if not recs:
        return None
    return {"status": OK, "records": recs, "source": "fortios_config",
            "evidence": recs[0].get("_line") or f"policy {recs[0]['policy_id']}"}


_COUNTER = re.compile(r"\b([a-z][a-z0-9_]{2,})\s*=\s*(\d+)(?:/(\d+))?\b", re.I)


def _read_counters(text: str) -> dict | None:
    """Counter output — `session_count=102 setup_rate=1 clash=0` — as ONE record.

    One record, not one per counter: they describe a single subject, and signals
    compare named fields on it (`field: {clash: {gt: 0}}`). Values written `a/b`
    (`ephemeral=0/131062`) keep the numerator, which is the current figure. Hex-ish
    fields like `error1=00000000` parse to 0 harmlessly and nothing reads them.
    """
    rec: dict = {}
    for m in _COUNTER.finditer(text):
        rec.setdefault(m.group(1).lower(), m.group(2))
    if not rec:
        return None
    key = next((k for k in ("session_count", "clash") if k in rec), None)
    line = next((l.strip() for l in text.splitlines()
                 if key and f"{key}=" in l.lower()), "")
    rec["_line"] = line
    return {"status": OK, "records": [rec], "source": "counters",
            "evidence": line[:200] or f"{key}={rec.get(key)}"}


#: Vendors state resource use as a percentage in prose rather than a table, and the
#: figure is the whole diagnostic. FortiOS: "Memory: 2055764k total, 816652k used
#: (39.7%)" and "CPU states: 0% user ... 100% idle". Arista prints the same facts in
#: `show processes top once`. Read as ONE record of percentages so signals can compare
#: them numerically with `field:`.
_MEM_PCT  = re.compile(r"mem(?:ory)?\b[^\n]*?([\d.]+)k?\s*used\s*\(([\d.]+)%\)", re.I)
_MEM_FREE = re.compile(r"([\d.]+)k?\s*free\s*\(([\d.]+)%\)", re.I)
_CPU_IDLE = re.compile(r"([\d.]+)%\s*idle", re.I)
_UPTIME   = re.compile(r"^\s*uptime:\s*(.+)$", re.I | re.M)
#: Arista states memory in ABSOLUTE kB and no percentage, in `show version`:
#:     Total memory: 32309508 kB
#:     Free memory:  7022660 kB
#: With only the percentage forms above, `check-memory` extracted nothing but uptime on
#: Arista and `evaluate` returned NO SIGNAL — so the reference SOP's resource handoff
#: ("all adjacencies down -> process crash or resource exhaustion") spent a device round
#: and could not answer either way, on the platform the OSPF work targets.
_MEM_TOTAL_KB = re.compile(r"total memory:\s*([\d,]+)\s*kb", re.I)
_MEM_FREE_KB  = re.compile(r"free memory:\s*([\d,]+)\s*kb", re.I)

#: Junos `show chassis routing-engine` states both figures IN WORDS:
#:     Memory utilization          14 percent
#:     5 sec CPU utilization:
#:       Idle                      92 percent
#: `_CPU_IDLE` requires a literal `%`, so it matched neither and CPU was unreadable on
#: Junos. (`show system memory` happened to work only because Junos writes
#: "Total memory: … Kbytes", which `_MEM_TOTAL_KB` matches by luck of wording.)
_JUNOS_MEM_UTIL = re.compile(r"^\s*Memory utilization\s+([\d.]+)\s+percent", re.I | re.M)
#: Junos runs FreeBSD, where INACTIVE pages are clean and reclaimable on demand — they are
#: available memory, not consumed memory. Counting them as used overstates pressure by the
#: whole inactive pool, and the device says so itself: `show system memory` on HQ_CoreSW
#: reports 63% inactive, which the generic (total-free)/total gives as 77.9% used, while
#: `show chassis routing-engine` on the SAME box at the SAME moment reports 14 percent.
#: Adding inactive and cache back yields 14.7% — the two outputs agree, and the 77.9%
#: reading was minutes of load away from tripping `memory-pressure` at 85%.
_JUNOS_MEM_INACTIVE = re.compile(r"inactive memory:\s*([\d,]+)\s*kb", re.I)
_JUNOS_MEM_CACHE    = re.compile(r"cache memory:\s*([\d,]+)\s*kb", re.I)
#: The window label heading each utilisation block. Blocks are sliced BETWEEN successive
#: headers rather than matched with a lookahead terminator: every plausible "end of block"
#: pattern also matches the block's own body lines (`  User   2 percent`), which silently
#: produced four EMPTY blocks and no CPU reading at all.
_JUNOS_CPU_HEADER = re.compile(r"^[ \t]*(\d+)\s*(sec|min)\s+CPU utilization:", re.I | re.M)
_JUNOS_CPU_IDLE = re.compile(r"^\s*Idle\s+([\d.]+)\s+percent", re.I | re.M)


def _junos_cpu_idle(text: str) -> tuple[str, str] | None:
    """Idle % from `show chassis routing-engine`, from the most SUSTAINED window available.

    The device prints four blocks — 5 sec, 1 min, 5 min, 15 min — and taking the first
    would read CPU over five seconds. `cpu-saturated` fires above 90% used, so a
    five-second sample makes any momentary spike a control-plane exhaustion verdict: the
    same error as judging a link by a cumulative flap counter, which is why
    `flaps_per_hour` and `changes_per_hour` exist.

    Preference is 5 min, then 1 min, then whatever is there. 15 min is NOT preferred over
    5 min — it is slow enough to mask a real ongoing exhaustion that started minutes ago.
    """
    heads = list(_JUNOS_CPU_HEADER.finditer(text))
    blocks: dict[str, tuple[str, str]] = {}
    for i, h in enumerate(heads):
        end = heads[i + 1].start() if i + 1 < len(heads) else len(text)
        idle = _JUNOS_CPU_IDLE.search(text[h.end():end])
        if idle:
            blocks[f"{h.group(1)} {h.group(2).lower()}"] = (
                idle.group(1), f"{h.group(1)} {h.group(2)} CPU utilization: "
                               f"Idle {idle.group(1)} percent")
    for key in ("5 min", "1 min"):
        if key in blocks:
            return blocks[key]
    return next(iter(blocks.values()), None)


def _read_resources(text: str) -> dict | None:
    rec: dict = {}
    m = _MEM_PCT.search(text)
    if m:
        rec["mem_used_pct"] = m.group(2)
        rec["_line_mem_used_pct"] = m.group(0).strip()
    elif (t := _MEM_TOTAL_KB.search(text)) and (fr := _MEM_FREE_KB.search(text)):
        total = float(t.group(1).replace(",", ""))
        free = float(fr.group(1).replace(",", ""))
        # Reclaimable pools count as AVAILABLE. Absent on Arista, so its arithmetic is
        # unchanged; present on Junos, where omitting them overstates usage by ~64 points.
        reclaim = 0.0
        parts = []
        for pat, label in ((_JUNOS_MEM_INACTIVE, "inactive"), (_JUNOS_MEM_CACHE, "cache")):
            if (mm := pat.search(text)):
                reclaim += float(mm.group(1).replace(",", ""))
                parts.append(f"{label} {mm.group(1)}")
        if total > 0:
            avail = free + reclaim
            rec["mem_used_pct"] = f"{(total - avail) / total * 100:.1f}"
            rec["mem_free_pct"] = f"{avail / total * 100:.1f}"
            if parts:
                rec["_line_mem_used_pct"] = (
                    f"Total {t.group(1)} kB / free {fr.group(1)} kB"
                    f" + reclaimable ({', '.join(parts)}) -> {rec['mem_used_pct']}% used")
    m2 = _MEM_FREE.search(text)
    if m2:
        rec["mem_free_pct"] = m2.group(2)
    m3 = _CPU_IDLE.search(text)
    if m3:
        rec["cpu_idle_pct"] = m3.group(1)
        rec["_line_cpu_idle_pct"] = rec["_line_cpu_used_pct"] = m3.group(0).strip()
        # stated as idle; signals ask about load, so derive the complement rather than
        # make every contract subtract from 100 itself
        try:
            rec["cpu_used_pct"] = f"{100.0 - float(m3.group(1)):.1f}"
        except ValueError:
            pass
    # Junos states both in words; only reached when the `%`-bearing forms found nothing,
    # so no existing vendor's reading can be overwritten by these.
    if "cpu_used_pct" not in rec and (j := _junos_cpu_idle(text)):
        idle, line = j
        rec["cpu_idle_pct"] = idle
        rec["_line_cpu_idle_pct"] = rec["_line_cpu_used_pct"] = line
        try:
            rec["cpu_used_pct"] = f"{100.0 - float(idle):.1f}"
        except ValueError:
            pass
    if "mem_used_pct" not in rec and (jm := _JUNOS_MEM_UTIL.search(text)):
        rec["mem_used_pct"] = jm.group(1)
        rec["_line_mem_used_pct"] = jm.group(0).strip()
    m4 = _UPTIME.search(text)
    if m4:
        rec["uptime"] = m4.group(1).strip()
    if not rec:
        return None
    # The quoted line must not be empty: a finding whose evidence is "" states a verdict
    # with nothing under it. The percentage-bearing line is preferred, but Arista's
    # `Total memory: … kB` carries no `%` at all and fell through to "".
    line = next((l.strip() for l in text.splitlines()
                 if re.search(r"mem(ory)?\b.*%|%\s*idle", l, re.I)), "")
    if not line:
        mem_lines = [l.strip() for l in text.splitlines()
                     if re.search(r"^\s*(?:total|free) memory:", l, re.I)]
        line = " / ".join(mem_lines)
    rec["_line"] = line
    return {"status": OK, "records": [rec], "source": "resources",
            "evidence": line[:200]}


#: A device stating a count of ZERO is a positive finding; a template returning no rows
#: is not. Arista ends `show mac address-table` with "Total Mac Addresses for this
#: criterion: 0" and FortiOS answers `execute log display` with "0 logs found." — in
#: both cases the device has ANSWERED, and reading that as unparseable throws away the
#: one unambiguous form of emptiness there is. Anchored to a literal 0 so a populated
#: table can never match.
_EXPLICIT_ZERO = re.compile(
    r"^\s*(?:total\b[^:\n]*:\s*0\b"
    r"|0\s+(?:logs?|entries|entry|routes?|sessions?|neighbou?rs?)\s+(?:found|displayed)\b"
    r"|number of [^:\n]*(?:is|:)\s*0\b)", re.I | re.M)


def _states_zero(text: str) -> str | None:
    """The line where the device declares a count of zero, if it does."""
    m = _EXPLICIT_ZERO.search(text or "")
    return m.group(0).strip() if m else None


# ── one-command physical layer + OSPF interface (regex; no template covers either) ──

def _num(m, default=None):
    return m.group(1).replace(",", "") if m else default


_UPTIME_UNITS = (("day", 24.0), ("hour", 1.0), ("minute", 1 / 60), ("second", 1 / 3600))


def _uptime_hours(text: str) -> float | None:
    """"22 hours, 58 minutes, 42 seconds" -> 22.98"""
    if not text:
        return None
    total, found = 0.0, False
    for unit, mult in _UPTIME_UNITS:
        m = re.search(rf"(\d+)\s*{unit}s?\b", text, re.I)
        if m:
            total += int(m.group(1)) * mult
            found = True
    return total if found else None


def _read_interface_detail(text: str) -> dict | None:
    """`show interfaces <if>` — the reference SOP's whole §2 in one read.

    Six of its seven physical questions come from here (up/up, flaps, CRC and error
    counters, discards, speed/duplex), plus MTU for §6 and the address/mask §5 compares.
    `show interfaces <if> counters errors` was a separate capability returning the SAME
    FCS/Align/Symbol/Runts/Giants counters, so it is redundant.

    Optics is the one §2 item NOT here — it needs `<if> transceiver`, which returns
    empty on virtual hardware and must read as "cannot assess", never as healthy.
    """
    first = next((l for l in text.splitlines() if l.strip()), "")
    m = re.match(r"^(\S+) is (\S+), line protocol is (\S+)", first)
    if not m:
        return None
    port, admin_raw, oper_raw = m.group(1), m.group(2), m.group(3)
    rec: dict = {
        "port": port,
        # "administratively down" is a person; "down" is the light. _derive_states holds
        # that distinction for the table form and it matters just as much here.
        "admin_state": "down" if re.search(r"admin", admin_raw, re.I) else "up",
        "oper_state": "up" if oper_raw.lower().startswith("up") else "down",
        "_line": first.strip(),
    }
    if re.search(r"is administratively down", text[:200], re.I):
        rec["admin_state"] = "down"

    for key, pat in (
        ("description",     r"^\s*Description:\s*(.+)$"),
        ("mtu",             r"MTU\s+(\d+)\s*bytes"),
        # `Auto` included: IOS prints `Auto-duplex, Auto-speed` while negotiating, and
        # SOP-INT-007 §9.3.1 asks for the NEGOTIATION STATE at both ends — its table's
        # unsafe rows are Auto-opposite-Hardcoded, so "auto" is half the answer and
        # dropping it left the most common mismatch unreadable.
        ("duplex",          r"^\s*(Full|Half|Auto)-duplex"),
        # THE ONE-SIDED DUPLEX MISMATCH DETECTOR, and the reason this SOP does not need
        # the far end to reach a verdict. §9.3.2: when one end is hard-coded it stops
        # sending negotiation signalling, so the auto end falls back to HALF duplex by
        # standard while the hard-coded end stays FULL. The half-duplex end then sees
        # late collisions — a collision after the 512-bit slot time, which on a
        # correctly-negotiated full-duplex link is impossible, not merely unusual.
        ("late_collisions", r"(\d+)\s+late collision"),
        ("collisions",      r"(\d+)\s+collisions"),
        ("speed",           r"-duplex,\s*([^,]+?),"),
        ("autoneg",         r"auto negotiation:\s*(\S+?)(?:,|$)"),
        ("address",         r"Internet address is ((?:\d{1,3}\.){3}\d{1,3})"),
        ("prefix_len",      r"Internet address is (?:\d{1,3}\.){3}\d{1,3}/(\d+)"),
        # the flap counter — §2 asks for link flaps and this is exactly it
        ("flaps",           r"(\d+)\s+link status changes"),
        ("uptime",          r"^\s*Up\s+(.+)$"),
        ("input_errors",    r"(\d+)\s+input errors"),
        ("crc",             r"input errors,\s*(\d+)\s+CRC"),
        ("input_discards",  r"(\d+)\s+input discards"),
        ("output_errors",   r"(\d+)\s+output errors"),
        ("output_discards", r"(\d+)\s+output discards"),
        ("runts",           r"(\d+)\s+runts"),
        ("giants",          r"runts,\s*(\d+)\s+giants"),
    ):
        mm = re.search(pat, text, re.I | re.M)
        if mm:
            rec[key] = mm.group(1).strip()
            # Keep the LINE each counter came from. One `_line` cannot serve a dozen
            # counters: `interface-flapping` fired on `flaps_per_hour` and quoted the
            # header, "Ethernet1 is up, line protocol is up (connected)" — a health line
            # offered as proof of a fault. The matching line is already in hand here, so
            # keeping it costs nothing and the signal that fires on a counter quotes the
            # counter.
            rec[f"_line_{key}"] = mm.group(0).strip()

    if rec.get("duplex"):
        rec["duplex"] = rec["duplex"].lower()

    # `N link status changes since last clear` is CUMULATIVE with no window, so the raw
    # count cannot show flapping: ar02's healthy Et1 reports 16 changes over 23 hours of
    # uptime — 0.7/hour, entirely normal — and a `flaps > 5` signal called that a
    # flapping link on the very first healthy capture. Flapping is a RATE.
    #
    # The window is only knowable when the counters were never cleared, in which case it
    # is the interface uptime. If they were cleared at some unstated time, the rate is
    # unknowable and the field is left unset so no signal can fire on it — better silent
    # than confidently wrong.
    cl = re.search(r'Last clearing of .*? counters\s+(\S+)', text, re.I)
    rec["counters_cleared"] = (cl.group(1).strip().lower() if cl else "unknown")
    hrs = _uptime_hours(rec.get("uptime") or "")
    if hrs:
        rec["uptime_hours"] = f"{hrs:.2f}"
    if rec.get("flaps") and hrs and hrs > 0 and rec["counters_cleared"] == "never":
        rec["flaps_per_hour"] = f"{int(rec['flaps']) / hrs:.2f}"
        # a DERIVED field has no line of its own; quote the counter it came from, with the
        # window that makes the rate meaningful — "16 link status changes" alone is
        # healthy over a day and a fault over a minute
        rec["_line_flaps_per_hour"] = (f"{rec.get('_line_flaps', '')}"
                                       f" (up {rec.get('uptime', '?')}"
                                       f" -> {rec['flaps_per_hour']} flaps/hour)")

    return {"status": OK, "records": [rec], "source": "interface_detail",
            "evidence": first.strip()[:200]}


#: `Errors: 0, Drops: 0, Framing errors: 0, Runts: 0, …` appears under BOTH the
#: `Input errors:` and `Output errors:` headings with the same field names, so the
#: headings have to scope the read or input and output silently share a value.
_JUNOS_ERR_SECTION = re.compile(
    r"^\s*(Input|Output) errors:(.*?)(?=^\s*\w[\w ]*:\s*$|^\s{0,2}\w|\Z)", re.I | re.M | re.S)


def _read_junos_interface(text: str) -> dict | None:
    """`show interfaces <if> extensive` — Junos.

    Junos shares almost no wording with IOS or EOS here, so `_read_interface_detail`
    returned None on it and `check-interface-errors` was blind on this vendor:

        Physical interface: ge-0/0/0, Enabled, Physical link is Up
          Link-level type: Ethernet, MTU: 1514, LAN-PHY mode, Speed: 1000mbps,
          Last flapped   : 2026-09-16 03:43:43 UTC (06:38:17 ago)
          Input errors:
            Errors: 0, Drops: 0, Framing errors: 0, Runts: 0, Policed discards: 0,

    MTU IS NORMALISED TO LAYER 3, and this is the trap the reader exists to avoid.
    Junos reports the PHYSICAL MTU — 1514 — which counts the 14-byte Ethernet header;
    IOS and EOS report 1500 for the identical link. `interface-mtu-mismatch` compares
    `differs: {field: mtu, between: [local, peer]}`, so a correctly configured
    Junos-to-Cisco link would read 1514 against 1500 and report an MTU mismatch that is
    not there — a false root cause on a healthy link, quoting the device to prove it.
    The logical unit's `Protocol inet, MTU: 1500` is preferred when the capture reaches
    it; otherwise the header is subtracted. `mtu_physical` keeps the device's own number
    so the evidence line never contradicts the field.

    NO FLAP RATE IS DERIVED. `Carrier transitions` counts the interface's whole life,
    while `Last flapped` is the time since the LAST transition — dividing one by the
    other is exactly the bug fixed in `_read_peer_detail`, where a 40-day adjacency that
    blipped once 30 seconds ago read as 840 changes/hour. Junos does not print the
    counter's own window, so the rate is absent and `interface-flapping` cannot fire
    here rather than firing wrongly.
    """
    m = re.search(r"^Physical interface:\s*(\S+?),\s*(\w+),\s*Physical link is (\w+)",
                  text, re.M)
    if not m:
        return None
    rec: dict = {
        "port": m.group(1),
        "admin_state": "down" if m.group(2).lower().startswith("disab") else "up",
        "oper_state": "up" if m.group(3).lower().startswith("up") else "down",
        "_line": m.group(0).strip(),
    }
    for key, pat in (
        ("description",   r"^\s*Description:\s*(.+)$"),
        ("speed",         r"Speed:\s*([^,\s]+)"),
        ("last_flapped",  r"Last flapped\s*:\s*(.+?)\s*$"),
        ("mac_address",   r"Current address:\s*(\S+?),"),
    ):
        mm = re.search(pat, text, re.I | re.M)
        if mm:
            rec[key] = mm.group(1).strip()
            rec[f"_line_{key}"] = mm.group(0).strip()

    phys = re.search(r"\bMTU:\s*(\d+)", text)
    logical = re.search(r"Protocol\s+inet,\s*MTU:\s*(\d+)", text, re.I)
    if logical:
        rec["mtu"] = logical.group(1)
        rec["_line_mtu"] = logical.group(0).strip()
    elif phys:
        rec["mtu_physical"] = phys.group(1)
        rec["mtu"] = str(int(phys.group(1)) - 14)      # strip the Ethernet header
        rec["_line_mtu"] = (f"{phys.group(0).strip()} (physical; layer-3 MTU "
                            f"{rec['mtu']} after the 14-byte Ethernet header)")

    for m2 in _JUNOS_ERR_SECTION.finditer(text):
        direction, body = m2.group(1).lower(), m2.group(2)
        for key, pat in (("errors", r"\bErrors:\s*(\d+)"),
                         ("discards", r"\bDrops:\s*(\d+)")):
            mm = re.search(pat, body)
            if mm:
                field = f"{'input' if direction == 'input' else 'output'}_{key}"
                rec[field] = mm.group(1)
                rec[f"_line_{field}"] = f"{direction.capitalize()} errors: {mm.group(0)}"
        if direction == "input":
            for key, pat in (("runts", r"\bRunts:\s*(\d+)"),
                             ("framing_errors", r"\bFraming errors:\s*(\d+)")):
                mm = re.search(pat, body)
                if mm:
                    rec[key] = mm.group(1)
                    rec[f"_line_{key}"] = f"Input errors: {mm.group(0)}"
        else:
            mm = re.search(r"\bCarrier transitions:\s*(\d+)", body)
            if mm:
                rec["flaps"] = mm.group(1)
                rec["_line_flaps"] = f"Output errors: {mm.group(0)}"

    # Junos calls CRC "FCS errors", in the MAC statistics table further down.
    mm = re.search(r"^\s*CRC/Align errors\s+(\d+)", text, re.M) or \
        re.search(r"\bFCS errors:\s*(\d+)", text, re.I)
    if mm:
        rec["crc"] = mm.group(1)
        rec["_line_crc"] = mm.group(0).strip()

    rec["counters_cleared"] = (
        "never" if re.search(r"Statistics last cleared:\s*Never", text, re.I) else "unknown")
    return {"status": OK, "records": [rec], "source": "junos_interface",
            "evidence": rec["_line"][:200]}


#: `0.0.0.0/0          *[Static/5] 05:36:52` — a route begins at column 0 with a prefix.
#: The `*`/`+` flag is what Junos calls Active; a route printed without one is in the
#: table but not forwarding, which is the distinction `programmed` carries.
_JUNOS_ROUTE = re.compile(r"^(\S+/\d+)\s+([*+-]?)\[(\w[\w-]*)/(\d+)\]\s*(.*)$", re.M)


def _read_junos_routes(text: str) -> dict | None:
    """`show route` — Junos. ntc-templates has NO template for this at all.

    Not a silent-empty parse but a hard `ParsingException`, so the capability returned
    `unparseable` and `default-route-missing` could never be assessed on this vendor.

    A route's next hop sits on the FOLLOWING line, indented:

        0.0.0.0/0          *[Static/5] 05:36:52
        >  to 192.168.10.1 via irb.10
        192.168.10.0/24    *[Direct/0] 05:36:52
        >  via irb.10

    Both address families are read. `inet6.0` prefixes are kept with their own
    destinations so an IPv6 default is not mistaken for an IPv4 one — `routes-present`
    matches the literal `0.0.0.0/0`, and `::/0` is a different statement.
    """
    # GATED ON THE JUNOS TABLE HEADER so this reader can never claim another vendor's
    # route output. IOS prints `O  10.1.1.0/24 [110/2] via …` — a protocol CODE first,
    # then a bracket that also holds two numbers — and only the leading column keeps the
    # two apart. `inet.0: 3 destinations` is unambiguous, so it is the gate.
    if not re.search(r"^\S+\.\d+:\s+\d+\s+destinations", text, re.M):
        return None
    lines = text.splitlines()
    out: list[dict] = []
    family = None
    for i, line in enumerate(lines):
        if (fm := re.match(r"^(\S+\.\d+):\s+\d+\s+destinations", line)):
            family = fm.group(1)
            continue
        m = _JUNOS_ROUTE.match(line)
        if not m:
            continue
        rec: dict = {
            "destination": m.group(1),
            "protocol": m.group(3),
            # `*` Both, `+` Active. Anything else is present but not forwarding.
            "programmed": "true" if m.group(2) in ("*", "+") else "false",
            "_line": line.strip(),
        }
        if family:
            rec["family"] = family
        if (mt := re.search(r"\bmetric\s+(\d+)", m.group(5), re.I)):
            rec["metric"] = mt.group(1)
        # look ahead for the next-hop continuation lines, stopping at the next route
        for nxt in lines[i + 1:]:
            if not nxt.strip() or _JUNOS_ROUTE.match(nxt) or re.match(r"^\S+\.\d+:", nxt):
                break
            if (nh := re.search(r"\bto\s+(\S+)\s+via\s+(\S+)", nxt)):
                rec["next_hop"], rec["interface"] = nh.group(1), nh.group(2).rstrip(",")
                break
            if (via := re.search(r"\bvia\s+(\S+)", nxt)):
                rec["interface"] = via.group(1).rstrip(",")
                # Direct and Local routes have no next hop by definition; recording the
                # interface as one would invent a gateway the device never named.
                break
        out.append(rec)
    if not out:
        return None
    _derive_install_state(out)
    return {"status": OK, "records": out, "source": "junos_routes",
            "evidence": out[0]["_line"][:200]}


#: `S    *> 0.0.0.0/0 [5/0] via 10.0.0.2, port1`   — selected, in the FIB
#: `S       0.0.0.0/0 [10/0] via 10.0.1.1, port2`  — in the RIB, NOT in the FIB
#: `C    *> 10.0.0.0/24 is directly connected, port1`
_FOS_ROUTE = re.compile(
    r"^(?P<code>[A-Za-z][A-Za-z0-9]?)\s+(?P<flags>[*>]{0,2})\s*"
    r"(?P<dest>\d{1,3}(?:\.\d{1,3}){3}/\d+)\s+"
    r"(?:\[(?P<distance>\d+)/(?P<metric>\d+)\]\s+)?"
    r"(?:via\s+(?P<next_hop>\S+?),\s*(?P<iface1>\S+)"
    r"|is directly connected,\s*(?P<iface2>\S+))\s*$", re.M)

#: The single-letter route codes FortiOS prints, expanded so `protocol` reads the way the
#: other vendors' do rather than as a bare letter.
_FOS_CODE = {"K": "kernel", "C": "connected", "S": "static", "R": "rip", "B": "bgp",
             "O": "ospf", "IA": "ospf-inter-area", "E1": "ospf-external-1",
             "E2": "ospf-external-2", "N1": "ospf-nssa-1", "N2": "ospf-nssa-2",
             "i": "isis", "L1": "isis-l1", "L2": "isis-l2", "ia": "isis-inter-area"}


def _read_fos_routes(text: str) -> dict | None:
    """`get router info routing-table database` — FortiOS.

    ntc-templates ships a template for `routing-table all` but none for `database`, and
    aliasing the lookup was NOT enough: the database form prints an extra legend line,

        > - selected route, * - FIB route, p - stale info

    which raises TextFSMError inside the `all` template's state machine. So the capability
    returned `unparseable` and `default-route-missing` could not be assessed on FortiOS.

    `database` stays the dispatched command rather than being downgraded to `all`, because
    the RIB-versus-FIB distinction is the whole point: a lab firewall carries TWO default
    routes and only one is marked `*>`. That is precisely what `route-not-programmed`
    tests, and `all` cannot express it — a device with a default route present but not
    installed would read as perfectly healthy.
    """
    # GATED ON THE DATABASE LEGEND, not on "Codes:" — because `*` MEANS DIFFERENT THINGS
    # in the two commands, and the device says which in its own legend:
    #
    #   routing-table all       "* - candidate default"    S*      0.0.0.0/0 [5/0] via …
    #   routing-table database  "* - FIB route"            S    *> 0.0.0.0/0 [5/0] via …
    #
    # Reading `all`'s candidate-default marker as "in the FIB" inverted the meaning of
    # every row in it: `all` lists the FIB, so everything there IS installed, and this
    # reader marked all but the default route not-installed. `all` keeps its template.
    if "FIB route" not in text:
        return None
    out: list[dict] = []
    for m in _FOS_ROUTE.finditer(text):
        d = m.groupdict()
        rec: dict = {
            "destination": d["dest"],
            "protocol": _FOS_CODE.get(d["code"], d["code"].lower()),
            "interface": d["iface1"] or d["iface2"],
            # `*` is "in the FIB" per the device's own legend. A route listed without it
            # is known and not forwarding, which is a finding, not a detail.
            "programmed": "true" if "*" in (d["flags"] or "") else "false",
            "_line": m.group(0).strip(),
        }
        if d["next_hop"]:
            rec["next_hop"] = d["next_hop"]
        if d["metric"]:
            rec["metric"] = d["metric"]
        if d["distance"]:
            rec["distance"] = d["distance"]
        out.append(rec)
    if not out:
        return None
    _derive_install_state(out)
    return {"status": OK, "records": out, "source": "fos_routes",
            "evidence": out[0]["_line"][:200]}


#: Arista uptime spellings seen on the lab: `40d00h`, `19:42:22`, `00:00:30`.
_AGE = (
    (re.compile(r"^(\d+)w(\d+)d$"),            lambda m: int(m[1])*168 + int(m[2])*24),
    (re.compile(r"^(\d+)d(\d+)h$"),            lambda m: int(m[1])*24 + int(m[2])),
    (re.compile(r"^(\d+):(\d+):(\d+)$"),      lambda m: int(m[1]) + int(m[2])/60 + int(m[3])/3600),
)


def _age_hours(text: str) -> float | None:
    for pat, fn in _AGE:
        m = pat.match(text.strip())
        if m:
            return fn(m)
    return None


def _read_peer_detail(text: str) -> dict | None:
    """`show ip ospf neighbor detail` — the reference SOP's §9.3.8 stability table.

    The brief form gives a STATE. The reference SOP asks for something the brief form
    cannot answer: whether an adjacency is FLAPPING, which is not a state but a rate. The
    detail form carries it:

        Neighbor priority is 1, State is FULL, 7 state changes
        Adjacency was established 40d00h ago
        LSAs retransmitted 13774 times to this neighbor

    KEYED ON (peer, interface), NOT PEER. On a lab router `Neighbor 1.1.1.1` appears twice
    — the same router-id reached over Ethernet1 and Ethernet2 — so keying on the peer
    alone merges two adjacencies and attributes one link's flapping to the other.

    `changes_per_hour` is derived ONLY when the adjacency uptime is knowable, for the same
    reason `flaps_per_hour` is: `13 state changes` is healthy over nineteen hours and a
    fault over two minutes, and a cumulative counter cannot tell them apart. Where the
    uptime cannot be read the field is absent and no rate signal fires.

    ntc-templates has a template for this command that returns ZERO records against real
    Arista output — the silent-empty-parse failure this module exists to prevent — so this
    is regex.
    """
    blocks = re.split(r"^Neighbor\s+", text, flags=re.M)[1:]
    out: list[dict] = []
    for b in blocks:
        head = re.match(r"(\S+?),.*?interface address (\S+)", b, re.S)
        st = re.search(r"State is (\S+?),\s*(\d+) state changes", b)
        if not (head and st):
            continue
        rec: dict = {
            "peer": head.group(1).rstrip(","),
            # The neighbour's INTERFACE address, not its router-id. `ping-peer` needs a
            # reachable address and a router-id frequently is not one — in this lab the
            # loopbacks carrying those ids are unassigned, so pinging `1.1.1.1` would fail
            # on a perfectly healthy adjacency.
            "peer_address": head.group(2),
            "state": _norm_state(st.group(1)),
            "state_changes": st.group(2),
            "_line": f"Neighbor {head.group(1).rstrip(',')} … State is {st.group(1)}, "
                     f"{st.group(2)} state changes",
        }
        # Arista: "In area 0.0.0.0 interface Ethernet1"
        # Cisco:  "In the area 0 via interface Ethernet0/0"
        # Both spellings accepted so the reader is ready if Cisco is switched to the detail
        # form; only Arista dispatches it today, and only Arista is validated.
        if (m := re.search(r"In (?:the )?area (\S+) (?:via )?interface (\S+)", b)):
            rec["area"], rec["interface"] = m.group(1), m.group(2)
        if (m := re.search(r"Neighbor priority is (\d+)", b)):
            rec["priority"] = m.group(1)
        if (m := re.search(r"LSAs retransmitted (\d+) times", b)):
            rec["retransmits"] = m.group(1)
        # `Adjacency was established`, NOT `Current state was established`. The device
        # emits both and they are EQUAL on a stable link — which is why picking the wrong
        # one looks correct on healthy hardware and only lies on the fault it exists to
        # find. `state changes` counts the adjacency's whole life, so the denominator has
        # to be the adjacency's whole life. Divide it by time-since-the-LAST-transition
        # and a 40-day link with 7 lifetime changes that blipped once 30 seconds ago reads
        # as 840 changes/hour instead of 0.007 — the interface `flaps_per_hour` bug with a
        # different numerator.
        if (m := re.search(r"Adjacency was established (\S+) ago", b)):
            rec["uptime"] = m.group(1)
            hours = _age_hours(m.group(1))
            if hours and hours > 0:
                rec["changes_per_hour"] = f"{int(st.group(2)) / hours:.3f}"
    # `peers_total`/`peers_full` answer the reference SOP's scope question — "all
    # adjacencies down on one device" routes to a DEVICE fault, one adjacency down routes
    # to the link. Chasing MTU on one link while the process is dead is the same error
    # class as diagnosing ping-failure on an admin-shut port.
        out.append(rec)
    if not out:
        return None
    total = len(out)
    full = sum(1 for r in out if r.get("state") == "full")
    for r in out:
        r["peers_total"], r["peers_full"] = str(total), str(full)
    return {"status": OK, "records": out, "source": "peer_detail",
            "evidence": out[0]["_line"][:200]}


def _read_ospf_interface(text: str) -> dict | None:
    """`show ip ospf interface <if>` — every field §5 asks to compare between both ends.

    Area, network type, cost, hello/dead timers, authentication and the address OSPF is
    actually running on all come from this ONE command, which we were already issuing
    and reading nothing out of.
    """
    first = next((l for l in text.splitlines() if l.strip()), "")
    m = re.match(r"^(\S+) is (\S+)", first)
    if not m:
        return None
    rec: dict = {"port": m.group(1), "_line": first.strip()}

    for key, pat in (
        ("area",           r"Area\s+(\S+?)(?:,|\s*$)"),
        ("address",        r"Interface Address\s+((?:\d{1,3}\.){3}\d{1,3})"),
        ("prefix_len",     r"Interface Address\s+(?:\d{1,3}\.){3}\d{1,3}/(\d+)"),
        ("network_type",   r"Network Type\s+(\S+?)(?:,|\s*$)"),
        ("cost",           r"Cost:\s*(\d+)"),
        ("state",          r"State\s+(\S+?)(?:,|\s*$)"),
        ("priority",       r"Priority\s+(\d+)"),
        ("hello",          r"Hello\s+(\d+)"),
        ("dead",           r"Dead\s+(\d+)"),
        ("retransmit",     r"Retransmit\s+(\d+)"),
        ("neighbor_count", r"Neighbor Count is\s+(\d+)"),
        ("mtu",            r"MTU\s+(\d+)"),
    ):
        mm = re.search(pat, text, re.I | re.M)
        if mm:
            rec[key] = mm.group(1).strip()

    # Authentication is stated in prose, not as a value. "No authentication" is a real
    # finding for §5 (and our own ar02 config sets `authentication mode password` at the
    # process level while the interface reports none — a config-vs-running mismatch).
    if re.search(r"\bNo authentication\b", text, re.I):
        rec["auth"] = "none"
    else:
        am = re.search(r"authentication\s+(?:type\s+)?(\S+)", text, re.I)
        if am:
            rec["auth"] = am.group(1).strip().lower()

    rec["passive"] = "yes" if re.search(r"\bpassive\b", text, re.I) else "no"
    if rec.get("network_type"):
        rec["network_type"] = rec["network_type"].lower()
    if rec.get("state"):
        rec["state"] = rec["state"].upper()
    return {"status": OK, "records": [rec], "source": "ospf_interface",
            "evidence": first.strip()[:200]}


#: Vendor spellings that contain a SPACE inside a column value. TextFSM splits on
#: whitespace, so `EXCH START/BDR` shifts every following column and the row is dropped
#: silently — 4 OSPF neighbours in, 3 records out, and the one dropped was the only
#: faulty one. Normalised in the raw text BEFORE parsing, so the row survives.
_SPACED_VALUES = (
    (re.compile(r"\bEXCH\s+START\b", re.I), "EXSTART"),
    (re.compile(r"\b2\s+WAYS?\b", re.I), "2WAY"),
)


def _despace_values(text: str) -> str:
    for pat, rep in _SPACED_VALUES:
        text = pat.sub(rep, text)
    return text


def _data_row_count(text: str, shape: str) -> int:
    """Rough count of lines that LOOK like table rows, for corroborating a parse.

    A template that returns fewer records than there are data lines has skipped
    something, and skipping the faulty row while keeping the healthy ones is the worst
    possible failure — it reads as health.
    """
    words = _HEADERS.get(shape) or ()
    n = 0
    for line in text.splitlines():
        t = line.strip()
        if not t or t.startswith("-"):
            continue
        low = t.lower()
        if words and sum(1 for w in words if w in low) >= 2:
            continue                      # the header itself
        if re.match(r"^[\w./:*-]+\s+\S", t):
            n += 1
    return n


def extract(vendor: str, command: str, output: str, shape: str,
            log_window_minutes: float | None = _LOG_WINDOW_MINUTES) -> dict:
    """Raw output -> {status, records, evidence, source}. Deterministic only; never
    raises. Returns UNPARSEABLE where only the model can read it — see extract_layered.

    `log_window_minutes` bounds how old a log line may be and still count as evidence.
    It is relative to NOW, so pass None whenever "now" is not the right reference:

      * replaying a stored audit run — its lines are necessarily old, and re-filtering
        them would change the verdict on replay, breaking the property that a replay
        shows what was watched
      * a test asserting against a real capture, which ages
    """
    text = _despace_values(output or "")
    stripped = text.strip()

    if not stripped:
        return {"status": OK_EMPTY, "records": [], "evidence": "", "source": "empty"}

    if shape == "ping_result":
        return _read_ping(text)
    if shape == "policy_table":
        cfg = _read_fortios_config(text)
        if cfg:
            return cfg
        # a real `show` that produced no `edit` block is an EMPTY table, not unreadable
        first = next((l.strip() for l in text.splitlines() if l.strip()), "")
        return {"status": OK_NO_ROWS, "records": [], "source": "fortios_config",
                "evidence": first[:200]}
    if shape == "counter_kv":
        c = _read_counters(text)
        if c:
            return c
    if shape == "resource_kv":
        r = _read_resources(text)
        if r:
            return r
    if shape == "interface_detail":
        d = _read_interface_detail(text)
        if d:
            return d
        # Junos shares no wording with IOS/EOS, so it is a separate reader rather than
        # more alternations bolted onto the first.
        d = _read_junos_interface(text)
        if d:
            return d
    if shape == "route_table":
        # Both gated on their own vendor's table header, so a Cisco or Arista route table
        # falls straight through to the template path below.
        r = _read_junos_routes(text) or _read_fos_routes(text)
        if r:
            return r
    if shape == "peer_table":
        pd = _read_peer_detail(text)
        if pd:
            return pd
    if shape == "ospf_interface":
        o = _read_ospf_interface(text)
        if o:
            return o
    if shape == "status_kv":
        clock = _read_clock(text)
        if clock:
            return clock

    # A device that says a feature is OFF must never be read as "nothing found" —
    # but the statement has to BE the answer, not an aside. `show ip ospf interface`
    # ends with "Traffic engineering is disabled" on a healthy interface, and scanning
    # the whole block reported a live adjacency (State DR, Neighbor Count 1) as
    # ospf-interface-down. A device declining to answer says so up front, so only the
    # opening lines count.
    head = [l for l in text.splitlines() if l.strip()][:_STATUS_TEXT_LINES]
    for status, pat in _STATUS_TEXT:
        for line in head:
            m = re.search(pat, line, re.I)
            if m:
                return {"status": status, "records": [], "evidence": line.strip()[:200],
                        "source": "status_text"}

    if shape == "log_lines":
        recs = parse_logs(text)
        # A stale line is not evidence for a current fault. Dropped here so every log
        # signal on every vendor operates on the same window, rather than each contract
        # having to remember to check.
        if log_window_minutes is not None:
            fresh = [r for r in recs
                     if not r.get("age_minutes")
                     or float(r["age_minutes"]) <= log_window_minutes]
            dropped = len(recs) - len(fresh)
            if dropped and not fresh:
                return {"status": OK_NO_ROWS, "records": [], "source": "log_all_stale",
                        "evidence": f"{dropped} log line(s) read, all older than "
                                    f"{log_window_minutes:g} minutes"}
            recs = fresh
        return {"status": OK if recs else OK_EMPTY, "records": recs,
                "evidence": (recs[0].get("_line") or recs[0].get("message", ""))
                            if recs else "",
                "source": "regex"}

    # 1a — Arista native JSON
    if stripped.startswith("{"):
        try:
            doc = json.loads(stripped)
            if isinstance(doc, dict) and doc.get("errors"):
                return {"status": UNPARSEABLE, "records": [],
                        "evidence": str(doc["errors"][0])[:200], "source": "json_errors"}
            recs = _canonical(_flatten_json(doc), shape, text)
            return {"status": OK if recs else OK_EMPTY, "records": recs,
                    "evidence": (recs[0].get("_line") if recs else "") or stripped.splitlines()[0][:200],
                    "source": "json"}
        except json.JSONDecodeError:
            pass

    # 1b — TextFSM
    try:
        from ntc_templates.parse import parse_output
        raw = parse_output(platform=_PLATFORM.get(vendor, vendor),
                           command=_TEMPLATE_ALIAS.get((vendor, command), command), data=text)
        recs = _canonical(raw, shape, text)
        if recs:
            return {"status": OK, "records": recs,
                    "evidence": recs[0].get("_line") or stripped.splitlines()[0][:200],
                    "source": "textfsm"}
        # A table that printed its header and no rows is a REAL observation: the
        # feature is running and has nothing to report. Losing that cost us the
        # clearest evidence in an induced fault — OSPF's neighbour table emptied
        # and we produced no signal at all.
        zero = _states_zero(text)
        if zero:
            return {"status": OK_NO_ROWS, "records": [],
                    "evidence": zero[:200], "source": "explicit_zero"}
        if _header_only(text, shape):
            return {"status": OK_NO_ROWS, "records": [],
                    "evidence": _header_line(text, shape), "source": "header_only"}
        # Otherwise a template parsing to nothing is not proof of absence — the
        # output format may simply have moved. Hand it to layer 2.
        return {"status": UNPARSEABLE, "records": [],
                "evidence": stripped.splitlines()[0][:200], "source": "textfsm_empty"}
    except Exception:
        if _header_only(text, shape):
            return {"status": OK_NO_ROWS, "records": [],
                    "evidence": _header_line(text, shape), "source": "header_only"}
        return {"status": UNPARSEABLE, "records": [],
                "evidence": stripped.splitlines()[0][:200], "source": "no_template"}


def _flatten_json(doc: Any) -> list[dict]:
    """The biggest collection of uniform dicts in an EOS JSON reply.

    BOTH SHAPES COUNT, and missing the second one produced a confident wrong answer rather
    than a failure. EOS keys most collections BY THEIR IDENTIFIER — `routes` is a dict
    keyed by prefix, `interfaces` by name, `vrfs` by vrf — while nested detail like `vias`
    is a plain list. Looking only for lists meant `show ip route | json` returned the two
    NEXT-HOPS instead of the eight routes, so `no-default-route` fired on a device whose
    table plainly held `0.0.0.0/0`.

    A keyed dict carries its identity in the KEY, which is lost by taking the values alone,
    so the key is injected as `_key`; each shape's field map lists `_key` among the
    candidates for its identity field.
    """
    best: list[dict] = []

    def walk(node):
        nonlocal best
        if isinstance(node, list):
            rows = [x for x in node if isinstance(x, dict)]
            if len(rows) > len(best):
                best = rows
            for x in node:
                walk(x)
        elif isinstance(node, dict):
            vals = list(node.values())
            # A dict whose values are ALL dicts is a keyed collection, not a record.
            # Require 2+ so a single-entry wrapper is not mistaken for one.
            if len(vals) > 1 and all(isinstance(v, dict) for v in vals):
                rows = [{"_key": k, **v} for k, v in node.items()]
                if len(rows) > len(best):
                    best = rows
            for v in vals:
                walk(v)

    walk(doc)
    if best:
        return best
    return [doc] if isinstance(doc, dict) else []
