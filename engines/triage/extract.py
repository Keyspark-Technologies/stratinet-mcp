from __future__ import annotations

import json
import logging
import re
from typing import Any

logger = logging.getLogger(__name__)

OK, OK_EMPTY, OK_NO_ROWS, NOT_CONFIGURED, UNLICENSED, ERROR, UNPARSEABLE = (
    "ok", "ok_empty", "ok_no_rows", "not_configured", "unlicensed", "error", "unparseable")
NO_LOSS, PARTIAL_LOSS, TOTAL_LOSS, CLOCK_LOCAL = (
    "no_loss", "partial_loss", "total_loss", "clock_local")

_PLATFORM = {"fortios": "fortinet", "fortinet_fortios": "fortinet",
             "fortinet_fortiswitch": "fortinet", "paloalto_panos": "paloalto_panos"}

_STATUS_TEXT_LINES = 3

_STATUS_TEXT = [
    (UNLICENSED,      r"licen[sc]e key missing|requires '.*' licen[sc]e|not licensed|unlicensed"),
    (NOT_CONFIGURED,  r"%\s*bgp inactive|bgp is not running|ospf instance is not running"
                      r"|not enabled|is disabled|not running|no such process|process_status:\s*not up"
                      r"|authentication control:\s*disabled"),
    (ERROR,           r"%\s*invalid|command parse error|unknown action|command fail"),
]

SHAPES: dict[str, tuple[str, ...]] = {
    "peer_table":      ("peer", "peer_address", "state", "interface", "uptime", "area",
                        "priority", "state_changes", "changes_per_hour", "retransmits",
                        "peers_total", "peers_full"),
    "interface_table": ("port", "admin_state", "oper_state", "description", "speed", "duplex"),
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
    "interface_detail": ("port", "admin_state", "oper_state", "description", "mtu",
                         "duplex", "speed", "autoneg", "address", "prefix_len",
                         "flaps", "flaps_per_hour", "uptime", "uptime_hours",
                         "counters_cleared", "crc", "input_errors", "output_errors",
                         "input_discards", "output_discards", "runts", "giants",
                         "late_collisions", "collisions"),
    "ospf_interface":   ("port", "area", "network_type", "cost", "state", "priority",
                         "hello", "dead", "retransmit", "auth", "address", "prefix_len",
                         "neighbor_count", "passive", "mtu"),
}

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
    "resource_kv": {
        "memory_total": ("memory_total", "mem_total", "total"),
        "memory_used":  ("memory_used", "mem_used", "used"),
        "memory_free":  ("memory_free", "mem_free", "free"),
    },
    "route_table": {
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
        "acl_name":    ("acl_name", "name", "acl", "access_list"),
        "seq":         ("seq", "sn", "sequence", "line_num"),
        "action":      ("action", "permit_deny", "rule_action"),
        "protocol":    ("protocol", "proto"),
        "source":      ("source", "src", "source_address"),
        "destination": ("destination", "dst", "destination_address"),
        "matches":     ("matches", "match", "packets", "hit_count", "hits", "modifier"),
    },
    "vlan_table": {
        "vlan_id":   ("vlan_id", "vlan", "id"),
        "vlan_name": ("vlan_name", "name"),
        "status":    ("status", "state"),
        "ports":     ("ports", "interfaces", "interface"),
    },
    "mac_table": {
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

_STATE_WORDS = ("full", "established", "idle", "active", "connect", "opensent",
                "openconfirm", "init", "2way", "exstart", "exchange", "loading", "down")


def _norm_state(v: str) -> str:
    s = str(v or "").strip().lower()
    flat = s.replace(" ", "").replace("-", "")
    if flat.startswith("2way"):
        return "2way"
    if flat.startswith("exchstart") or flat.startswith("exstart"):
        return "exstart"
    if flat.startswith("exchange"):
        return "exchange"
    for w in _STATE_WORDS:
        if s.startswith(w) or f"/{w}" in s or f" {w}" in s:
            return w
    return s


_STATUS_STATES = (
    (r"^(connected|up|active|ok)\b",                    ("up",   "up")),
    (r"^(admin.?down|administratively down|disabled|shutdown)\b", ("down", "down")),
    (r"^(errdisabled|err.?disable)\b",                  ("up",   "down")),
    (r"^(notconnect|not ?connected|down|inactive|no ?carrier)\b", ("up", "down")),
    (r"^(monitoring|dormant|testing)\b",                ("up",   "unknown")),
)


def _derive_states(v: str) -> tuple[str, str]:
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
    rest = [l for l in lines[hdr + 1:] if set(l.strip()) - {"-", "=", " "}]
    return not rest


def _all_dashes(rec: dict) -> bool:
    vals = [str(v).strip() for v in rec.values() if str(v).strip()]
    return bool(vals) and all(set(v) <= {"-", "="} for v in vals)


_IDENT = {"interface_table": ("port",), "peer_table": ("peer", "interface"),
          "route_table": ("destination",), "neighbor_table": ("neighbor_name", "local_interface"),
          "status_kv": ("hostname", "model")}


def _source_line(text: str, rec: dict, shape: str) -> str:
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
    def _yes(v) -> bool:
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


_SYSLOG = re.compile(
    r"^(?P<timestamp>\w{3}\s+\d+\s+[\d:]+)\s+(?P<host>\S+)\s+(?P<proc>\S+?):"
    r"[^%]*"
    r"%(?P<facility>[A-Z0-9_]+)-(?P<severity>\d)-(?P<mnemonic>[A-Z0-9_]+):\s*(?P<message>.*)$")

_SYSLOG_PLAIN = re.compile(
    r"^(?P<timestamp>\w{3}\s+\d+\s+[\d:]+)\s+(?P<host>\S+)\s+(?P<proc>\S+?):\s*"
    r"(?P<message>\S.*)$")

_SYSLOG_DEVICE = re.compile(
    r"^(?:\d+:\s*)?(?P<unsynced>\*)?(?P<timestamp>\w{3}\s+\d+\s+\d+:\d+:\d+)(?:\.\d+)?:\s*"
    r"%(?P<facility>[A-Z0-9_]+)-(?P<severity>\d)-(?P<mnemonic>[A-Z0-9_]+):\s*"
    r"(?P<message>.*)$")
_KV = re.compile(r'(\w+)=("([^"]*)"|\S+)')


_TEMPLATE_ALIAS: dict[tuple[str, str], str] = {
    ("fortinet_fortios", "get router info routing-table database"):
        "get router info routing-table all",
}


_ACL_PACKETS = re.compile(r"match\s+[\d,]+\s+bytes\s+in\s+([\d,]+)\s+packets", re.I)


def _derive_memory_pct(c: dict) -> None:
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
    raw = str(c.get("matches") or "")
    m = _ACL_PACKETS.search(raw)
    pkts = int(m.group(1).replace(",", "")) if m else 0
    c["matches"] = str(pkts)
    c["dropping"] = "yes" if (str(c.get("action", "")).lower().startswith("deny")
                              and pkts > 0) else "no"


_SELF_READ_CMD = re.compile(
    r"cmd=(show|get|display|diagnose|execute log"
    r"|terminal|enable|exit|end|logout|quit|no paging|set cli)\b", re.I)


def _event_source(facility: str, message: str) -> str:
    if (facility or "").upper() != "ACCOUNTING":
        return "device"
    if _SELF_READ_CMD.search(message or ""):
        return "self"
    return "self" if "cmd=" not in (message or "") else "device"


_LOG_WINDOW_MINUTES = 60

_SYSLOG_TS = re.compile(r"^(\w{3})\s+(\d+)\s+(\d{1,2}):(\d{2}):(\d{2})$")
_MONTHS = {m: i + 1 for i, m in enumerate(
    ("jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"))}


def _syslog_dt(ts: str):
    from datetime import datetime, timedelta
    raw = (ts or "").strip()
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
    when = _syslog_dt(ts)
    if when is None:
        return None
    if reference is None:
        from datetime import datetime
        reference = datetime.now()
    now = reference
    return (now - when).total_seconds() / 60.0


def parse_logs(text: str) -> list[dict]:
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
        m = _SYSLOG_DEVICE.match(line)
        if m:
            d = m.groupdict()
            unsynced = d.pop("unsynced", None)
            d["severity_class"] = _SEVERITY_CLASS.get(int(d["severity"]), "info")
            d["host"] = ""
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
                "facility": d["proc"], "mnemonic": "", "severity": "",
                "severity_class": "unknown", "event_source": "device",
                "message": d["message"].strip(),
                "_line": line,
            })
            continue
        if "=" in line and ("logid=" in line or "date=" in line):
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
    stamps = [dt for dt in (_syslog_dt(r.get("timestamp")) for r in out) if dt]
    ref = max(stamps) if stamps else None
    for r in out:
        age = _log_age_minutes(r.get("timestamp"), reference=ref)
        r["age_minutes"] = f"{age:.1f}" if age is not None else ""
    return out


_PING = re.compile(r"(\d+) packets transmitted,\s*(\d+)(?: packets)? received,\s*(\d+)% packet loss", re.I)
_RTT = re.compile(r"(?:rtt|round-trip) min/avg/max(?:/mdev)?\s*=\s*[\d.]+/([\d.]+)/", re.I)
_PING_IOS = re.compile(
    r"Success rate is (\d+) percent\s*\((\d+)/(\d+)\)", re.I)


def _read_ping(text: str) -> dict:
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
        fail = re.search(r"network is unreachable|no route to host|destination host "
                         r"unreachable|name or service not known|invalid (?:host|address)"
                         r"|connect: ", text, re.I)
        if fail:
            line = next((l.strip() for l in text.splitlines()
                         if fail.group(0).lower() in l.lower()), fail.group(0))
            return {"status": TOTAL_LOSS, "records": [],
                    "evidence": line[:200], "source": "ping_unreachable"}
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
    m = re.search(r"Clock source:\s*(.+)", text, re.I)
    if not m:
        return None
    src = m.group(1).strip()
    if re.match(r"local", src, re.I):
        return {"status": CLOCK_LOCAL, "records": [],
                "evidence": m.group(0).strip(), "source": "clock_source"}
    return None


async def extract_layered(vendor: str, command: str, output: str, shape: str) -> dict:
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


_MEM_PCT  = re.compile(r"mem(?:ory)?\b[^\n]*?([\d.]+)k?\s*used\s*\(([\d.]+)%\)", re.I)
_MEM_FREE = re.compile(r"([\d.]+)k?\s*free\s*\(([\d.]+)%\)", re.I)
_CPU_IDLE = re.compile(r"([\d.]+)%\s*idle", re.I)
_UPTIME   = re.compile(r"^\s*uptime:\s*(.+)$", re.I | re.M)
_MEM_TOTAL_KB = re.compile(r"total memory:\s*([\d,]+)\s*kb", re.I)
_MEM_FREE_KB  = re.compile(r"free memory:\s*([\d,]+)\s*kb", re.I)

_JUNOS_MEM_UTIL = re.compile(r"^\s*Memory utilization\s+([\d.]+)\s+percent", re.I | re.M)
_JUNOS_MEM_INACTIVE = re.compile(r"inactive memory:\s*([\d,]+)\s*kb", re.I)
_JUNOS_MEM_CACHE    = re.compile(r"cache memory:\s*([\d,]+)\s*kb", re.I)
_JUNOS_CPU_HEADER = re.compile(r"^[ \t]*(\d+)\s*(sec|min)\s+CPU utilization:", re.I | re.M)
_JUNOS_CPU_IDLE = re.compile(r"^\s*Idle\s+([\d.]+)\s+percent", re.I | re.M)


def _junos_cpu_idle(text: str) -> tuple[str, str] | None:
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
        try:
            rec["cpu_used_pct"] = f"{100.0 - float(m3.group(1)):.1f}"
        except ValueError:
            pass
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
    line = next((l.strip() for l in text.splitlines()
                 if re.search(r"mem(ory)?\b.*%|%\s*idle", l, re.I)), "")
    if not line:
        mem_lines = [l.strip() for l in text.splitlines()
                     if re.search(r"^\s*(?:total|free) memory:", l, re.I)]
        line = " / ".join(mem_lines)
    rec["_line"] = line
    return {"status": OK, "records": [rec], "source": "resources",
            "evidence": line[:200]}


_EXPLICIT_ZERO = re.compile(
    r"^\s*(?:total\b[^:\n]*:\s*0\b"
    r"|0\s+(?:logs?|entries|entry|routes?|sessions?|neighbou?rs?)\s+(?:found|displayed)\b"
    r"|number of [^:\n]*(?:is|:)\s*0\b)", re.I | re.M)


def _states_zero(text: str) -> str | None:
    m = _EXPLICIT_ZERO.search(text or "")
    return m.group(0).strip() if m else None


def _num(m, default=None):
    return m.group(1).replace(",", "") if m else default


_UPTIME_UNITS = (("day", 24.0), ("hour", 1.0), ("minute", 1 / 60), ("second", 1 / 3600))


def _uptime_hours(text: str) -> float | None:
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
    first = next((l for l in text.splitlines() if l.strip()), "")
    m = re.match(r"^(\S+) is (\S+), line protocol is (\S+)", first)
    if not m:
        return None
    port, admin_raw, oper_raw = m.group(1), m.group(2), m.group(3)
    rec: dict = {
        "port": port,
        "admin_state": "down" if re.search(r"admin", admin_raw, re.I) else "up",
        "oper_state": "up" if oper_raw.lower().startswith("up") else "down",
        "_line": first.strip(),
    }
    if re.search(r"is administratively down", text[:200], re.I):
        rec["admin_state"] = "down"

    for key, pat in (
        ("description",     r"^\s*Description:\s*(.+)$"),
        ("mtu",             r"MTU\s+(\d+)\s*bytes"),
        ("duplex",          r"^\s*(Full|Half|Auto)-duplex"),
        ("late_collisions", r"(\d+)\s+late collision"),
        ("collisions",      r"(\d+)\s+collisions"),
        ("speed",           r"-duplex,\s*([^,]+?),"),
        ("autoneg",         r"auto negotiation:\s*(\S+?)(?:,|$)"),
        ("address",         r"Internet address is ((?:\d{1,3}\.){3}\d{1,3})"),
        ("prefix_len",      r"Internet address is (?:\d{1,3}\.){3}\d{1,3}/(\d+)"),
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
            rec[f"_line_{key}"] = mm.group(0).strip()

    if rec.get("duplex"):
        rec["duplex"] = rec["duplex"].lower()

    cl = re.search(r'Last clearing of .*? counters\s+(\S+)', text, re.I)
    rec["counters_cleared"] = (cl.group(1).strip().lower() if cl else "unknown")
    hrs = _uptime_hours(rec.get("uptime") or "")
    if hrs:
        rec["uptime_hours"] = f"{hrs:.2f}"
    if rec.get("flaps") and hrs and hrs > 0 and rec["counters_cleared"] == "never":
        rec["flaps_per_hour"] = f"{int(rec['flaps']) / hrs:.2f}"
        rec["_line_flaps_per_hour"] = (f"{rec.get('_line_flaps', '')}"
                                       f" (up {rec.get('uptime', '?')}"
                                       f" -> {rec['flaps_per_hour']} flaps/hour)")

    return {"status": OK, "records": [rec], "source": "interface_detail",
            "evidence": first.strip()[:200]}


_JUNOS_ERR_SECTION = re.compile(
    r"^\s*(Input|Output) errors:(.*?)(?=^\s*\w[\w ]*:\s*$|^\s{0,2}\w|\Z)", re.I | re.M | re.S)


def _read_junos_interface(text: str) -> dict | None:
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
        rec["mtu"] = str(int(phys.group(1)) - 14)
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

    mm = re.search(r"^\s*CRC/Align errors\s+(\d+)", text, re.M) or \
        re.search(r"\bFCS errors:\s*(\d+)", text, re.I)
    if mm:
        rec["crc"] = mm.group(1)
        rec["_line_crc"] = mm.group(0).strip()

    rec["counters_cleared"] = (
        "never" if re.search(r"Statistics last cleared:\s*Never", text, re.I) else "unknown")
    return {"status": OK, "records": [rec], "source": "junos_interface",
            "evidence": rec["_line"][:200]}


_JUNOS_ROUTE = re.compile(r"^(\S+/\d+)\s+([*+-]?)\[(\w[\w-]*)/(\d+)\]\s*(.*)$", re.M)


def _read_junos_routes(text: str) -> dict | None:
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
            "programmed": "true" if m.group(2) in ("*", "+") else "false",
            "_line": line.strip(),
        }
        if family:
            rec["family"] = family
        if (mt := re.search(r"\bmetric\s+(\d+)", m.group(5), re.I)):
            rec["metric"] = mt.group(1)
        for nxt in lines[i + 1:]:
            if not nxt.strip() or _JUNOS_ROUTE.match(nxt) or re.match(r"^\S+\.\d+:", nxt):
                break
            if (nh := re.search(r"\bto\s+(\S+)\s+via\s+(\S+)", nxt)):
                rec["next_hop"], rec["interface"] = nh.group(1), nh.group(2).rstrip(",")
                break
            if (via := re.search(r"\bvia\s+(\S+)", nxt)):
                rec["interface"] = via.group(1).rstrip(",")
                break
        out.append(rec)
    if not out:
        return None
    _derive_install_state(out)
    return {"status": OK, "records": out, "source": "junos_routes",
            "evidence": out[0]["_line"][:200]}


_FOS_ROUTE = re.compile(
    r"^(?P<code>[A-Za-z][A-Za-z0-9]?)\s+(?P<flags>[*>]{0,2})\s*"
    r"(?P<dest>\d{1,3}(?:\.\d{1,3}){3}/\d+)\s+"
    r"(?:\[(?P<distance>\d+)/(?P<metric>\d+)\]\s+)?"
    r"(?:via\s+(?P<next_hop>\S+?),\s*(?P<iface1>\S+)"
    r"|is directly connected,\s*(?P<iface2>\S+))\s*$", re.M)

_FOS_CODE = {"K": "kernel", "C": "connected", "S": "static", "R": "rip", "B": "bgp",
             "O": "ospf", "IA": "ospf-inter-area", "E1": "ospf-external-1",
             "E2": "ospf-external-2", "N1": "ospf-nssa-1", "N2": "ospf-nssa-2",
             "i": "isis", "L1": "isis-l1", "L2": "isis-l2", "ia": "isis-inter-area"}


def _read_fos_routes(text: str) -> dict | None:
    if "FIB route" not in text:
        return None
    out: list[dict] = []
    for m in _FOS_ROUTE.finditer(text):
        d = m.groupdict()
        rec: dict = {
            "destination": d["dest"],
            "protocol": _FOS_CODE.get(d["code"], d["code"].lower()),
            "interface": d["iface1"] or d["iface2"],
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
    blocks = re.split(r"^Neighbor\s+", text, flags=re.M)[1:]
    out: list[dict] = []
    for b in blocks:
        head = re.match(r"(\S+?),.*?interface address (\S+)", b, re.S)
        st = re.search(r"State is (\S+?),\s*(\d+) state changes", b)
        if not (head and st):
            continue
        rec: dict = {
            "peer": head.group(1).rstrip(","),
            "peer_address": head.group(2),
            "state": _norm_state(st.group(1)),
            "state_changes": st.group(2),
            "_line": f"Neighbor {head.group(1).rstrip(',')} … State is {st.group(1)}, "
                     f"{st.group(2)} state changes",
        }
        if (m := re.search(r"In (?:the )?area (\S+) (?:via )?interface (\S+)", b)):
            rec["area"], rec["interface"] = m.group(1), m.group(2)
        if (m := re.search(r"Neighbor priority is (\d+)", b)):
            rec["priority"] = m.group(1)
        if (m := re.search(r"LSAs retransmitted (\d+) times", b)):
            rec["retransmits"] = m.group(1)
        if (m := re.search(r"Adjacency was established (\S+) ago", b)):
            rec["uptime"] = m.group(1)
            hours = _age_hours(m.group(1))
            if hours and hours > 0:
                rec["changes_per_hour"] = f"{int(st.group(2)) / hours:.3f}"
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


_SPACED_VALUES = (
    (re.compile(r"\bEXCH\s+START\b", re.I), "EXSTART"),
    (re.compile(r"\b2\s+WAYS?\b", re.I), "2WAY"),
)


def _despace_values(text: str) -> str:
    for pat, rep in _SPACED_VALUES:
        text = pat.sub(rep, text)
    return text


def _data_row_count(text: str, shape: str) -> int:
    words = _HEADERS.get(shape) or ()
    n = 0
    for line in text.splitlines():
        t = line.strip()
        if not t or t.startswith("-"):
            continue
        low = t.lower()
        if words and sum(1 for w in words if w in low) >= 2:
            continue
        if re.match(r"^[\w./:*-]+\s+\S", t):
            n += 1
    return n


def extract(vendor: str, command: str, output: str, shape: str,
            log_window_minutes: float | None = _LOG_WINDOW_MINUTES) -> dict:
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
        d = _read_junos_interface(text)
        if d:
            return d
    if shape == "route_table":
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

    head = [l for l in text.splitlines() if l.strip()][:_STATUS_TEXT_LINES]
    for status, pat in _STATUS_TEXT:
        for line in head:
            m = re.search(pat, line, re.I)
            if m:
                return {"status": status, "records": [], "evidence": line.strip()[:200],
                        "source": "status_text"}

    if shape == "log_lines":
        recs = parse_logs(text)
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

    try:
        from ntc_templates.parse import parse_output
        raw = parse_output(platform=_PLATFORM.get(vendor, vendor),
                           command=_TEMPLATE_ALIAS.get((vendor, command), command), data=text)
        recs = _canonical(raw, shape, text)
        if recs:
            return {"status": OK, "records": recs,
                    "evidence": recs[0].get("_line") or stripped.splitlines()[0][:200],
                    "source": "textfsm"}
        zero = _states_zero(text)
        if zero:
            return {"status": OK_NO_ROWS, "records": [],
                    "evidence": zero[:200], "source": "explicit_zero"}
        if _header_only(text, shape):
            return {"status": OK_NO_ROWS, "records": [],
                    "evidence": _header_line(text, shape), "source": "header_only"}
        return {"status": UNPARSEABLE, "records": [],
                "evidence": stripped.splitlines()[0][:200], "source": "textfsm_empty"}
    except Exception:
        if _header_only(text, shape):
            return {"status": OK_NO_ROWS, "records": [],
                    "evidence": _header_line(text, shape), "source": "header_only"}
        return {"status": UNPARSEABLE, "records": [],
                "evidence": stripped.splitlines()[0][:200], "source": "no_template"}


def _flatten_json(doc: Any) -> list[dict]:
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
