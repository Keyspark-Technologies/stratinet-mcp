"""One name per feature, so a workaround that clears three CVEs looks like one action.

Exposure is grounded per FEATURE, but the feature's name comes from two places: the hand-written
seed rules, and whatever string an LLM chose when it generated a detector. The result was five
labels -- `ssl-vpn`, `sslvpn`, `ssl_vpn`, `SSL-VPN enabled`, `ssl_vpn_web_mode` -- for what an
operator sees as two things. Grouping by that string splits one workaround across five rows and
makes shared leverage invisible: disabling SSL-VPN closes three CVEs, and the UI showed three
unrelated items.

THE CONSTRAINT THAT SHAPES THIS FILE: aliasing is only ever spelling. Two features merge here only
if disabling one necessarily disables the other -- that is what lets a single workaround claim the
whole group. `ssl_vpn_web_mode` is NOT `ssl_vpn`: web mode is one interface of the service, and
Fortinet says explicitly that disabling web mode is not a valid workaround for CVE-2024-21762.
Folding the narrow name into the broad one would let "disable SSL-VPN" appear to clear a CVE it
does not clear, and would let "disable web mode" appear to clear the three that need the whole
service off. Same reasoning keeps the four TerminAttr entries apart: `-cvaddr`, `-grpctunnel_addr`
and `-cveapimode=queued` are distinct flags on one daemon, and only some CVEs ride each one.

So this module is deliberately dumb: an exact-match alias table, no prefix or fuzzy matching (a
prefix rule is exactly what would swallow `ssl_vpn_web_mode` into `ssl_vpn`). An unrecognised
feature keeps its own identity and only gets a tidier label -- an unknown name is never guessed
into an existing group.

Naming only. Nothing here selects a detector or decides a verdict; canonicalising a label can
change how findings are GROUPED and never whether one is exposed.
"""
from __future__ import annotations

import re

# canonical id -> display label. Seed ids reuse grounding._FEATURES labels; the rest name features
# only ever seen from generated rules.
_LABELS: dict = {
    "ssl_vpn": "SSL-VPN enabled",
    "ssl_vpn_web_mode": "SSL-VPN web mode enabled",
    "ssl_vpn_host_check": "SSL-VPN portal host/OS check configured",
    "admin_forticloud_sso": "FortiCloud SSO admin login enabled",
    "wireless_controller": "Wireless controller (CAPWAP) enabled",
    "ssl_inspection_http2": "HTTP/2 permitted on an SSL inspection profile",
    "vip_h2_support": "HTTP/2 enabled on a firewall VIP",
    "dot1x": "802.1X (dot1x) authentication enabled",
    "admin_http": "HTTP/HTTPS admin management access on an interface",
    "admin_telnet": "Telnet admin access on an interface",
    "fgfm": "FGFM (FortiManager) access on an interface",
    "captive_portal": "Captive portal enabled",
    "fabric_allowaccess": "Security Fabric access on an interface",
    "auto_auth_extension_device": "auto-auth-extension-device enabled",
    "fsso_ts_agent": "FSSO Terminal Server agent configured",
    "automation_stitch": "Automation stitch configured",
    "dhcp_server": "DHCP server configured",
    "tunnel_decap": "Tunnel decapsulation (VXLAN VTEP / ip decap-group / GRE tunnel)",
    "snmp": "SNMP agent configured",
    "gnoi_openconfig": "OpenConfig / gNOI (gNMI) server enabled",
    "l3_interface": "Routed (L3) interface configured",
    "terminattr": "TerminAttr (CloudVision telemetry agent) running",
    "terminattr_grpctunnel": "TerminAttr with -grpctunnel_addr",
    "terminattr_cvaddr": "TerminAttr streaming to CloudVision (-cvaddr / -cvopt)",
    "terminattr_cveapi": "TerminAttr with -cveapimode=queued",
    "management_api_http_commands": "eAPI (management api http-commands) enabled",
    "cvx_mcs_service": "CVX MCS service enabled",
    "macsec": "MACsec configured on an interface",
    "software_forwarding_mtu": "Software forwarding without an MTU-exceed drop action",
    "software_forwarding_options": "Software forwarding without an IPv4-options drop action",
    "nexthop_redirect": "Traffic redirected to a next hop by PBR, BGP Flowspec, or an interface traffic policy",
    "snmp_transmit_max_size": "SNMP without a transmit max-size limit",
    "ipsec_anti_replay": "IPsec SA policy without anti-replay detection",
    "radius_without_tls": "RADIUS server configured without TLS (Blast-RADIUS)",
    "dot1x_multi_host": "802.1X in a multi-host mode",
    "port_mirroring": "Port mirroring (monitor session) configured",
    "eapi_user_cert_auth": "eAPI with user certificate authentication",
    "ip_routing": "IP routing enabled",
}

# Spelling variants ONLY. Every key here means the same feature as its value -- disabling one is
# disabling the other. Anything narrower or broader belongs in _LABELS as its own id.
_ALIASES: dict = {
    # the SSL-VPN service as a whole
    "sslvpn": "ssl_vpn",
    "ssl_vpn_enabled": "ssl_vpn",
    "sslvpn_enabled": "ssl_vpn",
    "vpn_ssl": "ssl_vpn",
    "vpn_ssl_settings": "ssl_vpn",
    "ssl_vpn_service": "ssl_vpn",
    # web mode specifically -- kept SEPARATE from ssl_vpn on purpose (see module docstring)
    "sslvpn_web_mode": "ssl_vpn_web_mode",
    "ssl_vpn_webmode": "ssl_vpn_web_mode",
    "sslvpn_webmode": "ssl_vpn_web_mode",
    "ssl_vpn_web_mode_enabled": "ssl_vpn_web_mode",
    # host check
    "sslvpn_host_check": "ssl_vpn_host_check",
    "ssl_vpn_hostcheck": "ssl_vpn_host_check",
    # admin access
    "admin_https": "admin_http",
    "http_admin": "admin_http",
    "https_admin": "admin_http",
    "admin_access_http": "admin_http",
    "telnet_admin": "admin_telnet",
    "admin_telnet_enabled": "admin_telnet",
    # Arista management plane
    "openconfig_gnmi": "gnoi_openconfig",
    "openconfig": "gnoi_openconfig",
    "gnmi": "gnoi_openconfig",
    "gnoi": "gnoi_openconfig",
    "eapi": "management_api_http_commands",
    "management_api_http": "management_api_http_commands",
    # misc spellings
    "fortimanager_fgfm": "fgfm",
    "security_fabric": "fabric_allowaccess",
    "auto_auth_extension": "auto_auth_extension_device",
}

_WORD = re.compile(r"[^a-z0-9]+")


def _key(raw: str) -> str:
    """Fold a free-form feature name to a comparison key: lowercase, non-alphanumerics to `_`.

    Makes `SSL-VPN enabled`, `ssl-vpn`, and `ssl_vpn` the same key without any fuzzy matching --
    the alias table still decides what is genuinely the same feature.
    """
    return _WORD.sub("_", (raw or "").strip().lower()).strip("_")


def _prettify(key: str) -> str:
    """A readable label for a feature we have no entry for. Tidies the name and nothing else --
    an unknown feature must never be guessed into an existing group."""
    if not key:
        return ""
    words = [w for w in key.split("_") if w]
    return " ".join(w if (w.isupper() or len(w) <= 3) else w.capitalize() for w in words)


def canonical_id(raw: str) -> str:
    """Canonical feature id for a raw feature name. Unrecognised names keep their own folded key,
    so they group with themselves and with nothing else."""
    k = _key(raw)
    if not k:
        return ""
    k = _ALIASES.get(k, k)
    # `SSL-VPN enabled` folds to `ssl_vpn_enabled`, which the alias table maps to `ssl_vpn`; a
    # second pass is never needed because aliases point only at canonical ids, never at other
    # aliases. Assert that invariant cheaply rather than looping.
    return k


def canonical_label(raw: str) -> str:
    """Human label for a raw feature name, stable across every spelling of it."""
    cid = canonical_id(raw)
    return _LABELS.get(cid) or _prettify(cid)


def canonicalize(raw: str) -> tuple:
    """(canonical_id, display_label) — what callers normally want."""
    cid = canonical_id(raw)
    return cid, (_LABELS.get(cid) or _prettify(cid))
