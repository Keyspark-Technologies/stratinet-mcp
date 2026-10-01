from __future__ import annotations

import re

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

_ALIASES: dict = {
    "sslvpn": "ssl_vpn",
    "ssl_vpn_enabled": "ssl_vpn",
    "sslvpn_enabled": "ssl_vpn",
    "vpn_ssl": "ssl_vpn",
    "vpn_ssl_settings": "ssl_vpn",
    "ssl_vpn_service": "ssl_vpn",
    "sslvpn_web_mode": "ssl_vpn_web_mode",
    "ssl_vpn_webmode": "ssl_vpn_web_mode",
    "sslvpn_webmode": "ssl_vpn_web_mode",
    "ssl_vpn_web_mode_enabled": "ssl_vpn_web_mode",
    "sslvpn_host_check": "ssl_vpn_host_check",
    "ssl_vpn_hostcheck": "ssl_vpn_host_check",
    "admin_https": "admin_http",
    "http_admin": "admin_http",
    "https_admin": "admin_http",
    "admin_access_http": "admin_http",
    "telnet_admin": "admin_telnet",
    "admin_telnet_enabled": "admin_telnet",
    "openconfig_gnmi": "gnoi_openconfig",
    "openconfig": "gnoi_openconfig",
    "gnmi": "gnoi_openconfig",
    "gnoi": "gnoi_openconfig",
    "eapi": "management_api_http_commands",
    "management_api_http": "management_api_http_commands",
    "fortimanager_fgfm": "fgfm",
    "security_fabric": "fabric_allowaccess",
    "auto_auth_extension": "auto_auth_extension_device",
}

_WORD = re.compile(r"[^a-z0-9]+")


def _key(raw: str) -> str:
    return _WORD.sub("_", (raw or "").strip().lower()).strip("_")


def _prettify(key: str) -> str:
    if not key:
        return ""
    words = [w for w in key.split("_") if w]
    return " ".join(w if (w.isupper() or len(w) <= 3) else w.capitalize() for w in words)


def canonical_id(raw: str) -> str:
    k = _key(raw)
    if not k:
        return ""
    k = _ALIASES.get(k, k)
    return k


def canonical_label(raw: str) -> str:
    cid = canonical_id(raw)
    return _LABELS.get(cid) or _prettify(cid)


def canonicalize(raw: str) -> tuple:
    cid = canonical_id(raw)
    return cid, (_LABELS.get(cid) or _prettify(cid))
