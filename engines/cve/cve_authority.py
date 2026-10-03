from __future__ import annotations

import json
import logging
import os
import re
from functools import lru_cache

logger = logging.getLogger("cve.authority")

_DEFAULT_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))), "data", "cve_authority.json")

_VENDOR_CNA = {
    "fortinet": {"fortinet"},
    "fortios": {"fortinet"},
    "fortigate": {"fortinet"},
    "arista": {"arista"},
    "arista_eos": {"arista"},
    "eos": {"arista"},
}


def _norm(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", (s or "").lower())


@lru_cache(maxsize=1)
def _records(path: str = "") -> dict:
    p = path or _DEFAULT_PATH
    try:
        with open(p, encoding="utf-8") as fh:
            return json.load(fh).get("records") or {}
    except FileNotFoundError:
        logger.info("cve authority cache absent (%s); product attribution unchecked", p)
        return {}
    except Exception as e:
        logger.warning("cve authority cache unreadable (%s): %s", p, e)
        return {}


def record_for(cve_id: str, path: str = "") -> dict | None:
    r = _records(path).get((cve_id or "").upper())
    return r if r and r.get("status") == "published" else None


_SIBLING_PRODUCTS = {
    "fortinet": ("fortiweb", "fortimanager", "fortianalyzer", "fortiproxy", "fortisandbox",
                 "fortiadc", "fortimail", "fortiswitch", "fortivoice", "fortindr", "fortisiem",
                 "fortiisolator", "fortipam", "fortirecorder", "fortiap", "forticlient"),
    "arista_eos": ("cloudvision", "cloudeos", "wifi manager", "ng firewall", "edge threat"),
}


def product_attributed(cve_id: str, platform: str, product_names, path: str = ""):
    rec = record_for(cve_id, path)
    if not rec:
        return None

    assigner = _norm(rec.get("assigner"))
    owners = {_norm(v) for v in _VENDOR_CNA.get((platform or "").strip().lower(), set())}
    if not owners or assigner not in owners:
        return None

    wanted = [_norm(p) for p in (product_names or []) if _norm(p)]
    if not wanted:
        return None

    listed = [_norm(p) for p in (rec.get("products") or [])]
    in_array = any(any(w in got for got in listed) for w in wanted)
    desc = _norm(rec.get("description"))
    in_desc = any(w and w in desc for w in wanted)

    if in_array and not in_desc:
        siblings = [s for s in _SIBLING_PRODUCTS.get((platform or "").strip().lower(), ())
                    if s in desc]
        if siblings:
            logger.info("%s: affected[] names this product but the description enumerates %s and "
                        "not it -- treating the record as not attributing it here",
                        cve_id, ", ".join(siblings[:3]))
            return False

    if in_array:
        return True

    if in_desc:
        return True

    return False


def cvss_for(cve_id: str, path: str = "") -> dict | None:
    rec = record_for(cve_id, path)
    if not rec:
        return None
    metrics = rec.get("metrics") or {}
    for key in ("cvssV4_0", "cvssV3_1", "cvssV3_0"):
        m = metrics.get(key)
        if m and m.get("score") is not None:
            return {"score": m["score"], "vector": m.get("vector"), "version": key}
    return None
