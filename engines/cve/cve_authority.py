"""Is this CVE actually about this product? The independent check the corpus cannot make.

The corpus is the vendor's own advisory pages, harvested and quote-verified. It is authoritative for
"which release fixes this" and unreliable for "does this CVE affect this product at all", because
`kb.product_fix_candidate` fans any product row carrying no cve_id out across every CVE in the
advisory:

    COALESCE(NULLIF(ap.cve_id, ''), bundle.cve_id) AS cve_id

A multi-CVE advisory therefore gives all of its CVEs the union of its products. That is where the
product false positives come from, and no internal consistency check can see it -- the corpus is
perfectly self-consistent and still wrong. Only a second, independent source settles it.

WHY THE DESCRIPTION IS CHECKED, NOT JUST affected[]
---------------------------------------------------
This is the part that is easy to get wrong, and getting it wrong is worse than the bug:

    CVE-2021-43081   affected[] = ["Fortinet FortiProxy"]
                     description = "...in FortiOS version 7.0.3 and below, 6.4.8 and below..."

A FortiGate on 7.0.3 runs the exact version named. Suppressing on affected[] alone would clear a
firewall the vendor explicitly lists, which is a false FIX: the device reads safe while remaining
exploitable, the ticket closes, and nobody looks again. CVE-2021-43072 is the same shape.

Fortinet's own CNA records are structurally inconsistent this way: the product is named in prose
and omitted from the structured array. So a product counts as attributed if it appears in EITHER.

WHY THE ASSIGNER MATTERS
------------------------
For an upstream-assigned CVE (runc, HTTP/2, OpenSSL, BlastRADIUS) the CNA is the upstream project,
and its record will never mention FortiOS or EOS even when the vendor's own advisory legitimately
says the OS bundles the vulnerable component. Absence there means nothing at all. Only a CVE
assigned BY the device's own vendor lets absence carry weight.

Everything here returns None rather than guessing. None means "this source cannot decide", and a
caller must treat it exactly like no data -- never as evidence of safety.
"""
from __future__ import annotations

import json
import logging
import os
import re
from functools import lru_cache

logger = logging.getLogger("cve.authority")

# Where the fetched cache lives. Produced by scripts/fetch_cve_authority.py.
_DEFAULT_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))), "data", "cve_authority.json")

# The CNA short name that owns each platform's own advisories. Absence of the product from a
# record assigned by anyone else is not evidence.
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
    except Exception as e:                     # a corrupt cache must not break a scan
        logger.warning("cve authority cache unreadable (%s): %s", p, e)
        return {}


def record_for(cve_id: str, path: str = "") -> dict | None:
    r = _records(path).get((cve_id or "").upper())
    return r if r and r.get("status") == "published" else None


# Products that share a vendor's release numbering but are NOT the device. Used only to read a
# description that ENUMERATES products: if the prose names these and not the device's own, the
# vendor was being specific. Never used to create a finding -- only to refuse one.
_SIBLING_PRODUCTS = {
    "fortinet": ("fortiweb", "fortimanager", "fortianalyzer", "fortiproxy", "fortisandbox",
                 "fortiadc", "fortimail", "fortiswitch", "fortivoice", "fortindr", "fortisiem",
                 "fortiisolator", "fortipam", "fortirecorder", "fortiap", "forticlient"),
    "arista_eos": ("cloudvision", "cloudeos", "wifi manager", "ng firewall", "edge threat"),
}


def product_attributed(cve_id: str, platform: str, product_names, path: str = ""):
    """Does the authoritative record attribute `cve_id` to this device's product?

    True   the record names the product, in affected[] or in the description
    False  the record is owned by this device's vendor and does NOT name the product anywhere
           -- the corpus attributed it, the vendor did not
    None   cannot decide: no record, not yet published, or the CVE belongs to an upstream CNA
           whose record would not mention the OS either way

    Only False is actionable, and only ever to SUPPRESS. Nothing here can create a finding.
    """
    rec = record_for(cve_id, path)
    if not rec:
        return None

    assigner = _norm(rec.get("assigner"))
    owners = {_norm(v) for v in _VENDOR_CNA.get((platform or "").strip().lower(), set())}
    if not owners or assigner not in owners:
        # Upstream-assigned: the CNA is the component's project, not the device's vendor. Its
        # silence about FortiOS/EOS is expected and carries no information. SA-0135's runc CVEs
        # are the canonical case -- genuinely bundled in EOS, absent from the runc record.
        return None

    wanted = [_norm(p) for p in (product_names or []) if _norm(p)]
    if not wanted:
        return None

    listed = [_norm(p) for p in (rec.get("products") or [])]
    in_array = any(any(w in got for got in listed) for w in wanted)
    desc = _norm(rec.get("description"))
    in_desc = any(w and w in desc for w in wanted)

    # The record contradicting ITSELF: affected[] claims this product, and the prose enumerates the
    # vendor's OTHER products and not this one.
    #
    # CVE-2026-70466 is the case. Its description reads "a vulnerability in Fortinet FortiWeb 8.0.0
    # through 8.0.2, FortiWeb 7.6.0 through 7.6.5, FortiWeb 7.4 all versions ..." -- FortiWeb, five
    # times, FortiOS never -- while affected[] carries FortiOS ranges. We matched it against two
    # FortiGates, one of which had no other open finding at all.
    #
    # An enumerating description that lists sibling products and omits this one is the vendor being
    # specific, not the vendor being terse. The guard is deliberately narrow: it needs a sibling
    # named IN PROSE, and it never fires on a description that simply says nothing about products.
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

    # The description is consulted with equal weight. See the module docstring: Fortinet names the
    # product in prose and omits it from the array often enough that array-only suppression would
    # clear devices on the exact version the advisory calls out.
    if in_desc:
        return True

    return False


def cvss_for(cve_id: str, path: str = "") -> dict | None:
    """The CVE's OWN score, v4.0 preferred over v3.1, or None.

    The corpus serves `kb.advisory.cvss` -- the advisory headline -- for every CVE in a bundle, so
    a multi-CVE advisory gives all its CVEs one score. That drifts both ways and is the widest
    single defect. A score returned here belongs to this CVE and nothing else.
    """
    rec = record_for(cve_id, path)
    if not rec:
        return None
    metrics = rec.get("metrics") or {}
    for key in ("cvssV4_0", "cvssV3_1", "cvssV3_0"):
        m = metrics.get(key)
        if m and m.get("score") is not None:
            return {"score": m["score"], "vector": m.get("vector"), "version": key}
    return None
