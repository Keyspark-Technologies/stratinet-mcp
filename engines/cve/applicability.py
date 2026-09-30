from __future__ import annotations

import os
from dataclasses import dataclass, field

from common.validate import check_enum, check_size
from engines.cve import corpus_query, cve_authority
from engines.cve.version_match import _num, analyze_range_prose, matches_any_range, parse_version

_FORTIOS_NAMES = [
    "FortiOS",
    "FortiGate",
    "FortiGate (FortiOS)",
    "FortiOS (includes FortiGate & FortiWiFi)",
]
_EOS_NAMES = [
    "EOS",
    "Arista EOS",
    "EOS running on Arista switching platforms",
    "EOS/vEOS",
]

_VENDORS = {
    "arista_eos": ("arista_eos", _EOS_NAMES),
    "fortinet_fortios": ("fortinet", _FORTIOS_NAMES),
}
SUPPORTED_VENDORS = sorted(_VENDORS)

_MAX_VERSION_BYTES = 64

_AUTHORITY_FILE = os.path.join("cve", "cve_authority.json")


class AuthorityUnavailable(RuntimeError):
    pass


def authority_path() -> str:
    return os.path.join(os.environ.get("DATA_DIR") or "data", _AUTHORITY_FILE)


@dataclass
class AdvisoryMatch:
    cve_id: str
    advisory_id: str
    substantiated: bool = True
    version_undecidable: bool = False
    affected_ranges: list = field(default_factory=list)
    fixed_versions: list = field(default_factory=list)
    affected_prose: list = field(default_factory=list)
    url: str = ""
    published: str = ""
    severity: str = ""
    cvss: float | None = None
    known_exploited: str = ""
    epss: float | None = None
    in_cisa_kev: bool = False
    kev_due_date: str = ""


@dataclass
class LookupResult:
    vendor: str
    version: str
    version_comparable: bool
    advisories: list = field(default_factory=list)
    cves_seen: tuple = ()


def _clean_version(version) -> str:
    check_size(version, _MAX_VERSION_BYTES, "version")
    return version.strip() if isinstance(version, str) else ""


def _comparable(os_version: str) -> bool:
    if not any(c.isdigit() for c in os_version):
        return False
    p = parse_version(os_version)
    return p is not None and len(_num(p)) >= 3


def _has_quote(r: dict) -> bool:
    return bool(r.get("has_quote")) or bool((r.get("evidence_quote") or "").strip())


def _cvss(cve_id: str, row_cvss, authority: str) -> float | None:
    own = cve_authority.cvss_for(cve_id, path=authority)
    if own and own.get("score") is not None:
        try:
            return float(own["score"])
        except (TypeError, ValueError):
            pass
    return row_cvss


def _same_series(fix_version: str, os_version: str, strict: bool = False) -> bool:
    pf, pv = parse_version(fix_version), parse_version(os_version)
    if pf is None or pv is None:
        return False
    nf, nv = _num(pf), _num(pv)
    if not (nf and nv):
        return False
    if strict:
        return len(nf) >= 2 and len(nv) >= 2 and nf[:2] == nv[:2]
    return nf[0] == nv[0]


def advisories_for_version(
    vendor: str, version: str, rows: list | None = None, authority: str | None = None
) -> LookupResult:
    check_enum(vendor, _VENDORS, "vendor")
    os_version = _clean_version(version)
    result = LookupResult(
        vendor=vendor, version=os_version, version_comparable=_comparable(os_version)
    )
    plat, products = _VENDORS[vendor]
    wanted = set(products)
    all_rows = corpus_query.product_rows(products) if rows is None else rows
    rows = [r for r in all_rows if (r.get("product_clean") or "") in wanted]
    result.cves_seen = tuple(
        sorted({(r.get("cve_id") or "").strip() for r in rows if _has_quote(r)} - {""})
    )
    if not result.version_comparable:
        return result
    authority = authority or authority_path()
    if not os.path.isfile(authority):
        raise AuthorityUnavailable("cve authority data unavailable")

    merged: dict = {}
    blind: dict = {}
    statuses: dict = {}
    fix_ranges: dict = {}
    clear_ranges: dict = {}
    cve_specific: dict = {}

    spans_by_key: dict = {}
    trains_spanned: dict = {}
    for r in rows:
        c = (r.get("cve_id") or "").strip()
        if not c:
            continue
        k = (r["advisory_id"], c)
        rg = (r.get("affected_range") or "").strip()
        if not rg:
            continue
        parsed = analyze_range_prose([rg])
        if not parsed["ranges"]:
            continue
        spans_by_key[k] = True
        if parsed["blind"]:
            continue
        for pr in parsed["ranges"]:
            for fld in ("introduced", "fixed", "train"):
                v = (pr.get(fld) or "").strip()
                pv = parse_version(v) if v else None
                n = _num(pv) if pv is not None else ()
                if len(n) >= 2:
                    trains_spanned.setdefault(k, set()).add(n[:2])

    dev_train = _num(parse_version(os_version) or ())[:2]

    for r in rows:
        cve = (r.get("cve_id") or "").strip()
        if not cve:
            continue
        if not _has_quote(r):
            continue
        key = (r["advisory_id"], cve)
        adv = merged.get(key)
        if adv is None:
            adv = merged[key] = AdvisoryMatch(
                cve_id=cve,
                advisory_id=r["advisory_id"],
                url=(r.get("url") or "").strip(),
                published=(r.get("published") or "").strip(),
                severity=(r.get("severity") or "").strip(),
                cvss=_cvss(cve, r.get("cvss"), authority),
                known_exploited=(r.get("known_exploited") or "").strip(),
                epss=r.get("epss"),
                in_cisa_kev=bool(r.get("in_cisa_kev")),
                kev_due_date=str(r.get("kev_due_date") or "").strip(),
            )
        rng = (r.get("affected_range") or "").strip()
        fix = (r.get("fixed_version_clean") or "").strip()
        row_status = (r.get("status") or "").strip().lower()
        statuses.setdefault(key, set()).add(row_status)
        if rng and rng not in adv.affected_prose:
            adv.affected_prose.append(rng)
        if fix and fix not in adv.fixed_versions and _same_series(fix, os_version):
            adv.fixed_versions.append(fix)

        seen_prose = analyze_range_prose([rng]) if rng else {"ranges": [], "blind": False}
        row_states_complete_span = bool(seen_prose["ranges"]) and not seen_prose["blind"]
        if fix and _same_series(fix, os_version, strict=spans_by_key.get(key, False)):
            cand = {"introduced": "", "fixed": fix}
            train_already_stated = bool(dev_train) and dev_train in trains_spanned.get(key, set())
            if (
                not row_states_complete_span
                and not train_already_stated
                and cand not in adv.affected_ranges
            ):
                adv.affected_ranges.append(cand)
            fr = fix_ranges.setdefault(key, [])
            if cand not in fr:
                fr.append(cand)
        if r.get("cve_specific"):
            cve_specific[key] = True
        if rng and row_status == "not_affected":
            cr = clear_ranges.setdefault(key, [])
            for pr in seen_prose["ranges"]:
                if pr not in cr:
                    cr.append(pr)
        elif rng:
            for pr in seen_prose["ranges"]:
                if pr not in adv.affected_ranges:
                    adv.affected_ranges.append(pr)
        if rng and row_status != "not_affected" and seen_prose["blind"]:
            blind[key] = True

    kept = _applicable(
        list(merged.values()),
        plat,
        os_version,
        blind,
        statuses,
        fix_ranges,
        clear_ranges,
        cve_specific,
        products,
        authority,
    )
    kept.sort(key=lambda a: (a.cve_id, a.advisory_id))
    result.advisories = kept
    return result


def _applicable(
    advisories: list,
    platform: str,
    os_version: str,
    blind: dict,
    statuses: dict,
    fix_ranges: dict,
    clear_ranges: dict,
    cve_specific: dict,
    products: list,
    authority_path: str,
) -> list:
    kept = []
    for a in advisories:
        key = (a.advisory_id, a.cve_id)
        st = statuses.get(key) or set()
        if st and st <= {"not_affected", ""}:
            continue
        if not cve_specific.get(key):
            if (
                cve_authority.product_attributed(a.cve_id, platform, products, path=authority_path)
                is False
            ):
                continue
        cr = clear_ranges.get(key) or []
        if cr and matches_any_range(os_version, cr) is True:
            if matches_any_range(os_version, a.affected_ranges) is not True:
                continue
        if blind.get(key):
            fr = fix_ranges.get(key) or []
            if fr and matches_any_range(os_version, fr) is False:
                continue
            if matches_any_range(os_version, a.affected_ranges) is True:
                kept.append(a)
                continue
            a.substantiated = False
            kept.append(a)
            continue
        if not a.affected_ranges:
            if st and not (st & {"affected", "migrate"}):
                continue
            a.substantiated = False
            kept.append(a)
            continue
        hit = matches_any_range(os_version, a.affected_ranges)
        if hit is None:
            a.substantiated = False
            a.version_undecidable = True
            kept.append(a)
        elif hit:
            kept.append(a)
    return kept
