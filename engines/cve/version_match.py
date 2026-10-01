from __future__ import annotations

import re
from typing import Optional

_VER_RE = re.compile(r"(\d+(?:\.\d+)+|\d+)\s*([A-Za-z]?)")

_CISCO_RE = re.compile(r"(\d+(?:\.\d+)+)\s*\((\d+)\)\s*([A-Za-z]*)")


def parse_version(raw: str) -> Optional[tuple]:
    if not raw:
        return None
    s = str(raw).strip()
    mc = _CISCO_RE.search(s)
    if mc:
        nums = tuple(int(x) for x in mc.group(1).split(".")) + (int(mc.group(2)),)
        return (nums, (mc.group(3) or "").lower()[:1])
    m = _VER_RE.search(s)
    if not m:
        return None
    try:
        nums = tuple(int(x) for x in m.group(1).split("."))
    except ValueError:
        return None
    return (nums, (m.group(2) or "").lower()[:1])


def _num(parsed) -> tuple:
    return parsed[0]


def _line(parsed) -> str:
    return parsed[1]


def comparable(a, b) -> bool:
    la, lb = _line(a), _line(b)
    return (not la) or (not lb) or la == lb


def _same_train(a, b) -> bool:
    na, nb = _num(a), _num(b)
    return len(na) >= 2 and len(nb) >= 2 and na[:2] == nb[:2]


def span_comparable(pv, pb) -> bool:
    if comparable(pv, pb):
        return True
    if not _same_train(pv, pb):
        return False
    return _num(pv) != _num(pb)


def _in_train(pv, train: str) -> Optional[bool]:
    pt = parse_version(train)
    if pt is None:
        return None
    t, v = _num(pt), _num(pv)
    if len(v) < len(t):
        return None
    return v[:len(t)] == t


def version_in_range(version: str,
                     introduced: str = "",
                     fixed: str = "",
                     fixed_inclusive: bool = False,
                     train: str = "") -> Optional[bool]:
    pv = parse_version(version)
    if pv is None:
        return None
    v = _num(pv)
    if train:
        inside = _in_train(pv, train)
        if inside is False:
            return False
        if inside is None:
            return None
    _pf_t = parse_version(fixed) if fixed else None
    _dvt = v[:2] if len(v) >= 2 else ()
    if _pf_t is not None and _dvt and len(_num(_pf_t)) >= 2 and _num(_pf_t)[:2] < _dvt:
        return False

    if introduced:
        pi = parse_version(introduced)
        if pi is not None:
            if not comparable(pv, pi):
                return None
            if v < _num(pi):
                return False
    if fixed:
        pf = parse_version(fixed)
        if pf is not None:
            f = _num(pf)
            if not (span_comparable(pv, pf) if fixed_inclusive else comparable(pv, pf)):
                _dt = _num(pv)[:2] if len(_num(pv)) >= 2 else ()
                _ft = _num(pf)[:2] if len(_num(pf)) >= 2 else ()
                if _dt and _ft and _dt > _ft:
                    return False
                if not fixed_inclusive and v < f:
                    pass
                else:
                    return None
            elif not fixed_inclusive:
                if v >= f:
                    return False
            else:
                if v > f and v[: len(f)] != f:
                    return False
    return True


def _range_train(r) -> tuple:
    for key in ("train", "fixed", "introduced"):
        raw = (r or {}).get(key) or ""
        if raw:
            p = parse_version(raw)
            if p is not None and len(_num(p)) >= 2:
                return _num(p)[:2]
    return ()


def matches_any_range(version: str, ranges: list) -> Optional[bool]:
    pv = parse_version(version)
    if pv is None:
        return None
    if not ranges:
        return None
    dev_train = _num(pv)[:2] if len(_num(pv)) >= 2 else ()
    own_train_undecidable = False
    decided = False

    _bare_trains = {
        _num(pf)[:2]
        for r in ranges
        if not ((r or {}).get("introduced") or "")
        and not bool((r or {}).get("fixed_inclusive", False))
        and (pf := parse_version((r or {}).get("fixed", "") or "")) is not None
        and len(_num(pf)) >= 2
    }
    per_train_fixes = len(_bare_trains) > 1

    for r in ranges:
        introduced = (r or {}).get("introduced", "") or ""
        fixed = (r or {}).get("fixed", "") or ""
        inc = bool((r or {}).get("fixed_inclusive", False))
        train = (r or {}).get("train", "") or ""

        if per_train_fixes and not introduced and not inc:
            pf = parse_version(fixed)
            fix_num = _num(pf) if pf is not None else ()
            dev_num = _num(pv)
            fix_train = fix_num[:2] if len(fix_num) >= 2 else ()
            if fix_train and dev_train and fix_train > dev_train:
                continue

        hit = version_in_range(version, introduced, fixed, inc, train)
        if hit is True:
            return True
        if hit is None:
            if _range_train(r) == dev_train:
                own_train_undecidable = True
        else:
            decided = True
    if own_train_undecidable:
        return None
    return False if decided else None


_RP_NOT_AFFECTED = re.compile(r"^\s*not\s*affected\b", re.I)

_RP_PAREN_TAIL = re.compile(r"\s*\([^()]*\)\s*$")

_RP_CLAUSE_SPLIT = re.compile(
    r"\s*[;,]\s*"
    r"|\s+and\s+(?=\d)"
    r"|(?<=train)\s+(?=\d)"
    r"|(?<=train)[.;:]\s+(?=\d)"
    r"|(?<=train)[.;:]?\s+(?=(?:[Ff]rom|[Ss]tarting)\s+\d)"
    r"|(?<=train)[.;:]?\s+(?=[Aa]ll\s+(?:the\s+)?(?:releases?|versions?)\s+in\b)"
    r"|(?<=train)\s+(?=[Aa]ll\s+(?:the\s+)?(?:releases?|versions?)\s+(?:prior\s+to|before)\b)"
    r"|(?<=train)\s+(?=[Aa]ll\s+(?:prior|earlier|previous)\s+(?:releases?|versions?)\b)"
    r"|(?<=\))\s+(?=\d)"
)

_LEAD = r"(?:[A-Za-z]+[\s-]){0,3}"
_VNUM = r"(\d+(?:\.\d+)*[A-Za-z]?)"

_RP_BEFORE = re.compile(
    r"^\W*" + _LEAD + r"(?:before|prior\s+to|earlier\s+than|below|lower\s+than|under|"
    r"less\s+than)\s*" + _VNUM + r"\W*$", re.I)


_RP_SPAN = re.compile(
    r"^\W*" + _LEAD + _VNUM + r"\s*"
    r"(?:->|\u2192|to|through|thru|until|upto|up\s+to|\.\.|-|\u2013|\u2014)\s*"
    + _LEAD + _VNUM + r"\W*$", re.I)

_RP_BELOW_UNTIL = re.compile(
    r"^\W*" + _LEAD + _VNUM + r"\s*(?:and|or)\s+(?:below|lower|earlier|prior|older)\s+"
    r"(?:versions?\s+)?(?:until|down\s+to|back\s+to)\s+" + _VNUM + r"\W*$", re.I)

_RP_BELOW = re.compile(
    r"^\W*" + _LEAD + _VNUM + r"\s*(?:branch\s+)?"
    r"(?:and|or)\s+(?:below|lower|earlier|prior|older|before)\b", re.I)

_RP_BELOW_PREFIX = re.compile(
    r"^\W*(?:all\s+versions?\s+)?"
    r"(?:below|before|upto|up\s+to|prior\s+to|earlier\s+than)\s+"
    + _LEAD + _VNUM + r"\b", re.I)

_RP_ALL_AND_BELOW = re.compile(
    r"^\W*" + _LEAD + r"(\d+(?:\.\d+)*)\s+(?:branch\s+)?all\s+versions?\s+"
    r"and\s+(?:below|lower|earlier)\W*$", re.I)

_RP_ABOVE = re.compile(
    r"^\W*" + _LEAD + _VNUM + r"\s*"
    r"(?:and|or)\s+(?:above|later|higher|greater|newer)\b", re.I)

_RP_TRAIN_WILDCARD = re.compile(r"^\W*" + _LEAD + r"(\d+(?:\.\d+)*)\.x\W*$", re.I)

_RP_TRAIN_BELOW = re.compile(
    r"^\W*" + _LEAD + _VNUM + r"\s*(?:and|or)\s+"
    r"(?:below|earlier|lower|prior|older)\s+(?:(?:releases?|versions?)\s+)?in\s+"
    r"(?:the\s+)?(\d+(?:\.\d+)*)(?:\.x)?\s+(?:code\s+)?train\b", re.I)

_RP_TRAIN_SPAN = re.compile(
    r"^\W*(?:from\s+)?" + _LEAD + _VNUM + r"\s*(?:through|thru|to|->|-)\s*" + _VNUM +
    r"\s+in\s+(?:the\s+)?(\d+(?:\.\d+)*)(?:\.x)?\s+(?:code\s+)?train\b", re.I)

_RP_IN_TRAIN = re.compile(
    r"^\W*" + _LEAD + _VNUM + r"\s+in\s+(?:the\s+)?"
    r"(\d+(?:\.\d+)*)(?:\.x)?\s+(?:code\s+)?train\b", re.I)

_RP_ALL_PRIOR_TO = re.compile(
    r"^\W*all\s+(?:the\s+)?(?:releases?|versions?)\s+(?:prior\s+to|before|older\s+than)\s+"
    r"(?:the\s+)?" + _VNUM + r"(?:\.x)?(?:\s+(?:code\s+)?train)?\W*$", re.I)

_RP_ALL_IN_TRAIN = re.compile(
    r"^\W*all\s+(?:the\s+)?(?:releases?|versions?)\s+in\s+(?:the\s+)?(?:branch\s+)?"
    r"(\d+(?:\.\d+)*)(?:\.x)?(?:\s+(?:code\s+)?(?:train|branch))?\W*$", re.I)

_RP_PREVIOUS_BRANCHES = re.compile(
    r"^\W*all\s+(?:the\s+)?(?:releases?|versions?)\s+in\s+"
    r"(?:previous|earlier|prior|older)\s+(?:branch(?:es)?|train(?:s)?|release(?:s)?)\W*$", re.I)

_RP_VERSION_LIST = re.compile(r"^\W*(?:\d+(?:\.\d+)+[A-Za-z]?\d*[A-Za-z]?\s+){2,}"
                              r"\d+(?:\.\d+)+[A-Za-z]?\d*[A-Za-z]?\W*$")

_RP_TRAIN_ALL = re.compile(
    r"^\W*" + _LEAD + r"(\d+(?:\.\d+)*)(?:\.x)?\s+(?:code\s+)?train\b"
    r"\s*[\(,]?\s*all\s+(?:releases?|versions?)", re.I)

_RP_FROM = re.compile(
    r"^\W*(?:(?:after|starting\s+(?:with|from|at)|from)\s+" + _LEAD + _VNUM
    + r"|" + _LEAD + _VNUM + r"\s+onwards?)\W*$", re.I)

_RP_ALL = re.compile(
    r"^\W*(?:all\s+versions?\s+(?:of\s+)?)?" + _LEAD +
    _VNUM + r"\s*,?\s*(?:branch\s+)?(?:all\s+versions?)?\W*$", re.I)
_RP_HAS_ALL = re.compile(r"\ball\s+versions?\b|\bbranch\b", re.I)


_RP_MULTI_LETTER = re.compile(r"\d[\d.]*[A-Za-z]{2,}")


def _train_prefix(v: str) -> str:
    parts = str(v).strip().split(".")
    return ".".join(parts[:2]) if len(parts) >= 2 else (parts[0] if parts else "")


_RP_PAREN_SEMANTIC = re.compile(r"\(\s*(all\s+(?:releases?|versions?)[^()]*)\)", re.I)


def _strip_notes(s: str) -> str:
    s = _RP_PAREN_SEMANTIC.sub(r"\1", s).strip()
    prev = None
    while prev != s:
        prev = s
        s = _RP_PAREN_TAIL.sub("", s).strip()
    return s


def split_range_clauses(text: str) -> list:
    s = _strip_notes(str(text or "").strip())
    if not s:
        return []
    return [c.strip() for c in _RP_CLAUSE_SPLIT.split(s) if c.strip()]


_RP_PRODUCT_LEAD = re.compile(r"^\W*(?:EOS|vEOS|cEOS|MOS|FortiOS|FortiProxy|FortiGate)[\s-]*",
                              re.I)

_RP_ALL_TRAINS_BEFORE = re.compile(
    r"^\W*all\s+releases?\s+in\s+all\s+trains?\s+(?:before|prior\s+to)\s+" + _VNUM + r"\W*$",
    re.I)

_RP_LATER_UP_TO = re.compile(
    r"^\W*" + _LEAD + _VNUM + r"\s+and\s+all\s+(?:later|subsequent|following)\s+"
    r"(?:versions?|releases?)\s+up\s+to\s+" + _VNUM + r"\W*$", re.I)


def parse_range_prose(text: str) -> Optional[dict]:
    if not text:
        return None
    s = _strip_notes(str(text).strip())
    if not s or _RP_NOT_AFFECTED.match(s):
        return None

    m = _RP_BEFORE.match(s)
    if m and parse_version(m.group(1)):
        return {"introduced": "", "fixed": m.group(1), "fixed_inclusive": False}

    m = _RP_ALL_TRAINS_BEFORE.match(s)
    if m and parse_version(m.group(1)):
        return {"introduced": "", "fixed": m.group(1), "fixed_inclusive": False}

    m = _RP_LATER_UP_TO.match(s)
    if m and parse_version(m.group(1)) and parse_version(m.group(2)):
        return {"introduced": m.group(1), "fixed": m.group(2), "fixed_inclusive": True}

    m = _RP_ALL_AND_BELOW.match(s)
    if m and parse_version(m.group(1)):
        return {"introduced": "", "fixed": m.group(1), "fixed_inclusive": True}

    m = _RP_TRAIN_SPAN.match(s)
    if m and parse_version(m.group(1)) and parse_version(m.group(2)) and parse_version(m.group(3)):
        return {"introduced": m.group(1), "fixed": m.group(2), "fixed_inclusive": True,
                "train": m.group(3)}

    m = _RP_SPAN.match(s)
    if m and parse_version(m.group(1)) and parse_version(m.group(2)):
        return {"introduced": m.group(1), "fixed": m.group(2), "fixed_inclusive": True}

    m = _RP_BELOW_UNTIL.match(s)
    if m and parse_version(m.group(1)) and parse_version(m.group(2)):
        return {"introduced": m.group(2), "fixed": m.group(1), "fixed_inclusive": True}

    m = _RP_TRAIN_BELOW.match(s)
    if m and parse_version(m.group(1)) and parse_version(m.group(2)):
        return {"introduced": "", "fixed": m.group(1), "fixed_inclusive": True,
                "train": m.group(2)}

    m = _RP_BELOW.match(s)
    if m and parse_version(m.group(1)):
        return {"introduced": "", "fixed": m.group(1), "fixed_inclusive": True}

    m = _RP_BELOW_PREFIX.match(s)
    if m and parse_version(m.group(1)):
        return {"introduced": "", "fixed": m.group(1), "fixed_inclusive": True}

    m = _RP_ABOVE.match(s)
    if m and parse_version(m.group(1)):
        return {"introduced": m.group(1), "fixed": _train_prefix(m.group(1)),
                "fixed_inclusive": True}

    m = _RP_TRAIN_WILDCARD.match(s)
    if m and parse_version(m.group(1)):
        return {"introduced": m.group(1), "fixed": m.group(1), "fixed_inclusive": True}

    m = _RP_ALL_PRIOR_TO.match(s)
    if m and parse_version(m.group(1)):
        return {"introduced": "", "fixed": m.group(1), "fixed_inclusive": False}

    m = _RP_ALL_IN_TRAIN.match(s)
    if m and parse_version(m.group(1)):
        return {"introduced": "", "fixed": "", "fixed_inclusive": True, "train": m.group(1)}

    m = _RP_TRAIN_ALL.match(s)
    if m and parse_version(m.group(1)):
        return {"introduced": "", "fixed": "", "fixed_inclusive": True, "train": m.group(1)}

    m = _RP_IN_TRAIN.match(s)
    if m and parse_version(m.group(1)):
        return {"introduced": m.group(1), "fixed": m.group(1), "fixed_inclusive": True,
                "train": m.group(2)}

    m = _RP_FROM.match(s)
    if m:
        v = m.group(1) or m.group(2)
        if v and parse_version(v):
            return {"introduced": v, "fixed": _train_prefix(v), "fixed_inclusive": True}

    m = _RP_ALL.match(s)
    if m and parse_version(m.group(1)):
        residue = _RP_PRODUCT_LEAD.sub("", _RP_HAS_ALL.sub("", s)).replace(m.group(1), "", 1)
        if len(re.sub(r"[^A-Za-z0-9]", "", residue)) <= 2:
            return {"introduced": m.group(1), "fixed": m.group(1), "fixed_inclusive": True}

    return None


RANGE, DISPOSITION, UNREADABLE = "range", "disposition", "unreadable"


def classify_range_clause(clause: str):
    if not clause or not clause.strip():
        return DISPOSITION, None
    s = clause.strip()
    if _RP_NOT_AFFECTED.match(s):
        return DISPOSITION, None
    if _RP_MULTI_LETTER.search(s):
        return UNREADABLE, None
    bounds = parse_range_prose(s)
    if bounds:
        return RANGE, bounds
    return UNREADABLE, None


_RP_VERSION_TOKEN = re.compile(r"\d+(?:\.\d+)+[A-Za-z]?")


def _unaccounted_versions(clause: str, bounds: dict) -> list:
    used = [v for v in ((bounds or {}).get("introduced"), (bounds or {}).get("fixed"),
                        (bounds or {}).get("train")) if v]
    out = []
    for tok in _RP_VERSION_TOKEN.findall(clause or ""):
        if any(tok == u or tok.startswith(u) or u.startswith(tok) for u in used):
            continue
        out.append(tok)
    return out


_RP_SCOPE_WORD = re.compile(
    r"(?i)\b(?:only|unless|when|if|models?|series|platforms?|hardware|appliances?|"
    r"builds?|onie|requires?|configured|enabled|running)\b")
_RP_PAREN = re.compile(r"\(([^()]{2,})\)")


def _dropped_qualifiers(text: str) -> list:
    out = []
    for note in _RP_PAREN.findall(text or ""):
        if _RP_VERSION_TOKEN.search(note) or _RP_SCOPE_WORD.search(note):
            out.append(note.strip())
    return out


def analyze_range_prose(texts) -> dict:
    ranges: list = []
    blind = False
    for t in texts or []:
        if _dropped_qualifiers(t):
            blind = True
        clauses = split_range_clauses(t)
        if not clauses and (t or "").strip():
            blind = True
            continue
        expanded = []
        for c in clauses:
            if _RP_VERSION_LIST.match(c or ""):
                expanded.extend(c.split())
            else:
                expanded.append(c)
        clauses = expanded

        _cell_bounds = []
        for c in clauses:
            k, b = classify_range_clause(c)
            if k == RANGE:
                for kk in ("introduced", "fixed", "train"):
                    v = (b or {}).get(kk) or ""
                    pv = parse_version(v) if v else None
                    if pv is not None and _num(pv):
                        _cell_bounds.append(_num(pv))
        _floor = min(_cell_bounds) if _cell_bounds else None
        if _floor is not None:
            _floor_str = ".".join(str(x) for x in _floor)
            for c in list(clauses):
                if _RP_PREVIOUS_BRANCHES.match(c or ""):
                    cand = {"introduced": "", "fixed": _floor_str, "fixed_inclusive": False}
                    if cand not in ranges:
                        ranges.append(cand)

        for clause in clauses:
            if _RP_PREVIOUS_BRANCHES.match(clause or "") and _floor is not None:
                continue
            kind, bounds = classify_range_clause(clause)
            if kind == RANGE:
                if bounds not in ranges:
                    ranges.append(bounds)
                if _unaccounted_versions(clause, bounds):
                    blind = True
            elif kind == UNREADABLE:
                blind = True
    return {"ranges": ranges, "blind": blind}


