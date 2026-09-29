"""Deterministic network-OS version parsing + range membership — the CVE-match core.

Replaces the fuzzy / fail-open substring matcher (`sources.version_affected`). Parses
vendor version strings — Arista EOS ("EOS 4.28.1F", "4.35.2F"), FortiOS ("7.0.3"),
Cisco IOS ("15.2(4)E"), Junos, etc. — into a comparable numeric key and decides whether
a device version falls inside an advisory's affected range.

Pure + deterministic (stdlib only). No LLM, no network. Unit-tested against the exact
train boundaries in docs/CVE_GROUND_TRUTH_REFERENCE.md.

Design:
  - Compare by the NUMERIC dotted tuple (4.28.1 -> (4,28,1)).
  - The Arista release-LINE letter (F/M/FX) is load-bearing when BOTH sides carry one.
    This module previously ignored it, on the reasoning that "advisory ranges are expressed
    per-train, so the numeric tuple orders them correctly". That is false, and the harvested
    corpus disproves it: F and M are PARALLEL lines, not sequential phases of a train. It
    looks sequential -- in 17 of the 20 trains carrying both, every F release sits numerically
    below every M release -- which is exactly why the assumption survived. But train 4.33
    carries 4.33.0M *below* 4.33.3F, and trains 4.14 and 4.30 place F and M at the identical
    number (4.14.5F / 4.14.5FX / 4.14.5M all exist). 53 of 301 numeric points in the corpus
    carry more than one suffix.
    The concrete failure: a device on 4.33.3F tested against an M-line span [4.33.0M, 4.33.2M)
    scored 4.33.3 >= 4.33.2 and returned NOT AFFECTED -- a silent FALSE FIX, the one outcome
    this engine exists to prevent. Such a pair now returns None (-> NEEDS_REVIEW).
  - A BARE bound stays line-agnostic and still compares numerically. That is not a compromise:
    an advisory span written introduced="4.28" / fixed="4.28.5" is a train-scoped statement
    covering every line inside it, and Fortinet/Junos carry no letter at all. Refusing those
    would push the whole corpus into NEEDS_REVIEW while removing no real risk. Only an
    explicit-vs-different-explicit line is undecidable.
  - Shorter tuples order below longer ones with the same prefix ((4,28) < (4,28,1)), so
    an `introduced="4.28"` train-floor correctly includes 4.28.1.
  - Fail-CLOSED on *ambiguity we can measure* but NEVER silently: an unparseable version
    returns None so the caller can mark NEEDS_REVIEW (invariant I3) rather than guess.

  - A SPAN boundary and a FIRST-FIX boundary ask different questions, so they get different
    rules (`span_comparable` vs `comparable`):
        "4.35.4M and below"  the vendor ENUMERATING an affected span. Whether 4.35.2F sits
                             inside it is arithmetic within one train -> allowed.
        "fixed in 4.33.2M"   whether 4.33.3F CONTAINS that fix. Its larger number does not
                             imply so, because an M release is maintenance on an older base
                             -> refused. This is the false fix described above.
    `fixed_inclusive` distinguishes them: True is a last-AFFECTED marker, False a first-FIXED one.
    The lower bound keeps the strict rule; "affected from 4.30.0M onwards" says nothing about
    whether an F release is inside an M-scoped span, and 4.30.0 exists on both lines.

  - Refusing BOTH directions of a first-fix comparison threw away a safe answer. Below every
    published fix means the fix is absent whichever line the device is on, and that direction
    can never clear a device; at or above would be a fix-containment claim. Only the second is
    refused.

  - TRAIN membership is a numeric PREFIX question and never needs the letter, so a range may
    carry an explicit `train` that is checked FIRST. Without it a train floor was only a floor:
    (4,35,2) >= (4,28) passed, the M-line ceiling was then incomparable, and the result failed
    closed to AFFECTED -- reporting 2012-era CVEs on a 2024 release.

  - In `matches_any_range`, an undecidable range poisons the answer only when it concerns the
    DEVICE'S OWN train. Vendors publish one fix per train, so an advisory routinely carries
    bounds on trains the device is nowhere near; letting those drown a decisive same-line answer
    accounted for 38 of 77 advisories on one switch.

  - The relaxations above are DERIVED from the corpus, not assumed. Across 27 trains carrying
    lettered releases, 18 keep F and M numerically separated and the 5 that interleave do so
    exactly at a COLLISION -- a numeric point carrying two letters (4.14.5 is F, FX and M;
    4.22.3, 4.30.0 and 4.33.0 are each F and M; 14 points in total). At a collision the numbers
    are equal and carry no order, so those stay refused.

  Every rule above has a direct test in tests/test_matcher_contract.py. `span_comparable` and
  `_in_train` decide whether a comparison may happen AT ALL, and were for a while exercised only
  indirectly through matches_any_range -- which passes for the wrong reason as easily as the right.
"""
from __future__ import annotations

import re
from typing import Optional

# One or more dotted integers, optionally followed by a train/rebuild letter.
# Matches "4.28.1F", "4.35.2F", "7.0.3", "4.28.5.1M", "15.2" (Cisco "(4)E" tail ignored here).
_VER_RE = re.compile(r"(\d+(?:\.\d+)+|\d+)\s*([A-Za-z]?)")

# Cisco-style "15.2(4)E" — capture the parenthetical rebuild as an extra numeric level.
_CISCO_RE = re.compile(r"(\d+(?:\.\d+)+)\s*\((\d+)\)\s*([A-Za-z]*)")


def parse_version(raw: str) -> Optional[tuple]:
    """Parse a version string to (numeric_tuple, train_letter). None if no version found.

    'EOS 4.28.1F'   -> ((4, 28, 1), 'f')
    '4.35.2F'        -> ((4, 35, 2), 'f')
    '7.0.3'          -> ((7, 0, 3), '')
    '4.28.5.1M'      -> ((4, 28, 5, 1), 'm')
    '15.2(4)E'       -> ((15, 2, 4), 'e')
    'no version here'-> None
    """
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
    """The release-line letter ('f', 'm', 'e', ...) or '' for a bare version."""
    return parsed[1]


def comparable(a, b) -> bool:
    """Can these two parsed versions be ordered against each other at all?

    Yes when they share a release line, and yes when EITHER is bare -- a bare version is a
    train-scoped statement that spans every line inside it. No when both name a line and the
    lines differ: 4.33.3F and 4.33.2M are separate branches, and their numeric order carries
    no information about which contains the other's fix. See the module docstring for the
    evidence that these lines are parallel rather than sequential.
    """
    la, lb = _line(a), _line(b)
    return (not la) or (not lb) or la == lb


def _same_train(a, b) -> bool:
    """Do these two parsed versions sit in the same release train (first two components)?"""
    na, nb = _num(a), _num(b)
    return len(na) >= 2 and len(nb) >= 2 and na[:2] == nb[:2]


def span_comparable(pv, pb) -> bool:
    """May a device be ordered against an AFFECTED-SPAN boundary that names a different line?

    `comparable` refuses every explicit-vs-different-explicit line pair, which is right for a
    FIRST-FIXED bound and wrong for a span boundary. The two ask different questions:

        "fixed in 4.33.2M"            -> does 4.33.3F CONTAIN that fix?  Not implied by 4.33.3
                                          being the larger number: an M release is maintenance on
                                          an older base, so a numerically-higher F release can
                                          predate it. Refusing here is what stops the false fix.

        "4.35.4M and below, 4.35 train" -> is 4.35.2F INSIDE the span the vendor enumerated?
                                          That is a numeric question about one train, and the
                                          vendor has already told us the train is affected up to
                                          that number.

    Derived from the corpus rather than assumed. Across 27 trains carrying lettered releases, 18
    keep F and M numerically separated and the 5 that interleave do so exactly AT a collision --
    a numeric point carrying two letters (4.14.5 is F, FX and M; 4.22.3, 4.30.0 and 4.33.0 are
    each F and M; 14 such points in total). Away from those points the numeric tuple is a total
    order within its train, so a span boundary can be honoured.

    At a collision the numbers are equal and carry no order at all, so those stay refused.
    """
    if comparable(pv, pb):
        return True
    if not _same_train(pv, pb):
        return False                      # different trains -> the letters are not the problem
    return _num(pv) != _num(pb)           # equal numbers + different letters = genuine collision


def _in_train(pv, train: str) -> Optional[bool]:
    """Is this version inside release train `train` ("4.28")? Line-agnostic on purpose.

    Train membership is a NUMERIC PREFIX question and never needs the F/M letter, which is why it
    has to be asked before `comparable` gets involved. A bound written "4.28.8M and earlier
    releases in the 4.28.x train" put 4.28 in `introduced`, but a lower bound is only a FLOOR:
    (4,35,2) >= (4,28) passed it, and the ceiling 4.28.8M was then M-line against an F-line device,
    so the whole test came back undecidable and failed closed to AFFECTED. A 4.35 switch was
    reported against 4.21/4.24/4.28-train advisories -- CVEs from 2012 on a 2024 release.
    """
    pt = parse_version(train)
    if pt is None:
        return None
    t, v = _num(pt), _num(pv)
    if len(v) < len(t):
        return None                      # device is less specific than the train -- cannot tell
    return v[:len(t)] == t


def version_in_range(version: str,
                     introduced: str = "",
                     fixed: str = "",
                     fixed_inclusive: bool = False,
                     train: str = "") -> Optional[bool]:
    """Is `version` within [introduced, fixed)?  (fixed = first FIXED release, exclusive).

    - introduced="" -> no lower bound (affects from the beginning of the train).
    - fixed=""      -> no upper bound (no fix / all versions affected, e.g. CVE-2026-7473).
    - Returns None if `version` can't be parsed (caller -> NEEDS_REVIEW, never a silent guess),
      or if a bound sits on a DIFFERENT explicit release line than the device (see `comparable`)
      -- comparing across parallel Arista lines is what produced silent false fixes.
    An unparseable *bound* is ignored (that side is treated as open) rather than failing the whole test.
    """
    pv = parse_version(version)
    if pv is None:
        return None
    v = _num(pv)
    if train:
        # FIRST, and line-agnostic: a device outside the train the advisory scopes itself to is
        # definitively not in range, whatever release lines the bounds carry.
        inside = _in_train(pv, train)
        if inside is False:
            return False
        if inside is None:
            return None
    # A range that BOTH starts and ends in a train older than the device's cannot contain it,
    # whatever release lines the bounds carry. CVE-2025-8873 reaches the matcher from the catalog
    # as five bounded spans -- 4.33.0M..4.33.4M, 4.32.0M..4.32.6.1M, 4.31.0M..4.31.7.1M,
    # 4.30.0M..4.30.10M, 4.29.0M..4.29.10.1M. Against a 4.35.2F device every bound is M-line
    # against an F-line release, so each span came back undecidable and version_affected converted
    # that to AFFECTED. The device is simply above all five spans; no line comparison is needed to
    # say so, only the train.
    #
    # The UPPER bound alone decides this, and only when there is one. An open-ended range --
    # "affected from 4.20.0M onwards", no fix published -- extends past every later train and does
    # contain a 4.35 device; keying on the lower bound would have wrongly cleared it, which is what
    # test_no_ranges_decidable_at_all_is_still_unknown caught.
    _pf_t = parse_version(fixed) if fixed else None
    _dvt = v[:2] if len(v) >= 2 else ()
    if _pf_t is not None and _dvt and len(_num(_pf_t)) >= 2 and _num(_pf_t)[:2] < _dvt:
        return False

    if introduced:
        pi = parse_version(introduced)
        if pi is not None:
            # The lower bound keeps the STRICT rule. "Affected from 4.30.0M onwards" with no
            # upper bound does not tell us whether an F-line release sits inside an M-scoped
            # span, and 4.30 is one of the trains where 4.30.0 exists on BOTH lines. Answering
            # "affected" there would be conservative but more assertive than the evidence, so it
            # stays undecidable (-> NEEDS_REVIEW). Only the upper bound relaxes, and only when it
            # is inclusive, i.e. when the vendor wrote "X and below" and really did enumerate a
            # span. See tests/test_release_lines.py::test_cross_line_lower_bound_alone.
            if not comparable(pv, pi):
                return None
            if v < _num(pi):
                return False
    if fixed:
        pf = parse_version(fixed)
        if pf is not None:
            f = _num(pf)
            # An INCLUSIVE upper bound is the last AFFECTED release (vendor prose: "X and below"),
            # so it is a span boundary. An EXCLUSIVE one is the FIRST FIXED release, where a
            # cross-line comparison could assert fix containment we cannot know.
            if not (span_comparable(pv, pf) if fixed_inclusive else comparable(pv, pf)):
                # Cross-line on a FIRST-FIXED bound. The two directions carry different risk and
                # were previously discarded together:
                #   device BELOW the fix -> AFFECTED. This never clears anything, so it is safe
                #     across lines: a release earlier than every fix the vendor published does not
                #     contain one, whichever line it sits on.
                #   device AT OR ABOVE   -> would mean "fixed", which across lines is exactly the
                #     false fix this module exists to prevent (4.33.3F is not fixed by a fix that
                #     landed in 4.33.2M -- an M release is maintenance on an older base).
                # Refusing both cost us the safe half: on a 4.35.2F switch, 38 of 77 corpus
                # advisories came back undecidable purely because their only recorded fix sits on
                # the M line, and every one of those is a release the vendor never fixed for F.
                # A fix on a STRICTLY OLDER TRAIN is a third case, and it is decidable. Arista's
                # trains are sequential -- 4.32 -> 4.33 -> 4.34 -> 4.35 -- so a fix released in
                # 4.31.3M is carried forward into every later train regardless of line letter. The
                # cross-line refusal above is about fixes within the SAME train, where an M release
                # is maintenance on an older base and containment genuinely cannot be assumed.
                #
                # Without this, a 4.35.2F switch stayed undecidable against CVE-2024-27890 (fixes
                # ending at 4.31.3M), CVE-2024-8000 (4.33.0M) and CVE-2025-8873 (4.33.5M) -- four
                # trains past every fix the vendor published, and reported as possibly affected.
                # The same reasoning is already applied to bare per-train fixes in
                # matches_any_range; this extends it to a first-fixed bound.
                _dt = _num(pv)[:2] if len(_num(pv)) >= 2 else ()
                _ft = _num(pf)[:2] if len(_num(pf)) >= 2 else ()
                if _dt and _ft and _dt > _ft:
                    # Holds for BOTH bound kinds, for the same reason in each:
                    #   first-fixed  -- the fix landed in an older train, so a newer train carries
                    #                   it forward whatever line letter it has.
                    #   inclusive    -- "4.29.7M and below" is a span that ENDS in the 4.29 train;
                    #                   a 4.35 release sits above it, so it is outside the span.
                    # Only the SAME-train cross-line case stays refused, which is the one the
                    # false-fix guard was written for (4.33.3F is not fixed by 4.33.2M).
                    return False
                if not fixed_inclusive and v < f:
                    pass                  # affected -- fall through
                else:
                    return None
            elif not fixed_inclusive:
                if v >= f:
                    return False
            else:
                # Inclusive upper bound. A train/branch prefix (e.g. "4.35") includes every
                # release inside it ("4.35.2F"), even though the tuple (4,35,2) sorts ABOVE
                # (4,35). CVE-v5 expresses "all of the 4.35 train affected" as
                # lessThanOrEqual="4.35"; exclude only when v is strictly above f AND not
                # within that train. (CSAF ranges use exclusive `fixed`, so this branch is
                # exercised only by the CVE-v5 mapper.)
                if v > f and v[: len(f)] != f:
                    return False
    return True


def _range_train(r) -> tuple:
    """The release train a range is bounded in, as a numeric pair, or () if it names none.

    Read from the explicit `train` key when present, else from whichever bound is available.
    """
    for key in ("train", "fixed", "introduced"):
        raw = (r or {}).get(key) or ""
        if raw:
            p = parse_version(raw)
            if p is not None and len(_num(p)) >= 2:
                return _num(p)[:2]
    return ()


def matches_any_range(version: str, ranges: list) -> Optional[bool]:
    """True if `version` is in ANY of `ranges` (list of {introduced, fixed}).

    None when the device version is unparseable, when `ranges` is empty (unknown -- do not
    fabricate a match), or when no range matched but at least one was UNDECIDABLE. That last
    case is the important one: a single undecidable range poisons a False. Previously the loop
    dropped None results on the floor (`result = result`) and returned False, so a device whose
    only applicable span sat on another Arista release line was reported NOT AFFECTED. A True
    still wins immediately -- one range that definitely matches settles it regardless.
    """
    pv = parse_version(version)
    if pv is None:
        return None
    if not ranges:
        return None
    dev_train = _num(pv)[:2] if len(_num(pv)) >= 2 else ()
    own_train_undecidable = False
    decided = False

    # A bare first-fix entry -- no `introduced`, so it reads as "everything below FIXED is
    # affected" -- is only meaningful inside its own train when the advisory publishes one fix PER
    # train. FG-IR-24-015 lists 7.4.3, 7.2.7, 7.0.14, 6.4.15, 6.2.16 and 6.0.18. A 7.2.13 firewall
    # is past its own train's fix (7.2.7) and genuinely patched, but 7.2.13 < 7.4.3 numerically, so
    # the 7.4 entry reported it AFFECTED -- a critical false positive on a device that had already
    # been upgraded.
    #
    # Scoped deliberately: this only engages when bare fixes span MORE THAN ONE train, which is
    # what makes them per-train statements. A product with a single linear fix ("fixed in 2.5.1")
    # keeps the old behaviour, where being below the fix does mean affected.
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
            # Direction matters, and only ONE direction is unsound.
            #
            # Fix on a LATER train than the device (7.2.13 against the 7.4.3 entry): says nothing
            # about this device, because 7.2 has its own fix. Reading "below 7.4.3" as affected is
            # what reported a patched firewall as EXPOSED. Skip it.
            #
            # Fix on an EARLIER or the SAME train (a 4.35.2F switch against SA-0010's 4.15.2F):
            # still meaningful -- a later train already contains a fix that landed earlier, so
            # "past it" is a real not-affected. Skipping these instead made a switch plainly past
            # every published fix read undecidable, which is safe but useless. Evaluate normally.
            #
            # Skipping the newer-train entry can never hide a real hit: a genuine match on the
            # device's own train returns True from its own entry, and True wins immediately.
            if fix_train and dev_train and fix_train > dev_train:
                continue

        hit = version_in_range(version, introduced, fixed, inc, train)
        if hit is True:
            return True
        if hit is None:
            # An undecidable range only poisons the answer when it concerns the DEVICE'S OWN
            # train. Arista publishes one fix per train, so a range bounded in another train says
            # nothing about this device: SA-0010 lists fixes for 4.11.12M, 4.12.11M, 4.13.13M,
            # 4.14.8M and 4.15.2F, and for a 4.35.2F switch only the last is comparable -- it is
            # on the same line, twenty trains earlier, and the device is plainly past it. Letting
            # the four ancient M-line entries poison that False is what reported CVE-2015-3456 on
            # a 2024 release, and it accounted for 38 of 77 advisories on that device.
            if _range_train(r) == dev_train:
                own_train_undecidable = True
        else:
            decided = True
    if own_train_undecidable:
        return None
    return False if decided else None


def fixed_from_ranges(ranges: list) -> list:
    """Vendor-fixed releases implied by a CVE's affected ranges.

    Every record in the catalog has an empty `fixed_versions` — the CVE-v5 feed carries affected
    spans, not a solution table — so `_pick_fixed` returned "" for all 9,981 CVEs and no finding
    ever cited the release that fixes it. The information is present, just encoded in the span:

        {"introduced": "7.0.0", "fixed": "7.0.17", "fixed_inclusive": True}
            affected THROUGH 7.0.17  ->  fixed in 7.0.18

        {"introduced": "4.28", "fixed": "4.28.5"}            (no fixed_inclusive)
            4.28.5 IS the first fixed release

    Which matches the vendor advisories: Fortinet publishes "7.0.0 through 7.0.17 → upgrade to
    7.0.18 or above". Deterministic — this reads a flag the parser already set, it does not guess.

    Open ranges (`fixed` empty) mean no patch exists and contribute nothing. Returns the
    per-train fixed releases, de-duplicated, in the order encountered.
    """
    out: list = []
    for r in ranges or []:
        if not isinstance(r, dict):
            continue
        fixed = str(r.get("fixed") or "").strip()
        if not fixed:
            continue                      # no-patch CVE — nothing to cite
        p = parse_version(fixed)
        if not p:
            continue
        nums, train = p
        if r.get("fixed_inclusive"):
            # Last AFFECTED release; the fix is the next one on that train.
            nums = nums[:-1] + (nums[-1] + 1,)
        v = ".".join(str(n) for n in nums) + (train.upper() if train else "")
        if v not in out:
            out.append(v)
    return out


# ── Vendor range prose → structured bounds ───────────────────────────────────
# Advisories state affected spans as English, not as data: "7.0.0 through 7.0.5", "6.2.0 and
# below", "7.0 all versions". The harvested corpus stores that text verbatim (kb.advisory_product
# .affected_range) because rewriting a vendor's words during extraction is how fabricated ranges
# get in. Somebody still has to turn it into bounds, and this module is where version semantics
# live -- a caller that parsed it locally would be a second, disagreeing implementation of the
# ordering rules that `comparable`/`version_in_range` already own.
#
# Why this is not optional: without it, a range that never became structured falls back to the
# legacy substring test in `sources.version_affected`, which cannot see that 7.0.3 lies inside
# "7.0.0 through 7.0.5". It reports NOT AFFECTED for a device the vendor lists as affected -- a
# false FIX, the one failure mode this package exists to prevent. Three real FortiOS advisories
# (CVE-2022-23438, CVE-2022-23442, CVE-2023-29184) hit exactly that on a 7.0.3 device.
#
# Anything not recognised returns None -- "I could not read this" -- so the caller keeps the
# advisory instead of dropping it on a guess.

_RP_NOT_AFFECTED = re.compile(r"^\s*not\s*affected\b", re.I)

# A trailing parenthetical is an operator note, not part of the range. Fortinet writes
# "6.4.0 through 6.4.9 (6.4.0 through 6.4.3 Need to be authenticated to provoke a crash)" and
# "7.0.0 through 7.0.6 (special below for FG6000F and 7000E models)". Twelve distinct corpus
# strings carry one, and it defeated every anchored pattern below -- including two 7.0.x spans
# that the test firewall sits inside.
_RP_PAREN_TAIL = re.compile(r"\s*\([^()]*\)\s*$")

# One cell can hold several spans: "6.2.0, 6.0.0 to 6.0.6, 5.6.10 and below" is three, and
# "5.4.0; 5.2.7 and below; 5.0.13 and below" three more. Split AFTER stripping notes, because a
# parenthetical can itself contain commas.
# Arista writes "4.12.0 through 4.12.7.1 and 4.13.0 through 4.13.6". Splitting on a bare "and"
# would also shatter "5.2.12 and newer versions" into a version plus the word "newer", so the
# separator only counts when a VERSION follows it.
_RP_CLAUSE_SPLIT = re.compile(
    r"\s*[;,]\s*"                     # Fortinet: comma / semicolon separated
    r"|\s+and\s+(?=\d)"               # "... and 4.13.0 through 4.13.6"
    r"|(?<=train)\s+(?=\d)"            # Arista: "... 4.21.x train 4.22.3M and below ..."
    # The same boundary, punctuated: "... in the 4.24.x train. 4.23.4M and below releases ...".
    # The lookbehind above needs "train" flush against the space, so a full stop between them
    # welded the next clause on and dropped it. CVE-2020-24360 and CVE-2020-15897.
    r"|(?<=train)[.;:]\s+(?=\d)"
    # ... and the same boundary followed by a WORD rather than a digit: "... in the 4.29.x train
    # From 4.28.1F through 4.28.11M in the 4.28.x train". The 4.28 clause was swallowed whole and
    # CVE-2024-5872 answered NOT AFFECTED for a 4.28.1F switch Arista names explicitly -- a false
    # fix. Only "From"/"Starting" qualify: they open a new bounded clause. A bare word must not
    # split, or "4.29 train all releases" loses the suffix that qualifies it.
    r"|(?<=train)[.;:]?\s+(?=(?:[Ff]rom|[Ss]tarting)\s+\d)"
    # "... 4.22.x train All releases in the 4.23.x train" -- a NEW clause. Requires the "in",
    # so the trailing suffix in "4.29 train all releases" (unwrapped from its parentheses by
    # _strip_notes) stays attached to the train it qualifies instead of being severed from it.
    # "the" is optional and the boundary may be punctuated: Arista writes both
    # "... 4.22.x train All releases in the 4.23.x train" and "... 4.29.x train All THE releases
    # in the 4.28.x train" (CVE-2024-9135, whose dropped clause is the 4.28 train the lab runs),
    # and "... 4.21.x train. All releases in the 4.20.x train" (CVE-2020-15897).
    r"|(?<=train)[.;:]?\s+(?=[Aa]ll\s+(?:the\s+)?(?:releases?|versions?)\s+in\b)"
    # "... 4.31.x train All releases prior to 4.31.x train" and "... 4.21.x train All prior
    # releases" -- an unbounded catch-all carrying its OWN scope, so a NEW clause. Without these
    # the tail welds onto the preceding span; classify_range_clause reads the leading bound,
    # returns a confident RANGE, and the catch-all is discarded with `blind` still False.
    #
    # That is the false-fix shape. CVE-2025-8872 is affected in "all releases prior to 4.31.x
    # train", which covers the 4.28.1F switches -- and the welded form reported them NOT AFFECTED
    # with confidence. The clause parses correctly in isolation (blind=True); only the welded
    # form loses it. Arista publishes a comma-less variant, so there is no separator to split on.
    #
    # Deliberately narrower than the bare "all releases" rule above: a trailing "4.29 train all
    # releases" (unwrapped from its parentheses by _strip_notes) is a SUFFIX qualifying its own
    # train, not a new scope, and must stay attached or a readable advisory becomes undecidable.
    # The discriminator is the scope word -- "in" / "prior to" / "before", or the adjective forms
    # "all prior/earlier/previous releases".
    r"|(?<=train)\s+(?=[Aa]ll\s+(?:the\s+)?(?:releases?|versions?)\s+(?:prior\s+to|before)\b)"
    r"|(?<=train)\s+(?=[Aa]ll\s+(?:prior|earlier|previous)\s+(?:releases?|versions?)\b)"
    r"|(?<=\))\s+(?=\d)"              # "4.29 train (all releases) 4.28 train (...)"
)

# Leading product/filler words to tolerate: "FortiOS 5.4.6 to 5.4.12", "before versions 5.4.2".
# "EOS-4.13.0F" attaches the product with a HYPHEN, not a space, so both separate.
_LEAD = r"(?:[A-Za-z]+[\s-]){0,3}"
_VNUM = r"(\d+(?:\.\d+)*[A-Za-z]?)"

# "7.0.0 through 7.0.5" / "5.4.6 to 5.4.12" / "6.0.3 - 6.2.0" / "5.6.1 -> 5.6.3".
# Upper bound INCLUSIVE: the vendor names the last affected release, not the first fixed one.
# "->" must precede "-" in the alternation or "-" consumes its first character and leaves ">".
# "before 7.0.3" / "prior to 7.0.3" / "earlier than 7.0.3" -- the version named is the FIRST
# FIXED release, so the bound is EXCLUSIVE. Fortinet's CNA writes this into the CVE-v5
# `version` field as free text ("FortiOS before 7.0.3"). Dropping the qualifier inverts the
# meaning: it made the fix itself the only affected release and flagged a patched 7.0.3
# firewall as vulnerable.
# Word order carries the whole meaning here, and the two orders are opposites:
#
#     "6.0.5 and below"   -> 6.0.5 IS affected      (inclusive, _RP_BELOW)
#     "below 6.0.5"       -> 6.0.5 is the FIX       (exclusive, here)
#
# Bare "below X" was missing from this list, and _LEAD -- which tolerates up to three leading
# words -- happily swallowed the word "below" itself, leaving a bare version that read as
# inclusive. So "all versions below 6.0.5" reported a device running exactly 6.0.5, the fixed
# release, as affected. CVE-2019-6695, CVE-2019-5587, CVE-2018-9186 and CVE-2017-14191 all use
# this phrasing.
_RP_BEFORE = re.compile(
    r"^\W*" + _LEAD + r"(?:before|prior\s+to|earlier\s+than|below|lower\s+than|under|"
    r"less\s+than)\s*" + _VNUM + r"\W*$", re.I)


_RP_SPAN = re.compile(
    r"^\W*" + _LEAD + _VNUM + r"\s*"
    r"(?:->|\u2192|to|through|thru|until|upto|up\s+to|\.\.|-|\u2013|\u2014)\s*"
    + _LEAD + _VNUM + r"\W*$", re.I)

# "6.0.8 and below versions until 5.4.0" -- the trailing "until Y" supplies a LOWER bound, so this
# is 5.4.0 through 6.0.8, not everything at or under 6.0.8. Must be tried before _RP_BELOW, which
# would match the same text and silently drop the bound. Independent review of all 264 corpus
# cells flagged exactly this one string: reading it as unbounded made a 5.2.14 device look
# affected. Conservative (a false positive, never a false fix), but wrong.
_RP_BELOW_UNTIL = re.compile(
    r"^\W*" + _LEAD + _VNUM + r"\s*(?:and|or)\s+(?:below|lower|earlier|prior|older)\s+"
    r"(?:versions?\s+)?(?:until|down\s+to|back\s+to)\s+" + _VNUM + r"\W*$", re.I)

# "6.2.0 and below" / "5.2 and lower versions" / "6.0.1 and before" / "5.2 branch and below"
_RP_BELOW = re.compile(
    r"^\W*" + _LEAD + _VNUM + r"\s*(?:branch\s+)?"
    r"(?:and|or)\s+(?:below|lower|earlier|prior|older|before)\b", re.I)

# "below FortiOS 6.0.8" / "all versions before 6.0.4" / "upto 5.6.0" / "prior to 6.2.3"
_RP_BELOW_PREFIX = re.compile(
    r"^\W*(?:all\s+versions?\s+)?"
    r"(?:below|before|upto|up\s+to|prior\s+to|earlier\s+than)\s+"
    + _LEAD + _VNUM + r"\b", re.I)

# "5.4 all versions and below" -- a whole train, and everything under it.
_RP_ALL_AND_BELOW = re.compile(
    r"^\W*" + _LEAD + r"(\d+(?:\.\d+)*)\s+(?:branch\s+)?all\s+versions?\s+"
    r"and\s+(?:below|lower|earlier)\W*$", re.I)

# "7.4.0 and above" / "5.2.12 and newer versions"
_RP_ABOVE = re.compile(
    r"^\W*" + _LEAD + _VNUM + r"\s*"
    r"(?:and|or)\s+(?:above|later|higher|greater|newer)\b", re.I)

# "6.0.x" / "5.2.x" -- a train wildcard.
_RP_TRAIN_WILDCARD = re.compile(r"^\W*" + _LEAD + r"(\d+(?:\.\d+)*)\.x\W*$", re.I)

# Arista, train-scoped. "4.21.8M and below releases in the 4.21.x train" bounds the span ABOVE at
# 4.21.8M and scopes it to the 4.21 train, so a 4.28 device is outside it -- and a 4.21.1F device is
# undecidable against it rather than cleared, because F and M are parallel lines (see `comparable`).
_RP_TRAIN_BELOW = re.compile(
    r"^\W*" + _LEAD + _VNUM + r"\s*(?:and|or)\s+"
    # "releases"/"versions" is OPTIONAL. Arista writes both "4.33.4M and below releases in the
    # 4.33.x train" and, on the same advisory, "4.33.1F and below in the 4.33.X train". Requiring
    # the noun made the second form fall through to _RP_BELOW, which is exactly the failure the
    # comment above warns about: the train scope is dropped and the span becomes unbounded
    # downwards, so CVE-2025-6188 -- which concerns 4.30 through 4.33 -- matched a 4.28.1F switch.
    r"(?:below|earlier|lower|prior|older)\s+(?:(?:releases?|versions?)\s+)?in\s+"
    r"(?:the\s+)?(\d+(?:\.\d+)*)(?:\.x)?\s+(?:code\s+)?train\b", re.I)

# "From 4.30.1F through 4.30.9M in the 4.30.x train" -- a span WITH a lower bound, scoped to a
# train. Unreadable before, so CVE-2025-0936 went blind and stayed on every switch as undecidable.
# Must be tried before _RP_SPAN, which would take the span and silently discard the train scope.
_RP_TRAIN_SPAN = re.compile(
    r"^\W*(?:from\s+)?" + _LEAD + _VNUM + r"\s*(?:through|thru|to|->|-)\s*" + _VNUM +
    r"\s+in\s+(?:the\s+)?(\d+(?:\.\d+)*)(?:\.x)?\s+(?:code\s+)?train\b", re.I)

# "4.27.0F in the 4.27.x train" -- that release, inside that train.
_RP_IN_TRAIN = re.compile(
    r"^\W*" + _LEAD + _VNUM + r"\s+in\s+(?:the\s+)?"
    r"(\d+(?:\.\d+)*)(?:\.x)?\s+(?:code\s+)?train\b", re.I)

# "All releases prior to 4.31.x train" / "All versions before 4.31" -- everything strictly BELOW
# the named train. Bounded, so it can be decided rather than merely flagged: it puts a 4.28.1F
# switch inside CVE-2025-8872 and a 4.35.2F switch outside it, which is what Arista means.
#
# The bare adjective form -- "All prior releases", CVE-2021-28500 -- names no version at all and
# stays unreadable on purpose. There is nothing to bound it with, and guessing would be the false
# fix this whole path exists to prevent.
_RP_ALL_PRIOR_TO = re.compile(
    r"^\W*all\s+(?:the\s+)?(?:releases?|versions?)\s+(?:prior\s+to|before|older\s+than)\s+"
    r"(?:the\s+)?" + _VNUM + r"(?:\.x)?(?:\s+(?:code\s+)?train)?\W*$", re.I)

# "All releases in the 4.22.x train" / "All releases in 4.22.x train"
_RP_ALL_IN_TRAIN = re.compile(
    # "All THE releases in the 4.28.x train" -- CVE-2024-9135 writes it this way, and without the
    # optional article the clause classified as unreadable, so the 4.28 train the lab runs was
    # never read as affected.
    # Fortinet says "branch" where Arista says "train": "All versions in branch 8.0".
    r"^\W*all\s+(?:the\s+)?(?:releases?|versions?)\s+in\s+(?:the\s+)?(?:branch\s+)?"
    r"(\d+(?:\.\d+)*)(?:\.x)?(?:\s+(?:code\s+)?(?:train|branch))?\W*$", re.I)

# "All versions in previous branches" -- everything OLDER than the branches named beside it. On its
# own it names no version, so it can only be read with the rest of the cell; analyze_range_prose
# resolves it against the lowest branch the other clauses mention. Fortinet uses it constantly on
# older advisories, and left unread it kept CVEs fixed in 5.2 alive on a 7.0.3 firewall -- the
# KRACK family among them, eight years past their fix.
_RP_PREVIOUS_BRANCHES = re.compile(
    r"^\W*all\s+(?:the\s+)?(?:releases?|versions?)\s+in\s+"
    r"(?:previous|earlier|prior|older)\s+(?:branch(?:es)?|train(?:s)?|release(?:s)?)\W*$", re.I)

# A bare whitespace-separated run of versions: "4.18 4.19 4.18.10M 4.19.0F". Arista lists every
# affected build this way on some advisories, and with no separator word the clause splitter sees
# one unreadable blob.
_RP_VERSION_LIST = re.compile(r"^\W*(?:\d+(?:\.\d+)+[A-Za-z]?\d*[A-Za-z]?\s+){2,}"
                              r"\d+(?:\.\d+)+[A-Za-z]?\d*[A-Za-z]?\W*$")

# "4.29 train (all releases)" / "4.29 train, all releases"
_RP_TRAIN_ALL = re.compile(
    r"^\W*" + _LEAD + r"(\d+(?:\.\d+)*)(?:\.x)?\s+(?:code\s+)?train\b"
    r"\s*[\(,]?\s*all\s+(?:releases?|versions?)", re.I)

# "after EOS-4.10.0" / "starting with 4.14.0F" / "4.17.0 onwards"
_RP_FROM = re.compile(
    r"^\W*(?:(?:after|starting\s+(?:with|from|at)|from)\s+" + _LEAD + _VNUM
    + r"|" + _LEAD + _VNUM + r"\s+onwards?)\W*$", re.I)

# "7.0 all versions" / "all versions of 6.4" / "5.2 branch all versions" / a bare "6.2.0"
_RP_ALL = re.compile(
    r"^\W*(?:all\s+versions?\s+(?:of\s+)?)?" + _LEAD +
    _VNUM + r"\s*,?\s*(?:branch\s+)?(?:all\s+versions?)?\W*$", re.I)
_RP_HAS_ALL = re.compile(r"\ball\s+versions?\b|\bbranch\b", re.I)


# Arista ships parallel lines whose suffix is more than one letter: 4.15.0FX, 4.15.0FXA,
# 4.15.1FXB. parse_version keeps only the FIRST letter (`(m.group(2) or "").lower()[:1]`), so every
# one of those collapses onto the F line -- and `comparable` would then happily compare 4.15.0FX
# against 4.15.2F as if they were the same release line. That is precisely the cross-line
# comparison this module refuses to make. Rather than widen parse_version (which would change
# every comparison in the engine), a clause carrying such a token is declared UNREADABLE, so the
# advisory is kept for review instead of being decided on a line we cannot represent.
_RP_MULTI_LETTER = re.compile(r"\d[\d.]*[A-Za-z]{2,}")


def _train_prefix(v: str) -> str:
    """The release train a version belongs to: "5.2.12" -> "5.2", "7.0" -> "7.0", "5" -> "5"."""
    parts = str(v).strip().split(".")
    return ".".join(parts[:2]) if len(parts) >= 2 else (parts[0] if parts else "")


# "4.29 train (all releases)" -- here the parenthetical carries the SCOPE, not an aside. Unwrap it
# instead of deleting it, or the clause degrades to "4.29 train" and parses as nothing at all.
_RP_PAREN_SEMANTIC = re.compile(r"\(\s*(all\s+(?:releases?|versions?)[^()]*)\)", re.I)


def _strip_notes(s: str) -> str:
    """Drop trailing parenthetical NOTES, keeping any that carry scope.

    Repeated because a few cells carry two notes.
    """
    s = _RP_PAREN_SEMANTIC.sub(r"\1", s).strip()
    prev = None
    while prev != s:
        prev = s
        s = _RP_PAREN_TAIL.sub("", s).strip()
    return s


def split_range_clauses(text: str) -> list:
    """One affected-range cell -> its individual span clauses, operator notes removed."""
    s = _strip_notes(str(text or "").strip())
    if not s:
        return []
    return [c.strip() for c in _RP_CLAUSE_SPLIT.split(s) if c.strip()]


# A leading product name, which carries no version information: "EOS-4.10", "FortiOS 6.2".
_RP_PRODUCT_LEAD = re.compile(r"^\W*(?:EOS|vEOS|cEOS|MOS|FortiOS|FortiProxy|FortiGate)[\s-]*",
                              re.I)

# "all releases in all trains before 4.31" -- everything strictly below 4.31, across every train.
# _RP_BEFORE cannot reach it: _LEAD tolerates three leading words and this has six.
_RP_ALL_TRAINS_BEFORE = re.compile(
    r"^\W*all\s+releases?\s+in\s+all\s+trains?\s+(?:before|prior\s+to)\s+" + _VNUM + r"\W*$",
    re.I)

# "4.13.0 and all later versions up to 4.19.0" -- a span written the long way round. Unambiguous:
# both ends are named, so it needs no interpretation, only a pattern.
_RP_LATER_UP_TO = re.compile(
    r"^\W*" + _LEAD + _VNUM + r"\s+and\s+all\s+(?:later|subsequent|following)\s+"
    r"(?:versions?|releases?)\s+up\s+to\s+" + _VNUM + r"\W*$", re.I)


def parse_range_prose(text: str) -> Optional[dict]:
    """A vendor's affected-range clause as {introduced, fixed, fixed_inclusive}, or None.

        "7.0.0 through 7.0.5"  -> {introduced: "7.0.0", fixed: "7.0.5", fixed_inclusive: True}
        "6.2.0 and below"      -> {introduced: "",      fixed: "6.2.0", fixed_inclusive: True}
        "7.0 all versions"     -> {introduced: "7.0",   fixed: "7.0",   fixed_inclusive: True}
        "6.0.x"                -> the 6.0 train
        "Not affected"         -> None   (a disposition, not a range)
        "all versions"         -> None   (no branch named -- scope genuinely unknown)
        "call support"         -> None   (unreadable -> caller must not drop the advisory)

    A train is expressed as an inclusive bound on ITSELF ("7.0" fixed-inclusive) so the prefix rule
    in `version_in_range` keeps 7.0.3 inside it while leaving 7.2.0 out. An open-ended range would
    have swept in every later train instead.

    Order matters: specific shapes are tried before the bare-version catch-all, so
    "5.4 all versions and below" reads as a bound rather than as the 5.4 train alone.
    """
    if not text:
        return None
    s = _strip_notes(str(text).strip())
    if not s or _RP_NOT_AFFECTED.match(s):
        return None

    # "before X" / "prior to X" -- X is the FIRST FIXED release, so the bound is EXCLUSIVE.
    # Tried before the inclusive forms: dropping the qualifier inverts the meaning, which is what
    # turned "FortiOS before 7.0.3" into "7.0.3 affected" and flagged a patched firewall.
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

    # Train-scoped span first: _RP_SPAN would match the same text and drop the train.
    m = _RP_TRAIN_SPAN.match(s)
    if m and parse_version(m.group(1)) and parse_version(m.group(2)) and parse_version(m.group(3)):
        return {"introduced": m.group(1), "fixed": m.group(2), "fixed_inclusive": True,
                "train": m.group(3)}

    m = _RP_SPAN.match(s)
    if m and parse_version(m.group(1)) and parse_version(m.group(2)):
        return {"introduced": m.group(1), "fixed": m.group(2), "fixed_inclusive": True}

    # Before the plain "and below": the "until Y" tail is a lower bound, and dropping it would
    # widen the span all the way down.
    m = _RP_BELOW_UNTIL.match(s)
    if m and parse_version(m.group(1)) and parse_version(m.group(2)):
        return {"introduced": m.group(2), "fixed": m.group(1), "fixed_inclusive": True}

    # BEFORE the plain "and below": "4.21.8M and below releases in the 4.21.x train" also matches
    # _RP_BELOW, which would drop the train scope and leave the span unbounded downwards -- so a
    # 4.20.1M device would match an advisory that only concerns the 4.21 train.
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
        # "5.2.12 and newer versions" is BRANCH-scoped. Fortinet names the branch in a separate
        # column, so the text alone reads open-ended; left unbounded (fixed=""), a 2018 advisory
        # about 5.2 would mark every release ever shipped as affected, 7.0.3 and 9.x alike -- the
        # wildcard-CPE failure that produced 212 bogus findings on one site, rebuilt one layer up.
        return {"introduced": m.group(1), "fixed": _train_prefix(m.group(1)),
                "fixed_inclusive": True}

    m = _RP_TRAIN_WILDCARD.match(s)
    if m and parse_version(m.group(1)):
        return {"introduced": m.group(1), "fixed": m.group(1), "fixed_inclusive": True}

    # Arista's remaining train-scoped clauses, before the bare-version catch-all.
    # Tried before _RP_ALL_IN_TRAIN: "prior to" is an EXCLUSIVE bound below the train, not the
    # train itself, and reading it as the train would invert which devices match.
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
            # Same branch-scoping as "X and above": an open top would mark every future release
            # affected by an advisory about one train.
            return {"introduced": v, "fixed": _train_prefix(v), "fixed_inclusive": True}

    # A bare version, with or without "all versions", means that release/train and nothing above.
    m = _RP_ALL.match(s)
    if m and parse_version(m.group(1)):
        # Guard against a stray number in prose we did not really understand: accept a bare
        # version only when the text is essentially just that version (optionally "all versions").
        # The product name is not residue. "EOS-4.10" left "EOS" behind -- three characters
        # against a limit of two -- so a perfectly ordinary version was rejected by a guard meant
        # to catch stray numbers in prose. 16 rows across 15 CVEs sat undecided on that one
        # character.
        residue = _RP_PRODUCT_LEAD.sub("", _RP_HAS_ALL.sub("", s)).replace(m.group(1), "", 1)
        if len(re.sub(r"[^A-Za-z0-9]", "", residue)) <= 2:
            return {"introduced": m.group(1), "fixed": m.group(1), "fixed_inclusive": True}

    return None


RANGE, DISPOSITION, UNREADABLE = "range", "disposition", "unreadable"


def classify_range_clause(clause: str):
    """(kind, bounds) for one clause: RANGE + dict, or DISPOSITION / UNREADABLE + None.

    The distinction between the last two is the whole point. "Not affected" is a DISPOSITION: the
    vendor is telling us a branch is fine, and the affected spans live in the sibling rows, so
    ignoring it loses nothing. Text we simply could not parse is UNREADABLE, and ignoring THAT
    loses the one span the device might sit in.

    Collapsing the two -- which is what silently skipping every unparsed clause does -- is a false
    fix waiting to happen. Treating them both as blind instead would be safe but useless: 86 of the
    corpus's range rows say "Not affected", so every advisory carrying one would become
    permanently undecidable and the 71 inapplicable advisories would come straight back.
    """
    if not clause or not clause.strip():
        return DISPOSITION, None
    s = clause.strip()
    if _RP_NOT_AFFECTED.match(s):
        return DISPOSITION, None
    if _RP_MULTI_LETTER.search(s):
        return UNREADABLE, None          # a release line parse_version cannot represent
    bounds = parse_range_prose(s)
    if bounds:
        return RANGE, bounds
    return UNREADABLE, None


_RP_VERSION_TOKEN = re.compile(r"\d+(?:\.\d+)+[A-Za-z]?")


def _unaccounted_versions(clause: str, bounds: dict) -> list:
    """Version numbers in `clause` that `bounds` never used.

    A bound "covers" a token when either is a prefix of the other, so "4.28" (a train) accounts
    for the "4.28.x" it was read from, and "4.28.11M" accounts for itself.
    """
    used = [v for v in ((bounds or {}).get("introduced"), (bounds or {}).get("fixed"),
                        (bounds or {}).get("train")) if v]
    out = []
    for tok in _RP_VERSION_TOKEN.findall(clause or ""):
        if any(tok == u or tok.startswith(u) or u.startswith(tok) for u in used):
            continue
        out.append(tok)
    return out


# Words that make a parenthetical a SCOPE condition rather than a comment. "(ONIE)" and
# "(special below for FG6000F and 7000E models)" narrow which hardware the range applies to;
# "(Need to be authenticated to provoke a crash)" describes exploitability and narrows nothing.
_RP_SCOPE_WORD = re.compile(
    r"(?i)\b(?:only|unless|when|if|models?|series|platforms?|hardware|appliances?|"
    r"builds?|onie|requires?|configured|enabled|running)\b")
_RP_PAREN = re.compile(r"\(([^()]{2,})\)")


def _dropped_qualifiers(text: str) -> list:
    """Parentheticals `_strip_notes` will discard that carried something load-bearing.

    Stripping parentheticals is deliberate -- they defeated every anchored pattern, and twelve
    corpus strings carry one. But nothing recorded that a SCOPE CONDITION had been thrown away,
    which is the same silent-discard bug the version accounting invariant exists to stop, in a
    dimension it cannot see:

        "7.0.0 through 7.0.6 (special below for FG6000F and 7000E models)"
            -- a model-scoped advisory, applied fleet-wide once the note is gone
        "4.24.2.4F and below (ONIE)" / "... (non-ONIE)"
            -- Arista scoping the same train by boot mode
        "6.0.0 through 6.0.4 (4.18 and 4.17)"
            -- versions INSIDE the parens, stripped before the token check ever runs, so the
               accounting invariant is blind to them by construction

    Two things make a parenthetical load-bearing: a version number (information we lost), or a
    scope word (a condition we cannot evaluate). Either way the honest answer is that we do not
    know the full extent of the range.
    """
    out = []
    for note in _RP_PAREN.findall(text or ""):
        if _RP_VERSION_TOKEN.search(note) or _RP_SCOPE_WORD.search(note):
            out.append(note.strip())
    return out


def analyze_range_prose(texts) -> dict:
    """{"ranges": [...], "blind": bool} for a set of affected-range cells.

    `blind` is True when ANY clause could not be read. A blind result means the caller must NOT
    conclude "not affected" from `ranges`: the ranges are incomplete by an unknown amount.

    This is what "all versions" and "All EOS releases shipped prior to the date of this release"
    resolve to as well. They are not unreadable so much as unbounded -- no branch is named at all
    -- and the honest handling is identical: refuse to decide, keep the advisory.
    """
    ranges: list = []
    blind = False
    for t in texts or []:
        # A discarded parenthetical can carry a scope condition or a version, and stripping it
        # silently is how a model-scoped advisory becomes a fleet-wide one.
        if _dropped_qualifiers(t):
            blind = True
        clauses = split_range_clauses(t)
        if not clauses and (t or "").strip():
            blind = True
            continue
        # A bare run of versions with no separator word -- "4.18 4.19 4.18.10M 4.19.0F" -- reaches
        # here as one blob. Each token is its own release, so expand before classifying.
        expanded = []
        for c in clauses:
            if _RP_VERSION_LIST.match(c or ""):
                expanded.extend(c.split())
            else:
                expanded.append(c)
        clauses = expanded

        # "All versions in previous branches" names nothing on its own; it means everything OLDER
        # than the branches named beside it. Resolve it against the lowest version this cell does
        # name -- an exclusive bound there covers exactly what the vendor meant, and leaves a
        # device on a NEWER branch correctly outside. Unresolvable alone, so if the cell names no
        # other version it stays unreadable and the caller keeps the advisory.
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
                continue          # already resolved against the cell's floor, above
            kind, bounds = classify_range_clause(clause)
            if kind == RANGE:
                if bounds not in ranges:
                    ranges.append(bounds)
                # ACCOUNTING INVARIANT. A clause that parsed "successfully" while leaving a
                # version number of its own unaccounted for did not parse successfully -- it
                # parsed the first thing it recognised and threw the rest away.
                #
                # Every defect this parser has had was a silent discard, never a wrong
                # calculation, and each was found only because a human happened to read the CVE:
                #
                #   "...4.29.x train From 4.28.1F through 4.28.11M in the 4.28.x train"
                #        the split rule wants a DIGIT after "train", got the word "From", welded
                #        the clause on, and answered NOT AFFECTED for a 4.28.1F switch that
                #        Arista names explicitly. CVE-2024-5872. A false fix.
                #   "...4.24.x train. 4.23.4M and below..."      separator is a period
                #   "4.22.13M and below releases till 4.22.1F"   the lower bound vanishes
                #
                # So the parser now checks its own work: if the clause still holds a version the
                # parse never used, we do not know what that version meant, and `blind` is the
                # honest answer. This catches the shapes nobody has thought of yet, which is the
                # whole point -- a new advisory format degrades to "undecided" instead of to a
                # confident wrong answer.
                if _unaccounted_versions(clause, bounds):
                    blind = True
            elif kind == UNREADABLE:
                blind = True
    return {"ranges": ranges, "blind": blind}


def ranges_from_prose(texts) -> list:
    """Every readable range in `texts`, de-duplicated, order preserved.

    Convenience wrapper over `analyze_range_prose` that DISCARDS the blind flag. Safe only where
    the caller has no verdict to reach (tests, display). Anything deciding whether a device is
    affected must use `analyze_range_prose` and honour `blind`, or it can clear a device on the
    strength of the clauses that happened to parse.
    """
    return analyze_range_prose(texts)["ranges"]
