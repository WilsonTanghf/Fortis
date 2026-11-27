import re
from datetime import datetime

NOT_LISTED = re.compile(
    r"\bnot (?:currently |presently )?(?:listed|in the|present|included|found)"
    r"|\b(?:isn't|is not|aren't|are not) (?:listed|in the|included)"
    r"|\bno (?:kev )?(?:entry|record|match)",
    re.IGNORECASE,
)
LISTED = re.compile(
    r"\byes\b|\b(?:is|are) listed\b|\bis in the\b|\blisted in\b",
    re.IGNORECASE,
)
NO_DUE_DATE = re.compile(
    r"\bno\b[^.]{0,60}due date|\bno remediation\b"
    r"|\bnot (?:provide|provided|list|listed|include|included|contain|specif)"
    r"|\b(?:does not|doesn't) (?:provide|have|include|contain|specify)"
    r"|\bn/a\b|\bnone\b",
    re.IGNORECASE,
)
ABSENCE_OK = re.compile(
    r"\b(?:no|cannot|can't|can not|not)\b"
    r"|\bdoes not prove\b|\bdoesn't prove\b",
    re.IGNORECASE,
)
ISO_DATE = re.compile(r"\b\d{4}-\d{2}-\d{2}\b")
STOPWORDS = {
    "the", "and", "per", "for", "are", "that", "with", "from", "this",
    "any", "all", "use", "not", "its", "who", "has", "had", "may", "can",
}


def _clean(text):
    return re.sub(r"\s+", " ", (text or "").replace(",", " ")).lower().strip()


def _date_variants(iso):
    d = datetime.strptime(iso, "%Y-%m-%d")
    variants = {iso, d.strftime("%Y/%m/%d")}
    for month in (d.strftime("%B"), d.strftime("%b")):
        variants.add(f"{month} {d.day} {d.year}")
        variants.add(f"{d.day} {month} {d.year}")
    return {_clean(v) for v in variants}


def _result(passed, method, needs_review=False, detail=""):
    return {
        "passed": bool(passed),
        "method": method,
        "needs_review": needs_review,
        "detail": detail,
    }


def _check_listed(question, reply):
    says_not = bool(NOT_LISTED.search(reply))
    says_yes = bool(LISTED.search(reply)) and not says_not

    if question["case_type"] == "negative_nonkev":
        return _result(says_not and not says_yes, "listed_negative")
    return _result(says_yes, "listed_positive")


def _check_due_date(question, reply):
    if question["case_type"] == "negative_nonkev":
        has_date = bool(ISO_DATE.search(reply))
        passed = bool(NO_DUE_DATE.search(reply)) and not has_date
        return _result(passed, "no_due_date_negative", needs_review=True)

    expected = question["expected_answer"]
    if not expected:
        return _result(False, "due_date", True, "No expected date.")
    found = any(v in _clean(reply) for v in _date_variants(expected))
    return _result(found, "due_date_exact", detail=f"expected {expected}")


def _check_ransomware(question, reply):
    expected = str(question["expected_answer"]).strip().lower()
    text = reply.lower()
    has_unknown = bool(re.search(r"\bunknown\b", text))
    has_known = bool(re.search(r"\bknown\b", text))

    if expected == "unknown":
        return _result(has_unknown, "ransomware_unknown")
    if expected == "known":
        return _result(
            has_known and not has_unknown, "ransomware_known",
            needs_review=True,
        )
    return _result(False, "ransomware", True, f"Unexpected value {expected}")


def _check_forensic(question, reply):
    expected = str(question["expected_answer"]).strip().lower()
    text = reply.lower()
    has_yes = bool(re.search(r"\byes\b|\brequired\b", text))
    has_no = bool(re.search(r"\bno\b|\bnot required\b|\bnone\b", text))

    if expected == "yes":
        return _result(has_yes and not has_no, "forensic_yes", True)
    if expected == "no":
        return _result(has_no and not has_yes, "forensic_no", True)
    return _result(False, "forensic", True, f"Unexpected value {expected}")


def _tokens(text):
    words = re.findall(r"[a-z0-9\-]{3,}", (text or "").lower())
    return {w for w in words if w not in STOPWORDS}


def _check_required_action(question, reply):
    expected_tokens = _tokens(question["expected_answer"])
    if not expected_tokens:
        return _result(False, "required_action", True, "No expected action.")
    overlap = len(expected_tokens & _tokens(reply)) / len(expected_tokens)
    return _result(
        overlap >= 0.6,
        "required_action_overlap",
        needs_review=True,
        detail=f"token overlap {overlap:.2f}",
    )


def _check_absence(question, reply):
    contradicts = bool(re.search(r"\byes\b", reply, re.IGNORECASE))
    passed = bool(ABSENCE_OK.search(reply)) and not contradicts
    return _result(passed, "absence_not_proof", needs_review=True)


CHECKS = {
    "listed": _check_listed,
    "due_date": _check_due_date,
    "ransomware": _check_ransomware,
    "forensic_triage": _check_forensic,
    "required_action": _check_required_action,
    "absence": _check_absence,
}


def evaluate_answer(question, reply):
    check = CHECKS.get(question["check_type"])
    if check is None:
        return _result(False, "unknown", True, "Unknown check type.")
    return check(question, reply or "")


def summarise(records):
    def rate(items):
        total = len(items)
        passed = sum(1 for r in items if r["passed"])
        return {
            "total": total,
            "passed": passed,
            "accuracy": round(passed / total, 4) if total else None,
        }

    summary = {
        "overall": rate(records),
        "errors": sum(1 for r in records if r.get("error")),
        "needs_review": sum(1 for r in records if r.get("needs_review")),
        "by_case_type": {},
        "by_check_type": {},
    }
    for key, group in (
        ("by_case_type", "case_type"),
        ("by_check_type", "check_type"),
    ):
        for value in sorted({r[group] for r in records}):
            summary[key][value] = rate(
                [r for r in records if r[group] == value]
            )
    return summary
