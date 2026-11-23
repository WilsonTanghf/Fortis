"""
Build a 40-case vulnerability intelligence evaluation dataset for Fortis:

- 35 positive cases from a complete CISA KEV snapshot.
- 5 non-KEV negative candidates that must pass snapshot verification.

Outputs only:
    curated_kev_40.json
    negative_control_verification.json

Windows / PowerShell:
    python evaluation/datasets/build_curated_kev_40.py \
        --input official_cisa.json \
        --output-dir evaluation/datasets/curated_kev_40

Uses only the Python standard library.
"""

import argparse
import hashlib
import json
import random
import re
import sys
from collections import Counter
from datetime import date, datetime, timezone
from pathlib import Path


SEED = 40
POSITIVE_COUNT = 35
NEGATIVE_COUNT = 5

CISA_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)

QUOTAS = {
    "RCE": 6,
    "Auth_Bypass": 6,
    "Access_PrivEsc": 5,
    "SQL_Injection": 3,
    "OS_Cmd_Injection": 3,
    "Path_Traversal": 3,
    "SSRF": 2,
    "Unrestricted_Upload": 2,
    "DoS": 2,
    "InfoLeak_Crypto": 2,
    "Logging_Monitoring": 1,
}

# Real CVE candidates. Their non-KEV status must be verified against
# the complete supplied snapshot.
NEGATIVE_CANDIDATES = [
    {
        "cve_id": "CVE-2024-3094",
        "vendor": "XZ Utils",
        "product": "XZ Utils",
        "reference": "https://www.cve.org/CVERecord?id=CVE-2024-3094",
    },
    {
        "cve_id": "CVE-2023-38545",
        "vendor": "curl",
        "product": "curl / libcurl",
        "reference": "https://curl.se/docs/CVE-2023-38545.html",
    },
    {
        "cve_id": "CVE-2021-45105",
        "vendor": "Apache",
        "product": "Log4j",
        "reference": "https://www.cve.org/CVERecord?id=CVE-2021-45105",
    },
    {
        "cve_id": "CVE-2022-3602",
        "vendor": "OpenSSL",
        "product": "OpenSSL",
        "reference": "https://www.cve.org/CVERecord?id=CVE-2022-3602",
    },
    {
        "cve_id": "CVE-2023-20593",
        "vendor": "AMD",
        "product": "Affected AMD Zen 2 processors",
        "reference": "https://www.cve.org/CVERecord?id=CVE-2023-20593",
    },
]

# These categories are sampling heuristics, not manually verified
# gold-standard labels.
CWE_MAP = {
    "CWE-94": "RCE",
    "CWE-287": "Auth_Bypass",
    "CWE-288": "Auth_Bypass",
    "CWE-306": "Auth_Bypass",
    "CWE-269": "Access_PrivEsc",
    "CWE-284": "Access_PrivEsc",
    "CWE-862": "Access_PrivEsc",
    "CWE-863": "Access_PrivEsc",
    "CWE-89": "SQL_Injection",
    "CWE-77": "OS_Cmd_Injection",
    "CWE-78": "OS_Cmd_Injection",
    "CWE-22": "Path_Traversal",
    "CWE-23": "Path_Traversal",
    "CWE-73": "Path_Traversal",
    "CWE-918": "SSRF",
    "CWE-434": "Unrestricted_Upload",
    "CWE-400": "DoS",
    "CWE-476": "DoS",
    "CWE-200": "InfoLeak_Crypto",
    "CWE-327": "InfoLeak_Crypto",
    "CWE-778": "Logging_Monitoring",
    "CWE-532": "Logging_Monitoring",
}

KEYWORDS = {
    "RCE": [
        "remote code execution",
        "execute arbitrary code",
        "arbitrary code execution",
        "execution of arbitrary code",
        "code injection",
    ],
    "Auth_Bypass": [
        "authentication bypass",
        "bypass authentication",
        "improper authentication",
        "missing authentication",
    ],
    "Access_PrivEsc": [
        "privilege escalation",
        "elevation of privilege",
        "escalation of privilege",
        "improper authorization",
        "missing authorization",
    ],
    "SQL_Injection": ["sql injection"],
    "OS_Cmd_Injection": ["command injection"],
    "Path_Traversal": ["path traversal", "directory traversal"],
    "SSRF": [
        "server-side request forgery",
        "server side request forgery",
        "ssrf",
    ],
    "Unrestricted_Upload": [
        "unrestricted upload",
        "arbitrary file upload",
        "upload of a dangerous",
    ],
    "DoS": ["denial of service", "denial-of-service"],
    "InfoLeak_Crypto": [
        "information disclosure",
        "information exposure",
        "sensitive information",
        "weak cryptography",
    ],
    "Logging_Monitoring": [
        "insufficient logging",
        "sensitive information into log",
        "sensitive information in log",
    ],
}


def save_json(path, data):
    path.write_text(
        json.dumps(data, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def load_snapshot(path):
    raw = path.read_bytes()
    feed = json.loads(raw.decode("utf-8-sig"))

    if not isinstance(feed, dict):
        raise ValueError("The input JSON must contain an object.")

    entries = feed.get("vulnerabilities")

    if not isinstance(entries, list) or not entries:
        raise ValueError("No valid vulnerabilities list was found.")

    if type(feed.get("count")) is not int:
        raise ValueError("The catalog count must be an integer.")

    if feed["count"] != len(entries):
        raise ValueError(
            f"Record count mismatch: declared={feed['count']}, "
            f"actual={len(entries)}. Use the complete snapshot."
        )

    for field in ("catalogVersion", "dateReleased"):
        if not isinstance(feed.get(field), str) or not feed[field]:
            raise ValueError(f"Missing or invalid {field}.")

    seen = set()

    for entry in entries:
        if not isinstance(entry, dict):
            raise ValueError("Each vulnerability record must be an object.")

        cve_id = entry.get("cveID")

        if (
            not isinstance(cve_id, str)
            or not re.fullmatch(r"CVE-\d{4}-\d{4,}", cve_id)
        ):
            raise ValueError(f"Invalid CVE ID: {cve_id!r}")

        if cve_id in seen:
            raise ValueError(f"Duplicate CVE ID: {cve_id}")

        seen.add(cve_id)

        for field in (
            "vendorProject",
            "product",
            "vulnerabilityName",
            "shortDescription",
            "requiredAction",
        ):
            if not isinstance(entry.get(field), str):
                raise ValueError(
                    f"Missing or invalid {field} for {cve_id}."
                )

        for field in ("dateAdded", "dueDate"):
            value = entry.get(field)

            if not isinstance(value, str):
                raise ValueError(
                    f"Missing or invalid {field} for {cve_id}."
                )

            try:
                date.fromisoformat(value)
            except ValueError as exc:
                raise ValueError(
                    f"Invalid {field} date format for {cve_id}."
                ) from exc

        cwes = entry.get("cwes", [])

        if not isinstance(cwes, list) or not all(
            isinstance(cwe, str) for cwe in cwes
        ):
            raise ValueError(
                f"The cwes field for {cve_id} must be a list of strings."
            )

    return feed, entries, hashlib.sha256(raw).hexdigest()


def classify(entry):
    evidence = {}

    for cwe in entry.get("cwes", []):
        category = CWE_MAP.get(cwe)

        if category:
            evidence.setdefault(category, []).append(cwe)

    text = (
        entry["vulnerabilityName"] + " " + entry["shortDescription"]
    ).lower()

    for category, keywords in KEYWORDS.items():
        for keyword in keywords:
            if keyword in text:
                evidence.setdefault(category, []).append(keyword)

    return evidence


def select_positives(entries, seed, strict):
    if sum(QUOTAS.values()) != POSITIVE_COUNT:
        raise ValueError("QUOTAS must add up to 35.")

    pool = sorted(entries, key=lambda entry: entry["cveID"])
    random.Random(seed).shuffle(pool)

    evidence = {
        entry["cveID"]: classify(entry)
        for entry in pool
    }

    candidates = {
        category: [
            entry
            for entry in pool
            if category in evidence[entry["cveID"]]
        ]
        for category in QUOTAS
    }

    # Match CVEs to quota slots, allowing reassignment when a CVE
    # qualifies for several categories.
    order = sorted(
        QUOTAS,
        key=lambda category: (
            len(candidates[category]) / QUOTAS[category],
            category,
        ),
    )

    slots = [
        (category, number)
        for category in order
        for number in range(QUOTAS[category])
    ]

    owner = {}
    matched = {}

    def assign(slot, visited):
        for entry in candidates[slot[0]]:
            cve_id = entry["cveID"]

            if cve_id in visited:
                continue

            visited.add(cve_id)
            previous = owner.get(cve_id)

            if previous is None or assign(previous, visited):
                owner[cve_id] = slot
                matched[slot] = entry
                return True

        return False

    for slot in slots:
        assign(slot, set())

    selected = [
        (matched[slot], slot[0])
        for slot in slots
        if slot in matched
    ]

    counts = Counter(category for _, category in selected)

    deficits = {
        category: quota - counts[category]
        for category, quota in QUOTAS.items()
        if counts[category] < quota
    }

    if strict and deficits:
        raise RuntimeError(
            "The following category quotas could not be filled: "
            + json.dumps(deficits, ensure_ascii=False)
        )

    used = {entry["cveID"] for entry, _ in selected}

    for entry in pool:
        if len(selected) == POSITIVE_COUNT:
            break

        if entry["cveID"] not in used:
            selected.append((entry, "General_Supplement"))
            used.add(entry["cveID"])

    if len(selected) != POSITIVE_COUNT:
        raise RuntimeError(
            "The input does not contain enough records "
            "to select 35 unique KEV cases."
        )

    summary = {
        "target_quotas": QUOTAS,
        "actual_sampling_categories": dict(
            Counter(category for _, category in selected)
        ),
        "quota_deficits": deficits,
        "classification_note": (
            "CWE and keyword categories are sampling heuristics "
            "and have not been manually validated."
        ),
    }

    cases = []

    for entry, category in selected:
        cve_id = entry["cveID"]

        cases.append({
            "case_type": "positive_kev",
            "cve_id": cve_id,
            "vendor": entry["vendorProject"],
            "product": entry["product"],
            "sampling_category": category,
            "classification_evidence": evidence[cve_id],
            "source_record": entry,
            "expected": {
                "kev_listed": True,
                "date_added": entry["dateAdded"],
                "due_date": entry["dueDate"],
                "ransomware_use": entry.get(
                    "knownRansomwareCampaignUse"
                ),
                "forensic_triage": entry.get("forensicTriage"),
                "cwes": entry.get("cwes", []),
            },
            "evaluation_questions": [
                f"Is {cve_id} listed in the supplied KEV snapshot?",
                f"What KEV remediation due date is given for {cve_id}?",
                (
                    f"What ransomware campaign use status "
                    f"is reported for {cve_id}?"
                ),
                (
                    f"What forensicTriage value, if any, "
                    f"is provided for {cve_id}?"
                ),
                f"What required action is specified for {cve_id}?",
            ],
        })

    return cases, summary


def build_negatives(entries):
    kev_ids = {entry["cveID"] for entry in entries}
    ids = [item["cve_id"] for item in NEGATIVE_CANDIDATES]

    if len(ids) != NEGATIVE_COUNT or len(set(ids)) != NEGATIVE_COUNT:
        raise ValueError(
            "Exactly five unique negative-control candidates are required."
        )

    conflicts = sorted(set(ids) & kev_ids)

    if conflicts:
        raise RuntimeError(
            "Negative-control verification failed. "
            "The following CVEs are present in the supplied KEV snapshot: "
            + ", ".join(conflicts)
            + ". They cannot be labelled as non-KEV controls."
        )

    cases = []

    for item in NEGATIVE_CANDIDATES:
        cve_id = item["cve_id"]

        cases.append({
            "case_type": "negative_non_kev",
            "cve_id": cve_id,
            "vendor": item["vendor"],
            "product": item["product"],
            "sampling_category": "Negative_Control",
            "existence_reference": item["reference"],
            "source_record": None,
            "expected": {
                "kev_listed": False,
                "date_added": None,
                "due_date": None,
                "ransomware_use": None,
                "forensic_triage": None,
                "cwes": None,
            },
            "evaluation_questions": [
                f"Is {cve_id} listed in the supplied KEV snapshot?",
                (
                    f"Does this KEV snapshot provide a remediation "
                    f"due date for {cve_id}?"
                ),
                (
                    f"Can absence of {cve_id} from KEV prove "
                    "that it has never been exploited?"
                ),
            ],
            "answer_guidance": [
                "Not listed in this KEV snapshot.",
                "No KEV remediation due date is provided.",
                "Absence from KEV does not prove no exploitation.",
                "Do not infer no ransomware risk or no need to patch.",
            ],
        })

    return cases


def main(argv=None):
    parser = argparse.ArgumentParser(
        description=(
            "Build a Fortis evaluation dataset containing "
            "35 KEV and five non-KEV cases."
        )
    )
    parser.add_argument("--input", default="official_cisa.json")
    parser.add_argument(
        "--output-dir",
        default="evaluation/datasets/curated_kev_40",
    )
    parser.add_argument("--seed", type=int, default=SEED)
    parser.add_argument("--strict-quotas", action="store_true")

    # Ignore automatically injected kernel arguments when the complete
    # script is executed directly inside a notebook cell.
    if argv is None and "ipykernel" in sys.modules:
        argv = []

    args = parser.parse_args(argv)

    input_path = Path(args.input)
    output_dir = Path(args.output_dir)

    if not input_path.is_file():
        raise FileNotFoundError(
            f"Input file not found: {input_path}. "
            "Prepare the complete official_cisa.json snapshot first."
        )

    feed, entries, snapshot_hash = load_snapshot(input_path)

    # Complete all checks before writing output files.
    negatives = build_negatives(entries)
    positives, sampling = select_positives(
        entries,
        args.seed,
        args.strict_quotas,
    )

    cases = positives + negatives
    ids = [case["cve_id"] for case in cases]

    if len(cases) != 40 or len(set(ids)) != 40:
        raise RuntimeError(
            "The dataset must contain exactly 40 unique CVE IDs."
        )

    generated_at = datetime.now(timezone.utc).isoformat()

    snapshot = {
        "catalog_url": CISA_URL,
        "catalog_version": feed["catalogVersion"],
        "catalog_release": feed["dateReleased"],
        "snapshot_entry_count": len(entries),
        "snapshot_sha256": snapshot_hash,
    }

    dataset = {
        "metadata": {
            "dataset_name": "Fortis curated KEV evaluation dataset",
            "schema_version": "2.0",
            "generated_at_utc": generated_at,
            "seed": args.seed,
            **snapshot,
            "positive_count": len(positives),
            "negative_count": len(negatives),
            "total_count": len(cases),
            "sampling": sampling,
            "limitations": [
                (
                    "Negative labels apply only to the complete "
                    "KEV snapshot supplied for this run."
                ),
                (
                    "Absence from KEV does not imply no exploitation, "
                    "low risk, or no need to patch."
                ),
                (
                    "Null means the snapshot provides no value "
                    "for that field; it does not mean confirmed No."
                ),
                (
                    "Categories are sampling heuristics, "
                    "not framework-mapping gold-standard labels."
                ),
                (
                    "Negative cases are purposefully selected "
                    "and do not represent all non-KEV vulnerabilities."
                ),
                (
                    "Reference links are provided for manual review; "
                    "the script does not verify CVEs online."
                ),
                (
                    "SHA-256 identifies the input file but does not "
                    "independently authenticate its source."
                ),
                (
                    "This script builds a dataset. It does not "
                    "run Fortis or evaluate model performance."
                ),
            ],
        },
        "cases": cases,
    }

    verification = {
        "checked_at_utc": generated_at,
        **snapshot,
        "method": (
            "Exact CVE ID absence check against all snapshot entries"
        ),
        "all_negative_candidates_absent": True,
        "results": [
            {
                "cve_id": item["cve_id"],
                "present_in_snapshot": False,
                "existence_reference": item["reference"],
            }
            for item in NEGATIVE_CANDIDATES
        ],
    }

    output_dir.mkdir(parents=True, exist_ok=True)

    dataset_path = output_dir / "curated_kev_40.json"
    verification_path = (
        output_dir / "negative_control_verification.json"
    )

    # Do not accidentally overwrite previously saved experiment results.
    existing = [
        str(path)
        for path in (dataset_path, verification_path)
        if path.exists()
    ]

    if existing:
        raise FileExistsError(
            "The following output files already exist. "
            "Choose a new --output-dir: "
            + ", ".join(existing)
        )

    save_json(dataset_path, dataset)
    save_json(verification_path, verification)

    print(f"Catalog version: {feed['catalogVersion']}")
    print(f"Snapshot entries: {len(entries)}")
    print(f"Positive cases: {len(positives)}")
    print(f"Negative cases: {len(negatives)}")
    print(f"Total unique cases: {len(cases)}")
    print(f"Seed: {args.seed}")
    print(f"SHA-256: {snapshot_hash}")
    print(f"Dataset: {dataset_path.resolve()}")
    print(f"Verification: {verification_path.resolve()}")
    print(
        "Category counts:",
        json.dumps(
            sampling["actual_sampling_categories"],
            ensure_ascii=False,
        ),
    )

    if sampling["quota_deficits"]:
        print(
            "WARNING: Some category quotas could not be filled. "
            "General_Supplement cases were used. "
            "Report the actual distribution."
        )

    print(
        "Complete: all five negative candidates are absent "
        "from the supplied snapshot."
    )


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, RuntimeError, TypeError) as exc:
        raise SystemExit(f"[ERROR] {exc}") from exc