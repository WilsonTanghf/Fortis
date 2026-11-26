import json
from pathlib import Path

SUBSET_POSITIVE_POSITIONS = [1, 15, 28]
SUBSET_NEGATIVE_POSITION = 3

POSITIVE_CHECKS = [
    "listed",
    "due_date",
    "ransomware",
    "forensic_triage",
    "required_action",
]
NEGATIVE_CHECKS = ["listed", "due_date", "absence"]

EXPECTED_COUNTS = {"subset": 18, "full": 190}


def load_dataset(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def select_cases(dataset, mode="subset"):
    cases = dataset["cases"]

    if mode == "full":
        return cases
    if mode != "subset":
        raise ValueError(f"Unknown mode: {mode}")

    positives = [c for c in cases if c.get("case_type") == "positive_kev"]
    negatives = [c for c in cases if c.get("case_type") == "negative_nonkev"]

    selected = [positives[i - 1] for i in SUBSET_POSITIVE_POSITIONS]
    selected.append(negatives[SUBSET_NEGATIVE_POSITION - 1])
    return selected


def expected_for_positive(case):
    expected = case["expected"]
    source = case.get("source_record") or {}
    return [
        expected.get("kev_listed"),
        expected.get("due_date"),
        expected.get("ransomware_use"),
        expected.get("forensic_triage"),
        source.get("requiredAction"),
    ]


def questions_for_case(case):
    cve_id = case["cve_id"]
    case_type = case.get("case_type")
    prompts = case["evaluation_questions"]

    if case_type == "positive_kev":
        checks = POSITIVE_CHECKS
        answers = expected_for_positive(case)
    elif case_type == "negative_nonkev":
        checks = NEGATIVE_CHECKS
        answers = case["answer_guidance"][: len(NEGATIVE_CHECKS)]
    else:
        raise ValueError(f"{cve_id}: unknown case_type {case_type}")

    if len(prompts) < len(checks) or len(answers) < len(checks):
        raise ValueError(f"{cve_id}: not enough questions or answers.")

    return [
        {
            "question_id": f"{cve_id}-q{i + 1}",
            "case_type": case_type,
            "cve_id": cve_id,
            "question_index": i,
            "check_type": checks[i],
            "question": prompts[i],
            "expected_answer": answers[i],
        }
        for i in range(len(checks))
    ]


def build_questions(dataset, mode="subset"):
    questions = []
    for case in select_cases(dataset, mode):
        questions.extend(questions_for_case(case))

    expected_count = EXPECTED_COUNTS[mode]
    if len(questions) != expected_count:
        raise ValueError(
            f"Expected {expected_count} questions in {mode} mode, "
            f"found {len(questions)}."
        )
    return questions