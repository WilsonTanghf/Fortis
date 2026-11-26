import json
from pathlib import Path


POSITIVE_CASE_INDEXES = [1, 15, 28]
NEGATIVE_CASE_INDEX = 3
QUESTIONS_PER_POSITIVE_CASE = 5
QUESTIONS_PER_NEGATIVE_CASE = 3
EXPECTED_QUESTION_COUNT = 18


def load_dataset(path):
    return json.loads(
        Path(path).read_text(encoding="utf-8")
    )


def select_cases(dataset):
    cases = dataset.get("cases", [])

    positive_cases = []
    negative_case = None

    for index in POSITIVE_CASE_INDEXES:
        case = cases[index - 1]

        if case.get("case_type") != "positive_kev":
            raise ValueError(
                f"Case {index} is not a positive KEV case."
            )

        positive_cases.append(case)

    negative_case = cases[NEGATIVE_CASE_INDEX - 1]

    if negative_case.get("case_type") != "negative_nonkev":
        raise ValueError(
            f"Case {NEGATIVE_CASE_INDEX} is not a negative control."
        )

    return positive_cases, negative_case


def build_questions(dataset):
    positive_cases, negative_case = select_cases(dataset)
    questions = []

    for case in positive_cases:
        cve_id = case["cve_id"]
        evaluation_questions = case["evaluation_questions"]
        expected = case["expected"]

        expected_answers = [
            expected.get("kev_listed"),
            expected.get("date_added"),
            expected.get("due_date"),
            expected.get("ransomware_use"),
            expected.get("required_action"),
        ]

        for index, question in enumerate(
            evaluation_questions[:QUESTIONS_PER_POSITIVE_CASE]
        ):
            questions.append({
                "case_type": "positive_kev",
                "cve_id": cve_id,
                "question_index": index,
                "question": question,
                "expected_answer": expected_answers[index],
            })

    cve_id = negative_case["cve_id"]
    evaluation_questions = negative_case["evaluation_questions"]
    guidance = negative_case["answer_guidance"]

    for index, question in enumerate(
        evaluation_questions[:QUESTIONS_PER_NEGATIVE_CASE]
    ):
        questions.append({
            "case_type": "negative_nonkev",
            "cve_id": cve_id,
            "question_index": index,
            "question": question,
            "expected_answer": guidance[index],
        })

    if len(questions) != EXPECTED_QUESTION_COUNT:
        raise ValueError(
            f"Expected {EXPECTED_QUESTION_COUNT} questions, "
            f"but found {len(questions)}."
        )

    return questions