from qianshen.diffing import CATEGORY_ORDER, compute_diff
from qianshen.models import make_finding

def finding(rule_id: str, file: str = "0001_a.up.sql", detail: str = "d"):
    return make_finding(
        rule_id=rule_id, title=rule_id, severity="warning", category="test",
        file=file, version=1, direction="up", object_name="demo_x",
        evidence=f"evidence:{rule_id}", suggestion="review", detail=detail,
    )

def test_new_fixed_persistent_and_exempted_categories():
    persistent, new, exempted, gone = (
        finding("rule.persistent"), finding("rule.new"), finding("rule.exempt"), finding("rule.gone")
    )
    exempted.exempt("ex-001")
    previous = {"run_id": "qn-old", "findings": [
        {"fingerprint": persistent.fingerprint, "rule_id": persistent.rule_id,
         "severity": "warning", "file_rel": persistent.file, "status": "active"},
        {"fingerprint": gone.fingerprint, "rule_id": gone.rule_id,
         "severity": "warning", "file_rel": gone.file, "status": "active"},
    ]}
    diff = compute_diff([persistent, new, exempted], previous)
    assert diff["counts"] == {"new": 1, "fixed": 1, "persistent": 1, "exempted": 1}
    assert [item["category"] for item in diff["items"]] == list(CATEGORY_ORDER)
    assert diff["previous_run_id"] == "qn-old" and diff["basis"] == "fingerprint"
    assert next(item for item in diff["items"] if item["category"] == "fixed")["fingerprint"] == gone.fingerprint

def test_previously_active_item_now_exempted_is_not_reported_fixed():
    item = finding("rule.changed")
    previous = {"run_id": "qn-old", "findings": [
        {"fingerprint": item.fingerprint, "rule_id": item.rule_id,
         "severity": "warning", "file_rel": item.file, "status": "active"},
    ]}
    item.exempt("ex-002")
    diff = compute_diff([item], previous)
    assert diff["counts"]["fixed"] == 0
    assert diff["counts"]["exempted"] == 1

def test_without_previous_run_every_active_finding_is_new():
    first, second = finding("rule.a"), finding("rule.b", file="0002_b.up.sql")
    diff = compute_diff([first, second], None)
    assert diff["baseline_available"] is False
    assert diff["previous_run_id"] is None
    assert diff["counts"] == {"new": 2, "fixed": 0, "persistent": 0, "exempted": 0}
    assert [item["fingerprint"] for item in diff["items"]] == [
        first.fingerprint, second.fingerprint,
    ]
