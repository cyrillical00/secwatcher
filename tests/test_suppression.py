from secwatcher.models import Finding, FindingType, Severity
from secwatcher.suppression import SuppressionRules


def _finding(file_path: str = "src/app.py", rule_id: str = "gitleaks/test") -> Finding:
    return Finding(
        repo="x/y",
        finding_type=FindingType.SECRET,
        severity=Severity.CRITICAL,
        rule_id=rule_id,
        title="t",
        file_path=file_path,
    )


def test_path_glob_suppresses():
    rules = SuppressionRules.from_yaml(
        "ignore_paths:\n  - 'tests/**'\n"
    )
    assert rules.is_suppressed(_finding("tests/test_x.py"))
    assert not rules.is_suppressed(_finding("src/app.py"))


def test_rule_id_suppresses():
    rules = SuppressionRules(rule_ids={"gitleaks/test"})
    assert rules.is_suppressed(_finding(rule_id="gitleaks/test"))
    assert not rules.is_suppressed(_finding(rule_id="gitleaks/other"))


def test_fingerprint_suppression_takes_priority():
    f = _finding()
    rules = SuppressionRules(suppressed_fingerprints={f.fingerprint})
    assert rules.is_suppressed(f)


def test_merge_combines_tiers():
    a = SuppressionRules(path_globs=["a/**"], rule_ids={"r1"})
    b = SuppressionRules(path_globs=["b/**"], rule_ids={"r2"})
    merged = a.merge(b)
    assert "a/**" in merged.path_globs and "b/**" in merged.path_globs
    assert merged.rule_ids == {"r1", "r2"}
