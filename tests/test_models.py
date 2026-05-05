from secwatcher.models import Finding, FindingType, Severity


def test_severity_rank_ordering():
    assert Severity.CRITICAL.rank > Severity.HIGH.rank > Severity.MEDIUM.rank
    assert Severity.MEDIUM.rank > Severity.LOW.rank > Severity.INFO.rank


def test_finding_fingerprint_is_stable():
    a = Finding(
        repo="cyrillical00/secwatcher",
        finding_type=FindingType.SECRET,
        severity=Severity.CRITICAL,
        rule_id="gitleaks/okta-api-token",
        title="Test",
        file_path="src/foo.py",
    )
    b = Finding(
        repo="cyrillical00/secwatcher",
        finding_type=FindingType.SECRET,
        severity=Severity.HIGH,  # severity does not contribute
        rule_id="gitleaks/okta-api-token",
        title="Different title",
        file_path="src/foo.py",
    )
    assert a.fingerprint == b.fingerprint


def test_finding_fingerprint_changes_on_path():
    base = dict(
        repo="x/y",
        finding_type=FindingType.SECRET,
        severity=Severity.CRITICAL,
        rule_id="rule",
        title="t",
    )
    a = Finding(**base, file_path="a.py")
    b = Finding(**base, file_path="b.py")
    assert a.fingerprint != b.fingerprint
