from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime

from secwatcher.scanners.actions import ActionsScanner


@dataclass
class FakeRepo:
    full_name: str = "x/y"
    default_branch: str = "main"
    fork: bool = False
    archived: bool = False
    private: bool = True
    has_push_access: bool = True
    description: str | None = None
    topics: list[str] = field(default_factory=list)
    clone_url: str = ""
    pushed_at: datetime = field(default_factory=lambda: datetime.now(UTC))


def _scan(workflow_yaml: str, *, path: str = ".github/workflows/ci.yml"):
    scanner = ActionsScanner(fetch_workflows=lambda repo: {path: workflow_yaml})
    return list(scanner.scan(FakeRepo()))


def test_write_all_permissions_flagged():
    yaml_doc = """
name: ci
on: push
permissions: write-all
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo hello
"""
    findings = _scan(yaml_doc)
    assert any(f.rule_id == "actions/write-all-permissions" for f in findings)


def test_pull_request_target_flagged():
    yaml_doc = """
on:
  pull_request_target:
    branches: [main]
jobs:
  x:
    runs-on: ubuntu-latest
    steps:
      - run: echo ok
"""
    findings = _scan(yaml_doc)
    assert any(f.rule_id == "actions/pull-request-target" for f in findings)


def test_secret_echo_flagged():
    yaml_doc = """
on: push
jobs:
  x:
    runs-on: ubuntu-latest
    steps:
      - name: leak
        run: echo "${{ secrets.MY_TOKEN }}"
"""
    findings = _scan(yaml_doc)
    assert any(f.rule_id == "actions/secret-echo" for f in findings)


def test_script_injection_flagged():
    yaml_doc = """
on: pull_request
jobs:
  x:
    runs-on: ubuntu-latest
    steps:
      - run: echo "PR was ${{ github.event.pull_request.body }}"
"""
    findings = _scan(yaml_doc)
    assert any(f.rule_id == "actions/script-injection" for f in findings)


def test_self_hosted_runner_flagged():
    yaml_doc = """
on: push
jobs:
  x:
    runs-on: self-hosted
    steps:
      - run: ./build.sh
"""
    findings = _scan(yaml_doc)
    assert any(f.rule_id == "actions/self-hosted-runner" for f in findings)


def test_mutable_action_ref_flagged():
    yaml_doc = """
on: push
jobs:
  x:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
"""
    findings = _scan(yaml_doc)
    assert any(f.rule_id == "actions/mutable-action-ref" for f in findings)


def test_sha_pinned_action_not_flagged():
    yaml_doc = """
on: push
jobs:
  x:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
"""
    findings = _scan(yaml_doc)
    assert not any(f.rule_id == "actions/mutable-action-ref" for f in findings)


def test_clean_workflow_no_findings():
    yaml_doc = """
on: push
permissions:
  contents: read
jobs:
  x:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
      - name: build
        env:
          BODY: ${{ github.event.pull_request.body }}
        run: echo "$BODY" | wc -c
"""
    findings = _scan(yaml_doc)
    assert findings == []
