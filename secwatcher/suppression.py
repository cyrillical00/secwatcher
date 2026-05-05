from __future__ import annotations

import fnmatch
import logging
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from secwatcher.models import Finding

logger = logging.getLogger(__name__)


@dataclass
class SuppressionRules:
    """Three-tier suppression: global YAML, per-repo file, GitHub Issue label.

    Issue-label suppressions are resolved by the orchestrator at runtime since they
    require API access; this class handles the static path/rule globs and exposes
    a hook for the third tier via `suppressed_fingerprints`.
    """

    path_globs: list[str] = field(default_factory=list)
    rule_ids: set[str] = field(default_factory=set)
    suppressed_fingerprints: set[str] = field(default_factory=set)

    @classmethod
    def from_yaml(cls, source: str | Path | None) -> SuppressionRules:
        if source is None:
            return cls()
        if isinstance(source, Path):
            if not source.exists():
                return cls()
            text = source.read_text(encoding="utf-8")
        else:
            text = source
        data = yaml.safe_load(text) or {}
        return cls(
            path_globs=list(data.get("ignore_paths", []) or []),
            rule_ids=set(data.get("ignore_rules", []) or []),
        )

    def merge(self, other: SuppressionRules) -> SuppressionRules:
        return SuppressionRules(
            path_globs=[*self.path_globs, *other.path_globs],
            rule_ids=self.rule_ids | other.rule_ids,
            suppressed_fingerprints=self.suppressed_fingerprints | other.suppressed_fingerprints,
        )

    def is_suppressed(self, finding: Finding) -> bool:
        if finding.fingerprint in self.suppressed_fingerprints:
            return True
        if finding.rule_id in self.rule_ids:
            return True
        if finding.file_path:
            for pattern in self.path_globs:
                if fnmatch.fnmatch(finding.file_path, pattern):
                    return True
        return False
