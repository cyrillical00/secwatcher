#!/usr/bin/env python3
"""Pin GitHub Actions refs to commit SHAs.

Scans .github/workflows/*.yml in a target directory for `uses: owner/repo@ref`
declarations. For any ref that isn't already a 40-char SHA, resolves the ref
to a commit SHA via the GitHub API and rewrites the line to:

    uses: owner/repo@<sha>  # <original ref>

This addresses the `actions/mutable-action-ref` finding from secwatcher: a
floating tag like `@v4` can be silently re-pointed to malicious code by an
upstream compromise (see the tj-actions/changed-files incident). A pinned
SHA is immutable.

Authenticates via the local `gh` CLI; run `gh auth status` first if API
calls fail. Stdlib-only otherwise.

Usage:
    python scripts/pin_actions.py [PATH] [--write]

Defaults to the current directory and dry-run mode. Pass --write to apply
changes in place.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

USES_RE = re.compile(
    r'^(?P<prefix>\s*-?\s*uses:\s*)'
    r'(?P<action>[^\s@#]+)@(?P<ref>\S+?)'
    r'(?P<trail>\s*(#.*)?)?$'
)
SHA_RE = re.compile(r'^[0-9a-f]{40}$')


def gh_api(path: str) -> dict | None:
    """Call `gh api <path>` and return parsed JSON, or None on failure."""
    proc = subprocess.run(
        ['gh', 'api', path],
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        return None
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError:
        return None


def resolve_sha(
    action: str,
    ref: str,
    cache: dict[tuple[str, str], str | None],
) -> str | None:
    """Resolve owner/repo@ref to a commit SHA. Cached per (action, ref)."""
    key = (action, ref)
    if key in cache:
        return cache[key]
    # Try as a tag, then as a branch, then as a raw commit.
    for path in (
        f'repos/{action}/git/ref/tags/{ref}',
        f'repos/{action}/git/ref/heads/{ref}',
        f'repos/{action}/commits/{ref}',
    ):
        data = gh_api(path)
        if not data:
            continue
        sha = data.get('object', {}).get('sha') or data.get('sha')
        # Annotated tags wrap the commit one level deeper.
        if sha and data.get('object', {}).get('type') == 'tag':
            tag_data = gh_api(f'repos/{action}/git/tags/{sha}')
            if tag_data and tag_data.get('object', {}).get('sha'):
                sha = tag_data['object']['sha']
        if sha and SHA_RE.match(sha):
            cache[key] = sha
            return sha
    cache[key] = None
    return None


def process_workflow(
    path: Path,
    cache: dict,
    write: bool,
) -> list[str]:
    """Return a list of human-readable change descriptions for this file."""
    text = path.read_text(encoding='utf-8')
    changes: list[str] = []
    out_lines: list[str] = []
    for line in text.splitlines(keepends=True):
        stripped = line.rstrip('\r\n')
        m = USES_RE.match(stripped)
        if not m:
            out_lines.append(line)
            continue
        prefix = m.group('prefix')
        action = m.group('action')
        ref = m.group('ref')
        # Skip local composite actions and docker:// references.
        if action.startswith('./') or action.startswith('docker:'):
            out_lines.append(line)
            continue
        if SHA_RE.match(ref):
            out_lines.append(line)
            continue
        sha = resolve_sha(action, ref, cache)
        if not sha:
            changes.append(f'  ! could not resolve {action}@{ref}')
            out_lines.append(line)
            continue
        eol = line[len(stripped):] or '\n'
        out_lines.append(f'{prefix}{action}@{sha}  # {ref}{eol}')
        changes.append(f'  {action}@{ref} -> {sha[:12]}')
    if write and any(not c.startswith('  !') for c in changes):
        path.write_text(''.join(out_lines), encoding='utf-8')
    return changes


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        'path', nargs='?', default='.',
        help='repo root (default: cwd)',
    )
    ap.add_argument(
        '--write', action='store_true',
        help='apply changes (default: dry-run)',
    )
    args = ap.parse_args()

    root = Path(args.path).resolve()
    workflows_dir = root / '.github' / 'workflows'
    if not workflows_dir.is_dir():
        print(f'No workflows dir at {workflows_dir}', file=sys.stderr)
        return 1

    cache: dict = {}
    any_changes = False
    files = sorted(workflows_dir.glob('*.yml')) + sorted(workflows_dir.glob('*.yaml'))
    for wf in files:
        changes = process_workflow(wf, cache, args.write)
        if changes:
            any_changes = True
            label = 'wrote' if args.write else 'would change'
            print(f'{label} {wf.relative_to(root)}:')
            for c in changes:
                print(c)
    if not any_changes:
        print('Nothing to pin.')
    elif not args.write:
        print('\nDry run, no files modified. Re-run with --write to apply.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
