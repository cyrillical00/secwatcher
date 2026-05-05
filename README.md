# Secwatcher

Autonomous GitHub repository security scanner. Audits every repo under a single
GitHub account for credential leaks, Actions workflow misconfigurations, branch
protection gaps, and dependency vulnerabilities, then delivers severity-bucketed
Slack alerts and CLI reports. Runs on a GitHub Actions cron with zero manual
intervention after setup.

> **North star:** never expose a leaked credential. Catch it before it lands in
> a public repo, or alert immediately if it already did.

## What it covers

| Scanner | What it checks |
|---|---|
| `secrets` | trufflehog (verified) + gitleaks (custom rules for Okta SSWS, GCP service accounts, Anthropic `sk-ant`, Stripe `sk_live`, GitHub App PEMs) |
| `actions` | Workflow YAML: secret echoes, script injection from `github.event.*.body`, `write-all` permissions, mutable action refs, self-hosted runner labels, `pull_request_target` use |
| `branch_protection` | Required reviews, status checks, stale-review dismissal, force-push restriction on the default branch |
| `visibility` | Public repos that look like internal tools (no description, no topics, internal-sounding name) |
| `deps` | Dependabot alerts, CRITICAL and HIGH only |

## Quickstart

### 1. Install dependencies (local development)

```bash
uv sync --extra dev
```

You also need `gitleaks` and `trufflehog` on PATH for the secret scanner. The CI
workflow installs both; locally:

```bash
# macOS
brew install gitleaks trufflehog

# Linux
curl -sSL -o gitleaks.tar.gz \
  https://github.com/gitleaks/gitleaks/releases/download/v8.21.2/gitleaks_8.21.2_linux_x64.tar.gz
tar -xzf gitleaks.tar.gz -C /usr/local/bin gitleaks

curl -sSL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh \
  | sh -s -- -b /usr/local/bin
```

### 2. Create a GitHub App

Settings, Developer settings, GitHub Apps, New GitHub App.

Required scopes (read-only, least-privilege):

| Scope | Why |
|---|---|
| `Contents: Read` | Clone repos, fetch workflow files |
| `Metadata: Read` | List repos, read visibility, topics, default branch |
| `Administration: Read` | Read branch protection rules |
| `Security events: Read` | Read Dependabot alerts |

Do not grant any write scopes for v1. Issue creation is v2 territory and would
require `Issues: Write`.

After creating the App:
1. Generate a private key and download the PEM
2. Install the App on your account, then note the installation ID from the URL
3. Note the App ID from the App settings page

### 3. Create a Slack incoming webhook

Slack, Apps, Incoming Webhooks, Add to workspace, pick a channel. Copy the URL.

### 4. Set environment variables

Local: copy `.env.example` to `.env` and fill in.

CI: in the repo Settings, Secrets and variables, Actions, add:

- `REPOSENTRY_APP_ID`
- `REPOSENTRY_INSTALLATION_ID`
- `REPOSENTRY_APP_PRIVATE_KEY` (paste the full PEM contents)
- `REPOSENTRY_SLACK_WEBHOOK`

### 5. First run

```bash
# Full-history baseline scan across every non-fork repo
uv run secwatcher init

# Incremental scan since last run
uv run secwatcher scan

# Render the latest finding set
uv run secwatcher report --format table
uv run secwatcher report --format md --out reports/latest.md
```

## Suppression

Three tiers, evaluated in order:

1. **Global** `config/.github-scanner.yml` in this repo, fields:
   `ignore_paths`, `ignore_rules`, `ignore_repos`
2. **Per-repo** `.scanner-ignore` at the root of any target repo, same schema
3. **Per-finding** GitHub Issue with label `scanner:suppressed`. The issue body
   must contain the finding fingerprint emitted in CLI output.

A finding's fingerprint is `sha256(repo + file_path + rule_id + finding_type)`.

## Architecture

```
.github/workflows/
  scan.yml              # weekly cron + manual dispatch
  scan-self.yml         # dogfood: gitleaks against this repo on push/PR
config/
  .github-scanner.yml   # global suppression and scan config
  gitleaks.toml         # custom secret detection rules
secwatcher/
  cli.py                # Typer entry point: init / scan / report
  orchestrator.py       # rate-aware repo iteration, scanner dispatch
  auth.py               # GitHub App JWT and installation token cache
  rate_limiter.py       # x-ratelimit-remaining handling
  config.py             # env-driven Settings
  models.py             # Severity, Finding, ScanResult, fingerprint
  suppression.py        # 3-tier path/rule/fingerprint filter
  scanners/
    secrets.py          # trufflehog + gitleaks subprocess
    actions.py          # workflow YAML auditor
    branch_protection.py
    visibility.py
    deps.py             # Dependabot alerts
  delivery/
    slack.py            # Block Kit delivery; CRITICAL immediate, others digest
    cli.py              # rich tables and markdown export
```

## v1 status

This repo currently ships:

- Project skeleton, configuration, and packaging (`pyproject.toml`, `uv` lock target)
- Five scanner modules with full audit logic
- Slack and CLI delivery surfaces
- Suppression layer with 3-tier resolution
- GitHub Actions cron and dogfood workflows
- Custom gitleaks rule set for Okta, GCP, Anthropic, Stripe, GitHub App keys

Wiring (CLI commands to orchestrator, PyGithub repo enumeration with
rate-limited token-aware fetchers, persistent state for incremental `--since`
mode) is the next implementation pass.

## v2 (not built yet)

- FastAPI webhook receiver on a VPS for sub-minute push/PR detection
- Next.js dashboard with per-repo health scores and finding history
- GitHub Issue auto-creation with suggested remediation on write-access repos
- Parallel async scan workers with per-host rate limit budgets

## License

MIT.
