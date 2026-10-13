"""CI/CD integration — GitHub Actions workflow generator for MoonMCP scans.

Generates ready-to-use GitHub Actions workflows that run MoonMCP-based security
scans on pull requests. Supports: PR diff-scope scanning, scheduled scans,
and manual triggers. Inspired by Strix's CI/CD integration.

Usage:
    workflow = generate_github_actions_workflow(
        target="./app",
        scan_mode="quick",
        scope_mode="diff",
        diff_base="origin/main",
    )
    # Save to .github/workflows/moonmcp-security.yml
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class CICDConfig:
    """Configuration for a CI/CD security scan."""
    target: str = "./"
    scan_mode: str = "standard"  # quick | standard | deep
    scope_mode: str = "full"  # full | diff
    diff_base: str = "origin/main"
    schedule: str = ""  # cron expression, empty = no schedule
    fail_on_severity: str = "high"  # critical | high | medium | low | info
    export_format: str = "sarif"  # sarif | json | markdown


def generate_github_actions_workflow(
    target: str = "./",
    scan_mode: str = "quick",
    scope_mode: str = "diff",
    diff_base: str = "origin/main",
    schedule: str = "",
    fail_on_severity: str = "high",
    export_format: str = "sarif",
) -> str:
    """Generate a GitHub Actions YAML workflow for MoonMCP security scanning.

    Args:
        target: Path to the application to scan (local path or URL).
        scan_mode: quick (PR review), standard (full scan), deep (exhaustive).
        scope_mode: full (entire codebase) or diff (only changed files).
        diff_base: Base branch for diff-scope (e.g. origin/main).
        schedule: Cron expression for scheduled scans (empty = PR-only).
        fail_on_severity: Minimum severity to fail the build.
        export_format: Output format (sarif for GitHub code scanning, json, markdown).

    Returns:
        YAML string for .github/workflows/moonmcp-security.yml
    """

    triggers = ["pull_request"]
    if schedule:
        triggers.insert(0, {"schedule": [{"cron": schedule}]})
    triggers.append("workflow_dispatch")

    # Build the triggers section
    trigger_lines = []
    for t in triggers:
        if isinstance(t, dict):
            for key, val in t.items():
                trigger_lines.append(f"  {key}:")
                for item in val:
                    if isinstance(item, dict):
                        for k2, v2 in item.items():
                            trigger_lines.append(f"    - {k2}: \"{v2}\"")
                    else:
                        trigger_lines.append(f"    - {item}")
        else:
            trigger_lines.append(f"  {t}:")

    triggers_yaml = "\n".join(trigger_lines)

    # Build scan steps
    diff_scope_args = ""
    if scope_mode == "diff":
        diff_scope_args = f"--scope-mode diff --diff-base {diff_base}"

    workflow = f"""name: MoonMCP Security Scan
on:
{triggers_yaml}

jobs:
  security-scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.12'

      - name: Install MoonMCP
        run: |
          pip install moonmcp

      - name: Run security scan
        env:
          MOONMCP_STATE_DIR: ${{{{ github.workspace }}}}/.moonmcp-state
        run: |
          moonmcp scan \\
            --target {target} \\
            --scan-mode {scan_mode} \\
            {diff_scope_args} \\
            --export {export_format} \\
            --fail-on {fail_on_severity} \\
            --output results.{export_format}

      - name: Upload SARIF results
        if: always() && export_format == 'sarif'
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif

      - name: Upload scan artifacts
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: moonmcp-results
          path: |
            results.{export_format}
            .moonmcp-state/
"""
    return workflow


def generate_gitlab_ci_pipeline(
    target: str = "./",
    scan_mode: str = "quick",
    fail_on_severity: str = "high",
) -> str:
    """Generate a GitLab CI pipeline for MoonMCP security scanning."""

    return f"""moonmcp-security:
  image: python:3.12-slim
  script:
    - pip install moonmcp
    - moonmcp scan --target {target} --scan-mode {scan_mode} --export json --fail-on {fail_on_severity}
  artifacts:
    paths:
      - results.json
      - .moonmcp-state/
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_PIPELINE_SOURCE == "schedule"
"""


# ─── MCP integration helpers ─────────────────────────────────────────────

CICD_TEMPLATES = {
    "github_pr": {
        "name": "GitHub Actions — PR Security Scan",
        "description": "Scan changed files on every pull request",
        "config": {"scan_mode": "quick", "scope_mode": "diff"},
    },
    "github_scheduled": {
        "name": "GitHub Actions — Scheduled Full Scan",
        "description": "Full security scan on schedule (e.g. nightly)",
        "config": {"scan_mode": "standard", "scope_mode": "full", "schedule": "0 2 * * *"},
    },
    "github_manual": {
        "name": "GitHub Actions — Manual Trigger",
        "description": "On-demand security scan via workflow_dispatch",
        "config": {"scan_mode": "deep", "scope_mode": "full"},
    },
    "gitlab_mr": {
        "name": "GitLab CI — MR Security Scan",
        "description": "Scan on merge request in GitLab CI",
        "config": {"scan_mode": "quick"},
    },
}