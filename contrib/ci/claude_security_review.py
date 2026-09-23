#!/usr/bin/env python3
"""
GitHub Actions job: Claude Code security review for Electrum pull requests.

Runs Claude Code against the PR diff to detect critical security
vulnerabilities. Optionally posts findings as a GitHub PR comment.

Exit codes:
    0 -- PASS (no critical/high issues)
    1 -- FAIL (critical/high issues found)
    2 -- review could not run (infra error, logged as warning)

Environment variables:
    Required:
        CLAUDE_CODE_OAUTH_TOKEN  -- OAuth token from `claude setup-token` (MAX subscription)
    Optional:
        GITHUB_TOKEN             -- GitHub token for posting PR comments
    Set by the workflow:
        PR_NUMBER                -- PR number (empty if not a PR build)
        BASE_BRANCH              -- target branch of the PR
    Set by GitHub Actions runtime:
        GITHUB_REPOSITORY        -- e.g. "spesmilo/electrum"
        GITHUB_RUN_ID            -- current workflow run ID
        GITHUB_SERVER_URL        -- e.g. "https://github.com"
"""

import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROMPT_FILE = os.path.join(SCRIPT_DIR, "security_review_prompt.md")

MAX_DIFF_CHARS = 800_000
CLAUDE_TIMEOUT_SECONDS = 60 * 60
CLAUDE_MODEL = "claude-opus-5"
CLAUDE_EFFORT = "max"

VERDICT_PASS = "PASS"
VERDICT_FAIL = "FAIL"

# stream-json system events emitted when Claude Code switches to another model,
# e.g. after a refusal by the cyber safeguards
FALLBACK_EVENT_SUBTYPES = ("model_refusal_fallback", "model_fallback")
# model name of assistant messages generated locally by Claude Code, not by the API
SYNTHETIC_MODEL = "<synthetic>"


def git(*args: str) -> str:
    result = subprocess.run(
        ["git"] + list(args),
        capture_output=True, text=True, check=True,
    )
    return result.stdout


def fetch_base_branch(base: str) -> None:
    try:
        git("fetch", "origin", base, "--depth=1")
    except subprocess.CalledProcessError:
        git("fetch", "origin", base)
    # Shallow CI clones may lack the history needed for three-dot diff
    # (merge-base computation). Unshallow if the merge-base is unreachable.
    try:
        git("merge-base", f"origin/{base}", "HEAD")
    except subprocess.CalledProcessError:
        try:
            git("fetch", "--unshallow")
        except subprocess.CalledProcessError:
            pass  # already a full clone


def get_pr_diff(base: str) -> str:
    return git("diff", f"origin/{base}...HEAD")


def get_commit_messages(base: str) -> str:
    return git("log", f"origin/{base}..HEAD")


def changed_files_from_diff(diff: str) -> str:
    return "\n".join(
        m.group(1) for m in re.finditer(r"^diff --git a/.+ b/(.+)$", diff, re.MULTILINE)
    )


def read_system_prompt() -> str:
    with open(PROMPT_FILE) as f:
        return f.read()


def build_user_prompt(diff: str, changed_files: str, commit_messages: str) -> str:
    return (
        "Review the following PR diff according to the review "
        "guidelines in your system prompt.\n\n"
        f"## Changed files\n\n```\n{changed_files}\n```\n\n"
        f"## Commit messages\n\n```\n{commit_messages}\n```\n\n"
        f"## Diff\n\n```diff\n{diff}\n```"
    )


def run_claude(user_prompt: str, system_prompt: str) -> tuple[str, list[str]] | None:
    """Invoke Claude Code CLI in print mode. Returns (review text, model downgrades) or None on failure.

    Passes the prompt via stdin to avoid OS argument length limits (MAX_ARG_STRLEN).
    """
    cmd = [
        "claude",
        "-p",
        "--dangerously-skip-permissions",
        "--model", CLAUDE_MODEL,
        "--effort", CLAUDE_EFFORT,
        "--output-format", "stream-json",
        "--verbose",  # required by stream-json in print mode
        "--append-system-prompt", system_prompt,
    ]

    try:
        result = subprocess.run(
            cmd,
            input=user_prompt,
            capture_output=True,
            text=True,
            timeout=CLAUDE_TIMEOUT_SECONDS,
        )
    except FileNotFoundError:
        print("ERROR: 'claude' CLI not found. Is @anthropic-ai/claude-code installed?")
        return None
    except subprocess.TimeoutExpired:
        print(f"ERROR: Claude Code timed out after {CLAUDE_TIMEOUT_SECONDS}s.")
        return None

    if result.returncode != 0:
        print(f"ERROR: Claude Code exited with code {result.returncode}")
        if result.stderr:
            print(result.stderr)
        return None

    review, downgrades = parse_stream_output(result.stdout)
    if review is None:
        return None
    return review, downgrades


def parse_stream_output(output: str) -> tuple[str | None, list[str]]:
    """Extract the review text and any model downgrades from stream-json output.

    Downgrades are detected from the fallback events Claude Code emits, and as a
    backstop from the model that actually served each main-thread response.
    """
    review = None
    downgrades = []
    fallback_models = set()
    served_models = set()
    for line in output.splitlines():
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        msg_type = msg.get("type")
        if msg_type == "system" and msg.get("subtype") in FALLBACK_EVENT_SUBTYPES:
            reason = msg.get("api_refusal_category") or msg.get("trigger") or "unknown reason"
            downgrades.append(f"{msg.get('original_model')} -> {msg.get('fallback_model')} ({reason})")
            fallback_models.add(msg.get("fallback_model"))
        elif msg_type == "assistant" and msg.get("parent_tool_use_id") is None:
            served_models.add(msg.get("message", {}).get("model"))
        elif msg_type == "result":
            if msg.get("is_error"):
                print(f"ERROR: Claude Code reported an error: {msg.get('result')}")
            else:
                review = msg.get("result")
    unexpected_models = served_models - fallback_models - {CLAUDE_MODEL, SYNTHETIC_MODEL, None}
    for model in sorted(unexpected_models):
        downgrades.append(f"{CLAUDE_MODEL} -> {model} (served without a fallback event)")
    return review, downgrades


def print_downgrade_warning(downgrades: list[str]) -> None:
    print("!" * 60)
    print(f"WARNING: MODEL DOWNGRADE -- the review was not (fully) done by {CLAUDE_MODEL}.")
    print("Review quality may be lower than expected:")
    for downgrade in downgrades:
        print(f"  {downgrade}")
    print("!" * 60)
    # GitHub Actions annotation, also shown on the workflow run summary page
    print(f"::warning title=Security review model downgraded::{'; '.join(downgrades)}")


def parse_verdict(review: str) -> str | None:
    for line in reversed(review.strip().splitlines()):
        stripped = line.strip()
        if stripped.startswith("VERDICT:"):
            verdict = stripped.split(":", 1)[1].strip().upper()
            if verdict in (VERDICT_PASS, VERDICT_FAIL):
                return verdict
    return None


def post_github_comment(body: str, *, repo: str, pr: str, downgrades: list[str]) -> None:
    """Post a comment on the PR. Silently skips if credentials are missing."""
    token = os.environ.get("GITHUB_TOKEN", "").strip()
    if not token:
        print("GITHUB_TOKEN not set -- skipping PR comment.")
        return

    run_id = os.environ.get("GITHUB_RUN_ID", "")
    server_url = os.environ.get("GITHUB_SERVER_URL", "https://github.com")
    log_url = f"{server_url}/{repo}/actions/runs/{run_id}" if run_id else ""

    comment = "## Security Review -- Issues Found\n\n"
    if downgrades:
        comment += (
            f"> [!WARNING]\n"
            f"> Model downgrade detected, the review was not (fully) done by {CLAUDE_MODEL}: "
            f"{'; '.join(downgrades)}\n\n"
        )
    comment += (
        f"{body}\n\n"
        f"---\n"
        f"*Reviewed by Claude Code ({CLAUDE_MODEL}) at {CLAUDE_EFFORT} effort*"
    )
    if log_url:
        comment += f" | [Full CI log]({log_url})"

    url = f"https://api.github.com/repos/{repo}/issues/{pr}/comments"
    data = json.dumps({"body": comment}).encode()
    req = urllib.request.Request(
        url,
        data=data,
        headers={
            "Authorization": f"token {token}",
            "Accept": "application/vnd.github.v3+json",
            "Content-Type": "application/json",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req) as resp:
            if resp.status == 201:
                print(f"Posted review comment on PR #{pr}.")
            else:
                print(f"GitHub API responded with status {resp.status}.")
    except urllib.error.HTTPError as exc:
        print(f"Failed to post PR comment: HTTP {exc.code} {exc.reason}")
    except urllib.error.URLError as exc:
        print(f"Failed to post PR comment: {exc.reason}")


def main() -> int:
    separator = "=" * 60

    print(separator)
    print("Claude Code Security Review")
    print(separator)

    pr = os.environ.get("PR_NUMBER", "").strip()
    if not pr:
        print("Not a PR build (PR_NUMBER is empty). Skipping.")
        return 0

    if not os.environ.get("CLAUDE_CODE_OAUTH_TOKEN", "").strip():
        print("ERROR: CLAUDE_CODE_OAUTH_TOKEN is not set.")
        return 2

    base_branch = os.environ.get("BASE_BRANCH", "master").strip()
    print(f"PR #{pr} -> base branch: {base_branch}")

    print("\nFetching base branch...")
    try:
        fetch_base_branch(base_branch)
    except subprocess.CalledProcessError as exc:
        print(f"ERROR: git fetch failed: {exc}")
        return 2

    print("Computing diff...")
    try:
        diff = get_pr_diff(base_branch)
    except subprocess.CalledProcessError as exc:
        print(f"ERROR: git diff failed: {exc}")
        return 2

    if not diff or diff.isspace():
        print("Empty diff -- nothing to review.")
        return 0

    try:
        commit_messages = get_commit_messages(base_branch)
    except subprocess.CalledProcessError as exc:
        print(f"ERROR: git log failed: {exc}")
        return 2

    changed_files = changed_files_from_diff(diff)
    file_count = len(changed_files.splitlines())
    print(f"Reviewing changes across {file_count} file(s)...")

    if len(diff) > MAX_DIFF_CHARS:
        print(f"ERROR: diff is {len(diff)} chars, exceeds maximum of {MAX_DIFF_CHARS}. Skipping review.")
        return 2

    user_prompt = build_user_prompt(diff, changed_files, commit_messages)
    system_prompt = read_system_prompt()

    print(f"\nRunning Claude Code review (model: {CLAUDE_MODEL}) at {CLAUDE_EFFORT} effort...\n")
    result = run_claude(user_prompt, system_prompt)

    if result is None:
        print("Review failed to produce output.")
        return 2
    review, downgrades = result

    print(separator)
    print("REVIEW OUTPUT")
    print(separator)
    print(review)
    print(separator)

    if downgrades:
        print_downgrade_warning(downgrades)

    verdict = parse_verdict(review)

    if verdict == VERDICT_FAIL:
        repo = os.environ.get("GITHUB_REPOSITORY", "").strip()
        print("\nVERDICT: FAIL -- Critical or high severity issues found.")
        post_github_comment(review, repo=repo, pr=pr, downgrades=downgrades)
        return 1

    if verdict == VERDICT_PASS:
        print("\nVERDICT: PASS -- No critical or high severity issues.")
        return 0

    print("\nWARNING: Could not parse verdict from review output.")
    print("Review logged above for manual inspection.")
    return 2


if __name__ == "__main__":
    sys.exit(main())
