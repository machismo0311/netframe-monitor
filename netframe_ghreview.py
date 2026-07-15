#!/usr/bin/env python3
"""NetFRAME GitHub Engineering Intelligence: a weekly, READ-ONLY portfolio review.

Jarvis audits every repo it can read, scores each on an objective rubric, then does
one deep-pass LLM synthesis in the voice of a hiring manager / staff engineer. It
NEVER writes to any repo, opens PRs, or pushes; output is a report + recommendations
only. This is Tier 0 (observation) applied to the GitHub portfolio.

Self-contained: pure Python stdlib over the GitHub REST API. No git, no gh CLI, no
extra packages installed on Jarvis. Facts (README size, CI, license, topics,
staleness, last commit, native secret-scanning alerts) all come from the API.

Access: a fine-grained, READ-ONLY token (contents+metadata; secret-scanning-alerts
read is optional). Resolution order:
  1. $GH_TOKEN / $GITHUB_TOKEN in the environment
  2. /opt/netframe-monitor/github_token (chmod 600; NOT committed)
  3. none -> public-only mode (unauthenticated; private repos are not listed)
The token is sent only in the Authorization header, never printed or written to disk.

Writes report-github.md + reports/github/<date>.md. Cadence: weekly timer.
"""
import datetime as dt
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import netframe_policy  # noqa: E402 - path first; the gate is mandatory

BASE = os.environ.get("NETFRAME_BASE", "/opt/netframe-monitor")
TOKEN_FILE = f"{BASE}/github_token"
OUT = f"{BASE}/report-github.md"
ARCHIVE_DIR = f"{BASE}/reports/github"
OWNER = os.environ.get("NETFRAME_GH_OWNER", "machismo0311")
API = "https://api.github.com"
OLLAMA_URL = os.environ.get("NETFRAME_OLLAMA_URL", "http://localhost:11434/api/chat")
MODEL = os.environ.get("NETFRAME_LLM_MODEL", "qwen2.5:72b")
LLM_TIMEOUT = int(os.environ.get("NETFRAME_LLM_TIMEOUT", "900"))
API_TIMEOUT = 20
STALE_DAYS = 120

SYSTEM_PROMPT = (
    "You are a staff-level engineer reviewing a candidate's GitHub portfolio as if you were "
    "a hiring manager for an infrastructure/SRE role. You are given OBJECTIVE FACTS about "
    "each repo (already gathered; do not invent any). Write a concise Markdown review "
    "(~500 words) with EXACTLY these headers:\n"
    "## Portfolio verdict\n## Strongest repos\n## Weakest / needs work\n"
    "## Drift and staleness\n## Presentation and technical accuracy\n## Security signals\n"
    "## Ranked recommendations\n"
    "Be specific and cite repo names. In Ranked recommendations, give at most 8 concrete, "
    "actionable items ordered by impact. RECOMMEND ONLY: never claim to have changed anything. "
    "No em dashes.")


def load_token():
    for var in ("GH_TOKEN", "GITHUB_TOKEN"):
        if os.environ.get(var):
            return os.environ[var]
    if os.path.exists(TOKEN_FILE):
        return open(TOKEN_FILE).read().strip() or None
    return None


def api(path, token, params=None):
    """GET the REST API. Returns (status, parsed_json_or_None, headers). Never raises."""
    url = API + path
    if params:
        url += "?" + urllib.parse.urlencode(params)
    headers = {"Accept": "application/vnd.github+json",
               "X-GitHub-Api-Version": "2022-11-28",
               "User-Agent": "netframe-ghreview"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=API_TIMEOUT) as resp:
            data = resp.read().decode()
            return resp.status, (json.loads(data) if data else None), dict(resp.headers)
    except urllib.error.HTTPError as e:
        return e.code, None, dict(e.headers or {})
    except (urllib.error.URLError, TimeoutError, ValueError):
        return None, None, {}


def token_health(token):
    """Validate the token and check its expiry. Returns (usable_token, note_or_None).
    A PAT expiry must never silently degrade the review to public-only (JAR-15)."""
    if not token:
        return None, (f"No GitHub token at {TOKEN_FILE}; private repos are NOT covered "
                      "by this review.")
    st, _, hdrs = api("/user", token)
    if st in (401, 403):
        return None, ("GitHub token PRESENT but REJECTED (expired or revoked); review "
                      f"degraded to public-only. Replace {TOKEN_FILE}.")
    exp_raw = next((v for k, v in hdrs.items()
                    if k.lower() == "github-authentication-token-expiration"), None)
    if exp_raw:
        # header format: '2026-10-13 10:00:00 UTC' (sometimes a numeric offset)
        try:
            exp = dt.datetime.strptime(exp_raw.replace(" UTC", ""), "%Y-%m-%d %H:%M:%S")
            exp = exp.replace(tzinfo=dt.timezone.utc)
            days = (exp - dt.datetime.now(dt.timezone.utc)).days
            if days <= 14:
                return token, (f"GitHub token expires in {days} day(s) "
                               f"({exp.date().isoformat()}); rotate it soon or this review "
                               "silently loses private-repo coverage.")
        except ValueError:
            pass
    return token, None


def list_repos(token):
    repos, page = [], 1
    while True:
        if token:
            path, params = "/user/repos", {"per_page": 100, "page": page,
                                           "affiliation": "owner", "sort": "pushed"}
        else:
            path, params = f"/users/{OWNER}/repos", {"per_page": 100, "page": page,
                                                     "sort": "pushed"}
        st, data, _ = api(path, token, params)
        if st != 200 or not data:
            if page == 1 and st != 200:
                return None, f"repo list HTTP {st}"
            break
        repos.extend(data)
        if len(data) < 100:
            break
        page += 1
    live = [r for r in repos if not r.get("archived")]
    return live, None


def days_since(iso):
    if not iso:
        return None
    try:
        then = dt.datetime.fromisoformat(iso.replace("Z", "+00:00"))
    except ValueError:
        return None
    return (dt.datetime.now(dt.timezone.utc) - then).days


def exists(path, token):
    st, _, _ = api(path, token)
    return st == 200


def analyze_repo(meta, token):
    o, n = OWNER, meta["name"]
    facts = {
        "name": n, "visibility": "private" if meta.get("private") else "public",
        "description": (meta.get("description") or "").strip(),
        "topics": meta.get("topics") or [],
        "license": (meta.get("license") or {}).get("spdx_id"),
        "stale_days": days_since(meta.get("pushed_at")),
        "is_fork": meta.get("fork", False),
        "default_branch": meta.get("default_branch"),
    }
    st, readme, _ = api(f"/repos/{o}/{n}/readme", token)
    facts["has_readme"] = st == 200
    facts["readme_bytes"] = (readme or {}).get("size", 0) if st == 200 else 0
    facts["has_license_file"] = bool(facts["license"]) or exists(
        f"/repos/{o}/{n}/contents/LICENSE", token)
    st, wf, _ = api(f"/repos/{o}/{n}/contents/.github/workflows", token)
    facts["has_ci"] = st == 200 and isinstance(wf, list) and len(wf) > 0
    facts["has_gitignore"] = exists(f"/repos/{o}/{n}/contents/.gitignore", token)
    st, commits, _ = api(f"/repos/{o}/{n}/commits", token, {"per_page": 1})
    if st == 200 and commits:
        facts["last_commit_subject"] = commits[0]["commit"]["message"].splitlines()[0][:120]
    else:
        facts["last_commit_subject"] = None
    facts["secret_scan"] = secret_signal(o, n, token)
    facts.update(deep_facts(o, n, token))
    return facts


def deep_facts(o, n, token):
    """The facts a senior reviewer actually checks: does CI pass, branch/PR hygiene,
    submodules, and declared dependencies. All read-only over the REST API."""
    f = {}
    # latest CI run conclusion: a green rubric on a repo with failing CI is misleading
    st, runs, _ = api(f"/repos/{o}/{n}/actions/runs", token, {"per_page": 1})
    if st == 200 and (runs or {}).get("workflow_runs"):
        f["ci_conclusion"] = runs["workflow_runs"][0].get("conclusion")  # success/failure/None
    else:
        f["ci_conclusion"] = None
    st, branches, _ = api(f"/repos/{o}/{n}/branches", token, {"per_page": 100})
    f["branch_count"] = len(branches) if st == 200 and isinstance(branches, list) else 1
    st, pulls, _ = api(f"/repos/{o}/{n}/pulls", token, {"state": "open", "per_page": 100})
    f["open_prs"] = len(pulls) if st == 200 and isinstance(pulls, list) else 0
    f["has_submodules"] = exists(f"/repos/{o}/{n}/contents/.gitmodules", token)
    f["dependency_manifest"] = next(
        (m for m in ("requirements.txt", "package.json", "go.mod", "pyproject.toml", "Gemfile")
         if exists(f"/repos/{o}/{n}/contents/{m}", token)), None)
    return f


def secret_signal(o, n, token):
    """Use GitHub's native secret-scanning alerts. 404/403 => not enabled or no scope."""
    st, alerts, _ = api(f"/repos/{o}/{n}/secret-scanning/alerts", token,
                        {"state": "open", "per_page": 100})
    if st == 200 and isinstance(alerts, list):
        return {"available": True, "open": len(alerts)}
    return {"available": False, "open": 0}


def score(f):
    """Objective 0-100 health rubric. Deterministic; the LLM never computes this."""
    s, issues = 0, []
    if f.get("has_readme") and f["readme_bytes"] >= 500:
        s += 24
    else:
        issues.append("README missing or thin (<500 bytes)")
    if f.get("has_license_file"):
        s += 13
    else:
        issues.append("no LICENSE")
    if f.get("has_ci"):
        s += 17
    else:
        issues.append("no CI workflow")
    if f.get("has_gitignore"):
        s += 6
    else:
        issues.append("no .gitignore")
    if f.get("description"):
        s += 9
    else:
        issues.append("no repo description")
    if f.get("topics"):
        s += 6
    else:
        issues.append("no topics")
    sd = f.get("stale_days")
    if sd is None:
        pass
    elif sd <= STALE_DAYS:
        s += 20
    else:
        issues.append(f"stale ({sd}d since last push)")
        s += max(0, 20 - (sd - STALE_DAYS) // 30 * 3)
    sec = f.get("secret_scan", {})
    if sec.get("available") and sec.get("open", 0) == 0:
        s += 5
    elif sec.get("available") and sec.get("open", 0) > 0:
        issues.append(f"{sec['open']} open secret-scanning alert(s)")
    # a green rubric on a repo whose CI is actually FAILING is misleading; dock it hard
    if f.get("ci_conclusion") == "failure":
        issues.append("CI is FAILING on the latest run")
        s -= 15
    if (f.get("open_prs") or 0) > 5:
        issues.append(f"{f['open_prs']} stale open PRs")
    return max(0, min(s, 100)), issues


def narrate(rows):
    facts = json.dumps([{k: r[k] for k in
                         ("name", "visibility", "score", "issues", "stale_days", "topics",
                          "description", "license", "has_ci", "secret_scan")}
                        for r in rows], indent=2)
    payload = {"model": MODEL, "stream": False, "options": {"temperature": 0.2},
               "messages": [{"role": "system", "content": SYSTEM_PROMPT},
                            {"role": "user", "content":
                             "OBJECTIVE FACTS (one object per repo):\n" + facts}]}
    req = urllib.request.Request(OLLAMA_URL, data=json.dumps(payload).encode(),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=LLM_TIMEOUT) as resp:
        return json.loads(resp.read().decode())["message"]["content"].strip()


RECRUITER_PROMPT = (
    "You are a Fortune 500 hiring manager for a senior infrastructure/SRE role. You have "
    "90 SECONDS to form a first impression of this candidate's GitHub from the objective "
    "facts given (do not invent any). Write a short Markdown block with EXACTLY these "
    "headers:\n## 90-second impression\n## Scores\n## What lands / what hurts\n"
    "Under Scores, give each 0-100 with one clause of justification: First impression, "
    "Technical maturity, Documentation, Engineering discipline, Portfolio strength. Under "
    "the impression, write the two or three sentences a hiring manager would actually think. "
    "Be candid, not flattering. No em dashes.")


def recruiter_review(rows):
    facts = json.dumps([{k: r.get(k) for k in
                         ("name", "visibility", "score", "description", "topics",
                          "has_ci", "ci_conclusion", "readme_bytes", "stale_days",
                          "has_submodules", "dependency_manifest", "open_prs", "issues")}
                        for r in rows], indent=2)
    payload = {"model": MODEL, "stream": False, "options": {"temperature": 0.2},
               "messages": [{"role": "system", "content": RECRUITER_PROMPT},
                            {"role": "user", "content": "PORTFOLIO FACTS:\n" + facts}]}
    req = urllib.request.Request(OLLAMA_URL, data=json.dumps(payload).encode(),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=LLM_TIMEOUT) as resp:
        return json.loads(resp.read().decode())["message"]["content"].strip()


def table(rows):
    out = ["| Repo | Vis | Score | CI | Key gaps |", "|---|---|---|---|---|"]
    for r in sorted(rows, key=lambda x: -(x["score"])):
        gaps = ", ".join(r["issues"][:3]) or "none"
        ci = {"success": "pass", "failure": "FAIL", None: "-"}.get(r.get("ci_conclusion"),
                                                                    r.get("ci_conclusion") or "-")
        out.append(f"| {r['name']} | {r['visibility']} | {r['score']} | {ci} | {gaps} |")
    return "\n".join(out)


def main():
    token, token_note = token_health(load_token())
    now = dt.datetime.now(dt.timezone.utc)
    repos, err = list_repos(token)
    mode = "authenticated (public + private)" if token else "public-only (no token)"
    if err or repos is None:
        body = f"## GitHub review unavailable\nCould not list repos: {err}\n"
        rows = []
    else:
        rows = []
        for meta in repos:
            f = analyze_repo(meta, token)
            f["score"], f["issues"] = score(f)
            rows.append(f)
        avg = round(sum(r["score"] for r in rows) / len(rows)) if rows else 0
        try:
            review = narrate(rows) if rows else "_No repos to review._"
        except Exception as e:  # noqa: BLE001 - degrade, never crash the timer
            review = f"_LLM synthesis unavailable ({e}); the rubric table above stands alone._"
        try:
            recruiter = recruiter_review(rows) if rows else ""
        except Exception as e:  # noqa: BLE001
            recruiter = f"_Recruiter simulation unavailable ({e})._"
        # Same deterministic gate as every other LLM->operator path. Lower risk than the
        # infra reports (its subject is repositories, not hardware), but "lower risk" is
        # not a reason for a different boundary: the whole defect was that some paths had
        # a weaker one than others.
        review, _ = netframe_policy.enforce(review, source="ghreview")
        recruiter, _ = netframe_policy.enforce(recruiter, source="ghreview-recruiter")
        body = (f"**Portfolio health: {avg}/100** across {len(rows)} repo(s), {mode}.\n\n"
                f"{table(rows)}\n\n---\n\n{review}\n\n---\n\n"
                f"# Recruiter Simulation Mode\n\n{recruiter}")
    if token_note:
        body = f"**Token status:** {token_note}\n\n{body}"
        print(f"TOKEN NOTE: {token_note}")
    report = (f"# NetFRAME GitHub Engineering Review\n\n_Generated {now.isoformat()} by {MODEL} "
              f"on Jarvis · read-only, recommend-only · {mode}_\n\n---\n\n{body}\n")
    with open(OUT, "w") as fh:
        fh.write(report)
    os.makedirs(ARCHIVE_DIR, exist_ok=True)
    with open(f"{ARCHIVE_DIR}/{now.date().isoformat()}.md", "w") as fh:
        fh.write(report)
    print(f"github review written by {MODEL}: {len(rows) if repos else 0} repos ({mode}) -> {OUT}")


if __name__ == "__main__":
    main()
