#!/usr/bin/env python3
"""Behavioural coverage for netframe-backup.sh.

This unit had none. It was extended on 2026-09-12 to cover llm_router (Jarvis is a PVE
*host*, so PBS backs up its guests and not its own filesystem), and that change landed
inside the window where a red lint aborted CI before pytest, so nothing ever exercised
it. ShellCheck passes on the script, but ShellCheck proves syntax, not that the right
paths reach restic or that a failed backup is reported as a failure.

A fake restic on PATH records each invocation's argv and the restic environment it was
handed. Nothing here contacts Randy, opens a real repository, reads a credential, or
runs a real backup.

Deliberately not covered: the freshness marker on the last line redirects into
/opt/netframe-monitor/context/, an absolute path that does not exist on a test runner,
so bash fails the redirection and the command never runs. Its failure is swallowed by
`|| true`, which the exit-code tests below cover indirectly.
"""

import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(os.path.dirname(HERE), "netframe-backup.sh")

# Paths the script is contracted to hand to restic. The llm_router entries are the
# 2026-09-12 addition and are the specific reason this file exists.
REQUIRED_PATHS = [
    "/opt/netframe-monitor",
    "/opt/llm_router",
    "/etc/llm_router.env",
    "/etc/systemd/system/llm_router.service",
    "/etc/systemd/system/llm-router-lock.service",
]

REQUIRED_EXCLUDES = [
    "/opt/netframe-monitor/web",
    "__pycache__",
    "/opt/llm_router/venv",
]

FAKE_RESTIC = r'''#!/usr/bin/env python3
import json, os, sys

with open(os.environ["NFM_FAKE_CALLS"], "a") as fh:
    fh.write(json.dumps({
        "argv": sys.argv[1:],
        "repo": os.environ.get("RESTIC_REPOSITORY"),
        "password_file": os.environ.get("RESTIC_PASSWORD_FILE"),
    }) + "\n")

verb = sys.argv[1] if len(sys.argv) > 1 else ""
if os.environ.get("NFM_FAKE_FAIL", "") == verb:
    sys.stderr.write("fake restic: simulated %s failure\n" % verb)
    sys.exit(1)
if verb == "snapshots":
    print("[]")
sys.exit(0)
'''


class Bed:
    """A fake restic on PATH plus a call log. The real binary is never involved."""

    def __init__(self, tmp):
        self.tmp = tmp
        self.calls = os.path.join(tmp, "calls")
        self.bin = os.path.join(tmp, "bin")
        os.makedirs(self.bin, exist_ok=True)
        fake = os.path.join(self.bin, "restic")
        with open(fake, "w") as f:
            f.write(FAKE_RESTIC)
        os.chmod(fake, 0o755)

    def run(self, **extra):
        e = dict(os.environ)
        e["NFM_FAKE_CALLS"] = self.calls
        e["PATH"] = self.bin + os.pathsep + e.get("PATH", "")
        e.update({k: str(v) for k, v in extra.items()})
        p = subprocess.run(["/bin/bash", SCRIPT], capture_output=True, text=True, env=e)
        return p.returncode, (p.stdout or "") + (p.stderr or "")

    def invocations(self):
        if not os.path.exists(self.calls):
            return []
        with open(self.calls) as f:
            return [json.loads(ln) for ln in f if ln.strip()]

    def verb(self, name):
        """The first invocation whose first argument is `name`, or None."""
        for c in self.invocations():
            if c["argv"][:1] == [name]:
                return c
        return None


def chk(label, ok, detail=""):
    """Assert one invariant, matching the style the lock suites use."""
    assert ok, "%s%s" % (label, (": " + detail) if detail else "")


def test_backup_covers_every_contracted_path():
    with tempfile.TemporaryDirectory() as tmp:
        bed = Bed(tmp)
        rc, out = bed.run()
        chk("exit 0 when restic succeeds", rc == 0, "rc=%d out=%r" % (rc, out[:200]))
        call = bed.verb("backup")
        chk("restic backup was invoked", call is not None, repr(bed.invocations()))
        argv = call["argv"]
        for p in REQUIRED_PATHS:
            chk("backup includes %s" % p, p in argv, repr(argv))
        chk("backup includes the netframe systemd units",
            any(a.startswith("/etc/systemd/system/netframe-") for a in argv), repr(argv))


def test_llm_router_paths_are_present():
    # The 2026-09-12 addition, asserted separately because it is the change that
    # landed with no coverage at all.
    with tempfile.TemporaryDirectory() as tmp:
        bed = Bed(tmp)
        bed.run()
        argv = bed.verb("backup")["argv"]
        chk("llm_router tree is backed up", "/opt/llm_router" in argv, repr(argv))
        chk("its 0600 env file is backed up", "/etc/llm_router.env" in argv, repr(argv))
        chk("its service unit is backed up",
            "/etc/systemd/system/llm_router.service" in argv, repr(argv))
        chk("its lock unit is backed up",
            "/etc/systemd/system/llm-router-lock.service" in argv, repr(argv))


def test_rebuildable_and_derived_paths_are_excluded():
    with tempfile.TemporaryDirectory() as tmp:
        bed = Bed(tmp)
        bed.run()
        argv = bed.verb("backup")["argv"]
        for x in REQUIRED_EXCLUDES:
            idxs = [i for i, a in enumerate(argv) if a == x]
            chk("%s is excluded" % x, idxs != [], repr(argv))
            chk("%s is excluded via --exclude" % x,
                any(argv[i - 1] == "--exclude" for i in idxs if i > 0), repr(argv))


def test_rag_corpus_is_not_excluded():
    # Deliberately INCLUDED per the script's own header: the embeddings are not
    # bit-reproducible, so they are state rather than derived output.
    with tempfile.TemporaryDirectory() as tmp:
        bed = Bed(tmp)
        bed.run()
        argv = bed.verb("backup")["argv"]
        for derived in ("rag_docs", "rag_embeddings.npy", "rag_index.json"):
            chk("%s is not excluded" % derived,
                not any(derived in a for a in argv), repr(argv))


def test_snapshot_is_tagged_netframe():
    with tempfile.TemporaryDirectory() as tmp:
        bed = Bed(tmp)
        bed.run()
        argv = bed.verb("backup")["argv"]
        chk("the snapshot carries the netframe tag",
            "--tag" in argv and argv[argv.index("--tag") + 1] == "netframe", repr(argv))


def test_repository_and_password_file_reach_restic():
    with tempfile.TemporaryDirectory() as tmp:
        bed = Bed(tmp)
        bed.run()
        call = bed.verb("backup")
        chk("the repository is exported to restic",
            call["repo"] == "sftp:root@192.168.30.187:/mnt/bulk/backups/jarvis-netframe",
            repr(call["repo"]))
        chk("the password file is exported rather than an inline secret",
            call["password_file"] == "/root/.config/restic/netframe-pass",
            repr(call["password_file"]))
        chk("no password value is passed on the command line",
            not any(a.startswith("--password=") or a == "--password" for a in call["argv"]),
            repr(call["argv"]))


def test_paths_are_separate_arguments_not_one_split_string():
    # Guards the line-continuation quoting: each path must arrive as its own argv
    # entry, never glued to a neighbour and never split on whitespace.
    with tempfile.TemporaryDirectory() as tmp:
        bed = Bed(tmp)
        bed.run()
        argv = bed.verb("backup")["argv"]
        for p in REQUIRED_PATHS:
            chk("%s arrives as exactly one argument" % p, argv.count(p) == 1, repr(argv))
        chk("no argument contains an embedded space-separated path list",
            not any(" /" in a for a in argv), repr(argv))


def test_retention_is_14_daily_8_weekly_with_prune():
    with tempfile.TemporaryDirectory() as tmp:
        bed = Bed(tmp)
        bed.run()
        call = bed.verb("forget")
        chk("restic forget was invoked", call is not None, repr(bed.invocations()))
        argv = call["argv"]
        chk("keeps 14 daily",
            "--keep-daily" in argv and argv[argv.index("--keep-daily") + 1] == "14", repr(argv))
        chk("keeps 8 weekly",
            "--keep-weekly" in argv and argv[argv.index("--keep-weekly") + 1] == "8", repr(argv))
        chk("prunes", "--prune" in argv, repr(argv))


def test_a_failed_backup_is_never_reported_as_success():
    with tempfile.TemporaryDirectory() as tmp:
        bed = Bed(tmp)
        rc, out = bed.run(NFM_FAKE_FAIL="backup")
        chk("a failed backup exits nonzero", rc != 0, "rc=%d out=%r" % (rc, out[:200]))


def test_retention_still_runs_after_a_failed_backup():
    # This records the CURRENT contract rather than a preference. The script captures
    # the backup's status into rc, then runs forget unconditionally and exits on rc.
    # Pinned here so that if retention is later gated on backup success, this test
    # fails and that becomes a deliberate decision instead of an accident.
    with tempfile.TemporaryDirectory() as tmp:
        bed = Bed(tmp)
        rc, _ = bed.run(NFM_FAKE_FAIL="backup")
        chk("the failure is still propagated", rc != 0, "rc=%d" % rc)
        chk("and retention runs anyway, which is the current contract",
            bed.verb("forget") is not None, repr(bed.invocations()))


def test_a_failed_retention_does_not_turn_a_good_backup_into_a_failure():
    with tempfile.TemporaryDirectory() as tmp:
        bed = Bed(tmp)
        rc, out = bed.run(NFM_FAKE_FAIL="forget")
        chk("forget ran", bed.verb("forget") is not None, repr(bed.invocations()))
        chk("but the run still reports the backup's own success",
            rc == 0, "rc=%d out=%r" % (rc, out[:200]))


def test_backup_runs_before_retention():
    with tempfile.TemporaryDirectory() as tmp:
        bed = Bed(tmp)
        bed.run()
        verbs = [c["argv"][0] for c in bed.invocations() if c["argv"]]
        chk("backup precedes forget, so retention never prunes ahead of the new snapshot",
            "backup" in verbs and "forget" in verbs
            and verbs.index("backup") < verbs.index("forget"), repr(verbs))


if __name__ == "__main__":
    fns = [(n, f) for n, f in sorted(globals().items()) if n.startswith("test_") and callable(f)]
    failed = 0
    for name, fn in fns:
        try:
            fn()
            print("  PASS  %s" % name)
        except AssertionError as exc:
            failed += 1
            print("  FAIL  %s: %s" % (name, exc))
    print("%d/%d passed" % (len(fns) - failed, len(fns)))
    sys.exit(1 if failed else 0)
