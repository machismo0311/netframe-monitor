#!/usr/bin/env python3
"""Prove netframe-8808-lock survives xtables lock contention and never lies about success.

Measured history (Phase 0, Jarvis): this unit lost the /run/xtables.lock race on two of three
retained boots and exited 4. On 2026-09-24T23:57 all three inserts failed, so tcp/8808 was left
with NO rules, fully exposing the unauthenticated report backend. The old script had no error
handling either, so a run whose last insert happened to win reported success with partial policy.

These tests use a fake iptables that takes a real flock on a TEMPORARY lock file. The production
/run/xtables.lock is never touched and no live contention is ever induced.
"""

import json
import os
import subprocess
import sys
import tempfile
import textwrap
import time

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(os.path.dirname(HERE), "netframe-8808-lock.sh")
PORT = "8808"
NPM = "192.168.10.181"
FAILURES = []

# The pre-fix script, verbatim in shape from git history: bare iptables, no -w, no error handling,
# no invariant check. Kept as a fixture so the negative controls test the real old behaviour.
OLD_SCRIPT = """#!/bin/bash
port=8808
npm=192.168.10.181
while iptables -C INPUT -p tcp --dport "$port" -s 127.0.0.1 -j ACCEPT 2>/dev/null; do
	iptables -D INPUT -p tcp --dport "$port" -s 127.0.0.1 -j ACCEPT
done
while iptables -C INPUT -p tcp --dport "$port" -s "$npm" -j ACCEPT 2>/dev/null; do
	iptables -D INPUT -p tcp --dport "$port" -s "$npm" -j ACCEPT
done
while iptables -C INPUT -p tcp --dport "$port" -j DROP 2>/dev/null; do
	iptables -D INPUT -p tcp --dport "$port" -j DROP
done
iptables -I INPUT 1 -p tcp --dport "$port" -j DROP
iptables -I INPUT 1 -p tcp --dport "$port" -s "$npm" -j ACCEPT
iptables -I INPUT 1 -p tcp --dport "$port" -s 127.0.0.1 -j ACCEPT
"""

# A fake iptables that models the two behaviours under test: canonical global-option parsing
# (so "-w 10 -C ..." is understood as a -C, not as an unknown verb), and real lock contention via
# flock on a temp file. Without -w it fails immediately exactly as iptables 1.8.11 does.
FAKE_IPTABLES = r'''#!/usr/bin/env python3
import fcntl, json, os, sys, time

args = sys.argv[1:]
state = os.environ["NFM_FAKE_STATE"]
lockfile = os.environ["NFM_FAKE_LOCK"]
fail_insert = int(os.environ.get("NFM_FAKE_FAIL_INSERT", "0"))
calls_file = os.environ.get("NFM_FAKE_CALLS", "")

# --- canonical leading global options come BEFORE the operation ---
wait = None
i = 0
while i < len(args):
    if args[i] in ("-w", "--wait"):
        i += 1
        if i < len(args) and args[i].lstrip("-").isdigit():
            wait = int(args[i]); i += 1
        else:
            wait = -1   # -w with no argument means wait forever
    elif args[i] in ("-W", "--wait-interval"):
        i += 1
        if i < len(args) and args[i].isdigit():
            i += 1
    else:
        break
args = args[i:]

if calls_file:
    with open(calls_file, "a") as fh:
        fh.write(("wait=%s " % wait) + " ".join(args) + "\n")

# --- lock acquisition, mirroring iptables 1.8.11 semantics ---
fh = open(lockfile, "w")
deadline = time.time() + (wait if (wait and wait > 0) else 0)
got = False
while True:
    try:
        fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
        got = True
        break
    except OSError:
        if wait is None or (wait > 0 and time.time() >= deadline):
            break
        if wait == -1 or time.time() < deadline:
            time.sleep(0.05)
            continue
        break
if not got:
    sys.stderr.write("Can't lock %s: Resource temporarily unavailable\n" % lockfile)
    sys.stderr.write("Another app is currently holding the xtables lock. "
                     "Perhaps you want to use the -w option?\n")
    sys.exit(4)

def load():
    with open(state) as f:
        return json.load(f)

def save(st):
    with open(state, "w") as f:
        json.dump(st, f)

def canon(tokens):
    """Render a rule spec the way iptables -S prints it, including its token REORDERING.

    Real iptables emits -s/-d first, then -p with its implicit -m match, then the match
    extension options, then -j. A fake that preserved the caller's order would let a
    wrongly-ordered spec compare equal, so the ordering is reproduced here deliberately.
    """
    src = dst = proto = jump = None
    dport = sport = None
    rest = []
    toks = list(tokens)
    while toks:
        t = toks.pop(0)
        if t == "-s":
            a = toks.pop(0); src = a if "/" in a else a + "/32"
        elif t == "-d":
            a = toks.pop(0); dst = a if "/" in a else a + "/32"
        elif t == "-p":
            proto = toks.pop(0)
        elif t == "--dport":
            dport = toks.pop(0)
        elif t == "--sport":
            sport = toks.pop(0)
        elif t == "-j":
            jump = toks.pop(0)
        elif t == "-m":
            m = toks.pop(0)
            if m != proto:          # iptables adds "-m <proto>" itself; do not duplicate it
                rest += ["-m", m]
        else:
            rest.append(t)
    out = []
    if src:
        out += ["-s", src]
    if dst:
        out += ["-d", dst]
    if proto:
        out += ["-p", proto, "-m", proto]
    if sport:
        out += ["--sport", sport]
    if dport:
        out += ["--dport", dport]
    out += rest
    if jump:
        out += ["-j", jump]
    return " ".join(out)

st = load()
rc = 0
op = args[0] if args else ""
chain = args[1] if len(args) > 1 else ""

if op in ("-C", "-D") and chain in st["chains"]:
    spec = canon(args[2:])
    rules = st["chains"][chain]
    idx = next((k for k, r in enumerate(rules) if r == spec), None)
    if idx is None:
        rc = 1
    elif op == "-D":
        rules.pop(idx)
elif op == "-I" and chain in st["chains"]:
    st["inserts"] = st.get("inserts", 0) + 1
    if fail_insert and st["inserts"] == fail_insert:
        sys.stderr.write("iptables: simulated insert failure\n")
        rc = 1
    else:
        pos = int(args[2]) - 1
        st["chains"][chain].insert(pos, canon(args[3:]))
elif op == "-S" and chain in st["chains"]:
    print("-P %s ACCEPT" % chain)
    for r in st["chains"][chain]:
        print("-A %s %s" % (chain, r))
elif op == "-L" and chain in st["chains"]:
    pass
else:
    st.setdefault("violations", []).append(args)
save(st)
sys.exit(rc)
'''


def chk(label, ok, detail=""):
    print("  %s  %s" % ("PASS" if ok else "FAIL", label))
    if not ok:
        FAILURES.append("%s%s" % (label, (": " + detail) if detail else ""))


class Bed:
    """A test bed: fake iptables on PATH, a temp state file, a temp lock file."""

    def __init__(self, tmp, chain_rules=None):
        self.tmp = tmp
        self.state = os.path.join(tmp, "state.json")
        self.lock = os.path.join(tmp, "xtables.lock.test")
        self.calls = os.path.join(tmp, "calls")
        self.bin = os.path.join(tmp, "bin")
        os.makedirs(self.bin, exist_ok=True)
        fake = os.path.join(self.bin, "iptables")
        with open(fake, "w") as f:
            f.write(FAKE_IPTABLES)
        os.chmod(fake, 0o755)
        self.fake = fake
        self.save({"chains": {"INPUT": list(chain_rules or [])}, "inserts": 0, "violations": []})

    def save(self, st):
        with open(self.state, "w") as f:
            json.dump(st, f)

    def load(self):
        with open(self.state) as f:
            return json.load(f)

    def env(self, **extra):
        e = dict(os.environ)
        e.update({
            "NFM_FAKE_STATE": self.state,
            "NFM_FAKE_LOCK": self.lock,
            "NFM_FAKE_CALLS": self.calls,
            "NFM_IPT": self.fake,
            "PATH": self.bin + os.pathsep + e.get("PATH", ""),
        })
        e.update({k: str(v) for k, v in extra.items()})
        return e

    def run_new(self, wait="10", **extra):
        e = self.env(NFM_IPT_WAIT=wait, **extra)
        t0 = time.time()
        p = subprocess.run(["/bin/bash", SCRIPT], capture_output=True, text=True, env=e)
        return p.returncode, (p.stdout or "") + (p.stderr or ""), time.time() - t0

    def run_old(self, **extra):
        old = os.path.join(self.tmp, "old-8808.sh")
        with open(old, "w") as f:
            f.write(OLD_SCRIPT)
        os.chmod(old, 0o755)
        e = self.env(**extra)
        t0 = time.time()
        p = subprocess.run(["/bin/bash", old], capture_output=True, text=True, env=e)
        return p.returncode, (p.stdout or "") + (p.stderr or ""), time.time() - t0

    def hold_lock(self, seconds):
        """Hold the temp lock in a child process for N seconds, exactly like a competing writer."""
        code = textwrap.dedent("""
            import fcntl, sys, time
            fh = open(sys.argv[1], "w")
            fcntl.flock(fh, fcntl.LOCK_EX)
            time.sleep(float(sys.argv[2]))
        """)
        proc = subprocess.Popen([sys.executable, "-c", code, self.lock, str(seconds)])
        time.sleep(0.4)  # let the child actually take the lock before the script runs
        return proc


WANT = [
    "-s 127.0.0.1/32 -p tcp -m tcp --dport %s -j ACCEPT" % PORT,
    "-s %s/32 -p tcp -m tcp --dport %s -j ACCEPT" % (NPM, PORT),
    "-p tcp -m tcp --dport %s -j DROP" % PORT,
]

print("=== positive control: establishes exactly the required policy, in order ===")
with tempfile.TemporaryDirectory() as tmp:
    bed = Bed(tmp)
    rc, out, _ = bed.run_new()
    rules = bed.load()["chains"]["INPUT"]
    chk("exit 0", rc == 0, "rc=%d out=%r" % (rc, out))
    chk("the three required rules are present, in the required order", rules[:3] == WANT, repr(rules))
    chk("both ACCEPTs are above the DROP",
        rules.index(WANT[0]) < rules.index(WANT[2]) and rules.index(WANT[1]) < rules.index(WANT[2]),
        repr(rules))
    chk("no unrecognised iptables verb was used (harness parsed the global -w)",
        bed.load().get("violations") == [], repr(bed.load().get("violations")))
    chk("every call carried the bounded wait",
        all("wait=10" in ln for ln in open(bed.calls).read().splitlines()),
        open(bed.calls).read()[:200])

print()
print("=== idempotency: a second run changes nothing and stays exact ===")
with tempfile.TemporaryDirectory() as tmp:
    bed = Bed(tmp)
    bed.run_new()
    first = bed.load()["chains"]["INPUT"]
    rc, out, _ = bed.run_new()
    second = bed.load()["chains"]["INPUT"]
    chk("exit 0", rc == 0, "rc=%d" % rc)
    chk("says it was already correct", "already correct" in out, out)
    chk("rule list is byte-identical, no duplicates", first == second, "%r vs %r" % (first, second))
    chk("exactly three rules touch the port",
        sum(1 for r in second if "--dport %s " % PORT in r + " ") == 3, repr(second))

print()
print("=== duplicates and wrong order are normalised, not compounded ===")
with tempfile.TemporaryDirectory() as tmp:
    # DROP above the ACCEPTs, plus a duplicate ACCEPT: the exact states the invariant must reject.
    bed = Bed(tmp, chain_rules=[WANT[2], WANT[0], WANT[0], WANT[1]])
    rc, out, _ = bed.run_new()
    rules = bed.load()["chains"]["INPUT"]
    chk("exit 0", rc == 0, "rc=%d out=%r" % (rc, out))
    chk("ends with exactly the three required rules in order", rules == WANT, repr(rules))

print()
print("=== OLD implementation loses the lock race immediately ===")
with tempfile.TemporaryDirectory() as tmp:
    bed = Bed(tmp)
    holder = bed.hold_lock(3)
    rc, out, elapsed = bed.run_old()
    holder.wait()
    chk("old script fails", rc != 0, "rc=%d" % rc)
    chk("old script fails with the real lock message", "xtables lock" in out, out[:200])
    chk("old script gave up immediately rather than waiting", elapsed < 2.0, "%.2fs" % elapsed)
    chk("old script left NO rules in place (the observed fail-open)",
        bed.load()["chains"]["INPUT"] == [], repr(bed.load()["chains"]["INPUT"]))

print()
print("=== NEW implementation waits and succeeds when the lock is released inside the bound ===")
with tempfile.TemporaryDirectory() as tmp:
    bed = Bed(tmp)
    holder = bed.hold_lock(2)
    rc, out, elapsed = bed.run_new(wait="10")
    holder.wait()
    rules = bed.load()["chains"]["INPUT"]
    chk("exit 0 despite the contention", rc == 0, "rc=%d out=%r" % (rc, out[:200]))
    chk("it actually waited for the holder", elapsed >= 1.2, "%.2fs" % elapsed)
    chk("policy is exactly right afterwards", rules == WANT, repr(rules))

print()
print("=== NEW implementation fails cleanly when the lock is held beyond the bound ===")
with tempfile.TemporaryDirectory() as tmp:
    bed = Bed(tmp)
    holder = bed.hold_lock(8)
    # The -w bound is per call and a run makes up to ten calls, so the AGGREGATE deadline is what
    # keeps the unit inside systemd's start timeout. Both bounds are exercised here.
    rc, out, elapsed = bed.run_new(wait="2", NFM_IPT_DEADLINE=4)
    holder.wait()
    chk("nonzero exit", rc != 0, "rc=%d" % rc)
    chk("the AGGREGATE deadline was honoured, it did not hang", elapsed < 7.0, "%.2fs" % elapsed)
    chk("the failure is observable in the output", "xtables lock" in out or "FAILED" in out, out[:200])
    chk("the aggregate deadline is reported when it trips",
        "deadline exceeded" in out or "xtables lock" in out, out[:300])

print()
print("=== the aggregate deadline keeps a full run well inside systemd's start timeout ===")
with tempfile.TemporaryDirectory() as tmp:
    bed = Bed(tmp)
    holder = bed.hold_lock(12)
    rc, out, elapsed = bed.run_new(wait="10", NFM_IPT_DEADLINE=5)
    holder.wait()
    chk("a permanently held lock cannot stretch past the deadline", elapsed < 9.0, "%.2fs" % elapsed)
    chk("and it still fails rather than reporting success", rc != 0, "rc=%d" % rc)

print()
print("=== partial application can never report success ===")
with tempfile.TemporaryDirectory() as tmp:
    # Fail the FIRST insert (the DROP). The old script continued and exited on the status of its
    # LAST insert, reporting success with the port left open. The new one must refuse.
    bed = Bed(tmp)
    rc_old, out_old, _ = bed.run_old(NFM_FAKE_FAIL_INSERT=1)
    old_rules = bed.load()["chains"]["INPUT"]
    chk("old script reported SUCCESS with a partial policy (the defect)",
        rc_old == 0 and not any("DROP" in r for r in old_rules),
        "rc=%d rules=%r" % (rc_old, old_rules))

with tempfile.TemporaryDirectory() as tmp:
    bed = Bed(tmp)
    rc_new, out_new, _ = bed.run_new(NFM_FAKE_FAIL_INSERT=1)
    new_rules = bed.load()["chains"]["INPUT"]
    chk("new script FAILS instead", rc_new != 0, "rc=%d out=%r" % (rc_new, out_new[:200]))
    chk("and says exactly which part of the invariant is unmet",
        "INVARIANT" in out_new and "DROP count" in out_new, out_new[:300])
    chk("and states the state was left for a re-run", "re-run repairs" in out_new, out_new[:300])
    chk("the DROP is genuinely absent, so the failure was real",
        not any("DROP" in r for r in new_rules), repr(new_rules))

print()
print("=== a re-run repairs the partial state (documented recovery path) ===")
with tempfile.TemporaryDirectory() as tmp:
    bed = Bed(tmp)
    bed.run_new(NFM_FAKE_FAIL_INSERT=1)
    rc, out, _ = bed.run_new()  # no injected failure this time
    chk("second run succeeds", rc == 0, "rc=%d out=%r" % (rc, out[:200]))
    chk("and the policy is exactly right", bed.load()["chains"]["INPUT"] == WANT,
        repr(bed.load()["chains"]["INPUT"]))

print()
print("=== broader exposure is rejected, not tolerated ===")
with tempfile.TemporaryDirectory() as tmp:
    # A fourth, broader rule on the same port must make the invariant fail rather than pass.
    extra = "-p tcp -m tcp --dport %s -j ACCEPT" % PORT
    bed = Bed(tmp, chain_rules=WANT + [extra])
    bed.save({"chains": {"INPUT": WANT + [extra]}, "inserts": 0, "violations": []})
    rc, out, _ = bed.run_new()
    chk("an extra ACCEPT on the port is detected as broader exposure",
        rc != 0 and "no broader exposure" in out, "rc=%d out=%r" % (rc, out[:300]))

print()
if FAILURES:
    print("JARVIS 8808 LOCK TESTS: FAIL (%d)" % len(FAILURES))
    for f in FAILURES:
        print("  - %s" % f)
    sys.exit(1)
print("JARVIS 8808 LOCK TESTS: PASS")
