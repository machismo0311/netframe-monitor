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
# Tailscale's own chain, verbatim in shape from Jarvis. The scripts must never modify it.
TS_INPUT = [
    "-s 100.64.0.6/32 -i lo -j ACCEPT",
    "-i tailscale0 -j ACCEPT",
    "-p udp -m udp --dport 41641 -j ACCEPT",
    "-s 100.115.92.0/23 ! -i tailscale0 -j RETURN",
    "-s 100.64.0.0/10 ! -i tailscale0 -j DROP",
]

FAKE_IPTABLES = r'''#!/usr/bin/env python3
import fcntl, json, os, sys, time

args = sys.argv[1:]
state = os.environ["NFM_FAKE_STATE"]
lockfile = os.environ["NFM_FAKE_LOCK"]
fail_insert = int(os.environ.get("NFM_FAKE_FAIL_INSERT", "0"))
# Deny one -C probe by ordinal, per table, WITHOUT touching the lock, so probe classification can
# be tested in isolation from insert failures. Scoped per table because this script probes the raw
# table inside its fast path.
fail_check = int(os.environ.get("NFM_FAKE_FAIL_CHECK", "0"))
fail_check_raw = int(os.environ.get("NFM_FAKE_FAIL_CHECK_RAW", "0"))
never_delete = os.environ.get("NFM_FAKE_NEVER_DELETE", "")
calls_file = os.environ.get("NFM_FAKE_CALLS", "")

# --- canonical leading global options come BEFORE the operation ---
wait = None
table = "filter"
i = 0
while i < len(args):
    if args[i] == "-t":
        i += 1
        if i < len(args):
            table = args[i]; i += 1
    elif args[i] in ("-w", "--wait"):
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
        fh.write(("wait=%s table=%s " % (wait, table)) + " ".join(args) + "\n")

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
# The raw table is a separate namespace. filter stays at st["chains"] so every pre-existing
# assertion keeps working unchanged.
if table == "filter":
    chains = st["chains"]
else:
    chains = st.setdefault("tables", {}).setdefault(table, {})

if op == "-C" and ((table == "filter" and fail_check) or (table == "raw" and fail_check_raw)):
    key = "checks" if table == "filter" else "checks_raw"
    want = fail_check if table == "filter" else fail_check_raw
    st[key] = st.get(key, 0) + 1
    if st[key] == want:
        save(st)
        sys.stderr.write("Can\'t lock %s: Resource temporarily unavailable\n" % lockfile)
        sys.stderr.write("Another app is currently holding the xtables lock. "
                         "Perhaps you want to use the -w option?\n")
        sys.exit(4)

if op in ("-C", "-D") and chain in chains:
    spec = canon(args[2:])
    rules = chains[chain]
    idx = next((k for k, r in enumerate(rules) if r == spec), None)
    if idx is None:
        rc = 1
    elif op == "-D":
        # NFM_FAKE_NEVER_DELETE models a delete that reports success without removing anything,
        # which is what spun the removal loop before it was bounded.
        if not never_delete:
            rules.pop(idx)
elif op == "-I" and chain in chains:
    st["inserts"] = st.get("inserts", 0) + 1
    if fail_insert and st["inserts"] == fail_insert:
        sys.stderr.write("iptables: simulated insert failure\n")
        rc = 1
    else:
        pos = int(args[2]) - 1
        chains[chain].insert(pos, canon(args[3:]))
elif op == "-S" and chain in chains:
    print("-P %s ACCEPT" % chain)
    for r in chains[chain]:
        print("-A %s %s" % (chain, r))
elif op == "-L" and chain in chains:
    pass
elif op in ("-C", "-D", "-I", "-S", "-L"):
    # A real iptables says so and exits nonzero. Returning 0 here used to make a missing chain
    # look like "rule present AND delete succeeded", which spun the removal loop until the
    # aggregate deadline. Harness fidelity matters: model the system, not the caller.
    sys.stderr.write("iptables: No chain/target/match by that name.\n")
    rc = 1
else:
    st.setdefault("violations", []).append(args)
save(st)
sys.exit(rc)
'''


def chk(label, ok, detail=""):
    """Assert one invariant.

    Kept as a helper so every check label below is preserved verbatim from the
    original suite. It raises instead of appending to a module-level list, so a
    violated invariant is a named FAILED test rather than a collection error.
    """
    assert ok, "%s%s" % (label, (": " + detail) if detail else "")


class Bed:
    """A test bed: fake iptables on PATH, a temp state file, a temp lock file."""

    def __init__(self, tmp, chain_rules=None, raw_rules=None):
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
        # ts-input models the Tailscale-owned chain: tests assert this script never touches it.
        self.save({"chains": {"INPUT": list(chain_rules or []), "ts-input": list(TS_INPUT)},
                   "tables": {"raw": {"PREROUTING": list(raw_rules or [])}},
                   "inserts": 0, "violations": []})

    def save(self, st):
        with open(self.state, "w") as f:
            json.dump(st, f)

    def load(self):
        with open(self.state) as f:
            return json.load(f)

    def raw(self):
        return self.load().get("tables", {}).get("raw", {}).get("PREROUTING", [])

    def tsinput(self):
        return self.load()["chains"].get("ts-input", [])

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


# positive control: establishes exactly the required policy, in order
def test_positive_control_establishes_exact_policy_in_order():
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


# idempotency: a second run changes nothing and stays exact
def test_idempotent_second_run_changes_nothing():
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


# duplicates and wrong order are normalised, not compounded
def test_duplicates_and_wrong_order_are_normalised():
    with tempfile.TemporaryDirectory() as tmp:
        # DROP above the ACCEPTs, plus a duplicate ACCEPT: the exact states the invariant must reject.
        bed = Bed(tmp, chain_rules=[WANT[2], WANT[0], WANT[0], WANT[1]])
        rc, out, _ = bed.run_new()
        rules = bed.load()["chains"]["INPUT"]
        chk("exit 0", rc == 0, "rc=%d out=%r" % (rc, out))
        chk("ends with exactly the three required rules in order", rules == WANT, repr(rules))


# OLD implementation loses the lock race immediately
def test_prefix_control_loses_lock_race_and_fails_open():
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


# NEW implementation waits and succeeds when the lock is released inside the bound
def test_bounded_wait_succeeds_when_lock_released_in_bound():
    with tempfile.TemporaryDirectory() as tmp:
        bed = Bed(tmp)
        holder = bed.hold_lock(2)
        rc, out, elapsed = bed.run_new(wait="10")
        holder.wait()
        rules = bed.load()["chains"]["INPUT"]
        chk("exit 0 despite the contention", rc == 0, "rc=%d out=%r" % (rc, out[:200]))
        chk("it actually waited for the holder", elapsed >= 1.2, "%.2fs" % elapsed)
        chk("policy is exactly right afterwards", rules == WANT, repr(rules))


# NEW implementation fails cleanly when the lock is held beyond the bound
def test_bounded_wait_fails_cleanly_past_bound():
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


# the aggregate deadline keeps a full run well inside systemd's start timeout
def test_aggregate_deadline_bounds_a_held_lock():
    with tempfile.TemporaryDirectory() as tmp:
        bed = Bed(tmp)
        holder = bed.hold_lock(12)
        rc, out, elapsed = bed.run_new(wait="10", NFM_IPT_DEADLINE=5)
        holder.wait()
        chk("a permanently held lock cannot stretch past the deadline", elapsed < 9.0, "%.2fs" % elapsed)
        chk("and it still fails rather than reporting success", rc != 0, "rc=%d" % rc)


# partial application can never report success
def test_prefix_control_reports_success_on_partial_policy():
    with tempfile.TemporaryDirectory() as tmp:
        # Fail the FIRST insert (the DROP). The old script continued and exited on the status of its
        # LAST insert, reporting success with the port left open. The new one must refuse.
        bed = Bed(tmp)
        rc_old, out_old, _ = bed.run_old(NFM_FAKE_FAIL_INSERT=1)
        old_rules = bed.load()["chains"]["INPUT"]
        chk("old script reported SUCCESS with a partial policy (the defect)",
            rc_old == 0 and not any("DROP" in r for r in old_rules),
            "rc=%d rules=%r" % (rc_old, old_rules))


def test_partial_application_refuses_to_report_success():
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


# a re-run repairs the partial state (documented recovery path)
def test_rerun_repairs_partial_state():
    with tempfile.TemporaryDirectory() as tmp:
        bed = Bed(tmp)
        bed.run_new(NFM_FAKE_FAIL_INSERT=1)
        rc, out, _ = bed.run_new()  # no injected failure this time
        chk("second run succeeds", rc == 0, "rc=%d out=%r" % (rc, out[:200]))
        chk("and the policy is exactly right", bed.load()["chains"]["INPUT"] == WANT,
            repr(bed.load()["chains"]["INPUT"]))


# broader exposure is rejected, not tolerated
def test_broader_exposure_is_rejected():
    with tempfile.TemporaryDirectory() as tmp:
        # A fourth, broader rule on the same port must make the invariant fail rather than pass.
        extra = "-p tcp -m tcp --dport %s -j ACCEPT" % PORT
        # Seed through Bed so the raw table and ts-input are present. A manual save() here used to
        # drop both, which modelled the caller instead of the system.
        bed = Bed(tmp, chain_rules=WANT + [extra])
        rc, out, _ = bed.run_new()
        chk("an extra ACCEPT on the port is detected as broader exposure",
            rc != 0 and "no broader exposure" in out, "rc=%d out=%r" % (rc, out[:300]))

TS_TAG = "NFM-%s-TAILNET-DENY" % PORT
FOREIGN_RAW = "-p tcp -m tcp --dport 9999 -i tailscale0 -m comment --comment SOMEONE-ELSE -j DROP"


def ts_rules(bed):
    return [r for r in bed.raw() if TS_TAG in r]


# T   the tailnet denial: placement, idempotency, repair, partial failure
def test_tailnet_denial_placement_and_idempotency():
    with tempfile.TemporaryDirectory() as tmp:
        bed = Bed(tmp, raw_rules=[FOREIGN_RAW])
        rc, out, _ = bed.run_new()
        raw = bed.raw()
        mine = ts_rules(bed)
        chk("T exit 0", rc == 0, "rc=%d out=%r" % (rc, out[:200]))
        chk("T exactly one tailnet denial exists", len(mine) == 1, repr(raw))
        chk("T it denies tcp/%s arriving on tailscale0, and DROPs" % PORT,
            len(mine) == 1 and "-i tailscale0" in mine[0] and "--dport %s " % PORT in mine[0] + " "
            and mine[0].endswith("-j DROP"), repr(mine))
        # Placement is STRUCTURAL, not positional: the raw table is traversed before the filter table,
        # so this rule is always evaluated before ts-input's terminal ACCEPT. There is no ordering
        # contest to assert, which is precisely why this table was chosen.
        chk("T the denial lives in the raw table, which precedes filter (so ts-input cannot pre-empt it)",
            all(TS_TAG not in r for r in bed.load()["chains"]["INPUT"]) and len(mine) == 1,
            repr(bed.load()["chains"]["INPUT"]))
        chk("T an unrelated tailnet rule for another port is untouched", FOREIGN_RAW in raw, repr(raw))
        chk("T Tailscale's own chain is byte-identical, never edited", bed.tsinput() == TS_INPUT,
            repr(bed.tsinput()))
        chk("T localhost remains allowed in filter", WANT[0] in bed.load()["chains"]["INPUT"], repr(WANT[0]))
        chk("T NPM remains allowed in filter", WANT[1] in bed.load()["chains"]["INPUT"], repr(WANT[1]))
        chk("T the filter policy is still exactly the three required rules",
            bed.load()["chains"]["INPUT"][:3] == WANT, repr(bed.load()["chains"]["INPUT"]))
        chk("T the raw calls carried the bounded wait too",
            all("wait=10" in ln for ln in open(bed.calls).read().splitlines() if "table=raw" in ln),
            "".join(ln for ln in open(bed.calls).read().splitlines(True) if "table=raw" in ln)[:200])

        # idempotency
        rc2, out2, _ = bed.run_new()
        chk("T a second run is a no-op and says so", rc2 == 0 and "already correct" in out2, out2[:160])
        chk("T no duplicate denial was created", len(ts_rules(bed)) == 1, repr(bed.raw()))


def test_tailnet_denial_repaired_when_deleted():
    with tempfile.TemporaryDirectory() as tmp:
        # missing-rule repair: an outside actor deletes the denial
        bed = Bed(tmp)
        bed.run_new()
        st = bed.load()
        st["tables"]["raw"]["PREROUTING"] = [r for r in st["tables"]["raw"]["PREROUTING"] if TS_TAG not in r]
        bed.save(st)
        rc, out, _ = bed.run_new()
        chk("T a deleted denial is detected and repaired", rc == 0 and len(ts_rules(bed)) == 1,
            "rc=%d raw=%r" % (rc, bed.raw()))


def test_tailnet_denial_duplicate_normalised():
    with tempfile.TemporaryDirectory() as tmp:
        # a duplicate the script did not create must be normalised back to exactly one
        bed = Bed(tmp)
        bed.run_new()
        st = bed.load()
        dup = [r for r in st["tables"]["raw"]["PREROUTING"] if TS_TAG in r][0]
        st["tables"]["raw"]["PREROUTING"].append(dup)
        bed.save(st)
        rc, out, _ = bed.run_new()
        chk("T a duplicated denial is normalised back to exactly one", rc == 0 and len(ts_rules(bed)) == 1,
            "rc=%d raw=%r" % (rc, bed.raw()))


def test_tailnet_denial_partial_insert_fails_loudly():
    with tempfile.TemporaryDirectory() as tmp:
        # partial application: the raw insert is denied the lock
        bed = Bed(tmp)
        # From a clean chain the inserts are drop, npm, local (filter) then the raw denial: ordinal 4.
        rc, out, _ = bed.run_new(NFM_FAKE_FAIL_INSERT=4)
        chk("T a denied raw insert exits nonzero rather than reporting success", rc != 0,
            "rc=%d out=%r" % (rc, out[:220]))
        chk("T and the invariant names the missing denial",
            "TAILNET-DENY" in out or "tailnet DROP" in out, out[:300])


def test_tailnet_denial_denied_probe_not_read_as_absent():
    with tempfile.TemporaryDirectory() as tmp:
        # A denied raw PROBE must not be read as absence. This needs a state the fast path rejects,
        # otherwise the run exits on the fast path after a single raw probe and ordinal 2 never occurs.
        # Seed a duplicate: the fast path declines (probe 1), then ts_remove_all probes (probe 2),
        # and that is the one denied.
        bed = Bed(tmp)
        bed.run_new()
        st = bed.load()
        dup = [r for r in st["tables"]["raw"]["PREROUTING"] if TS_TAG in r][0]
        st["tables"]["raw"]["PREROUTING"].append(dup)
        bed.save(st)
        rc, out, _ = bed.run_new(NFM_FAKE_FAIL_CHECK_RAW=2)
        # It could not probe that copy, so it could not remove it, and it deliberately still completes
        # the insert. For a DROP that is the fail-SAFE direction: an extra copy still denies, whereas
        # skipping the insert could leave none. So the end state is denied-but-duplicated, reported as
        # a failure, and normalised by a re-run. Same reasoning as the filter path above.
        chk("T a denied raw probe fails loudly rather than reporting success",
            rc != 0, "rc=%d out=%r" % (rc, out[:200]))
        chk("T and the denial is still in force (fail-safe direction)",
            len(ts_rules(bed)) >= 1, repr(bed.raw()))
        chk("T and says it is not treating the raw denial as absence",
            "raw probe failed" in out or "not treating as absent" in out, out[:260])
        rc_fix, _, _ = bed.run_new()
        chk("T and a re-run normalises it back to exactly one denial",
            rc_fix == 0 and len(ts_rules(bed)) == 1, "rc=%d raw=%r" % (rc_fix, bed.raw()))


def test_tailnet_denial_removal_loop_is_bounded():
    with tempfile.TemporaryDirectory() as tmp:
        # The bounded removal loop only engages when a removal is actually required, so seed a
        # duplicate first. With deletes that report success but remove nothing, the loop must give up
        # after MAX_PASSES rather than spin until the aggregate deadline.
        bed = Bed(tmp)
        bed.run_new()
        st = bed.load()
        dup = [r for r in st["tables"]["raw"]["PREROUTING"] if TS_TAG in r][0]
        st["tables"]["raw"]["PREROUTING"].append(dup)
        bed.save(st)
        rc, out, elapsed = bed.run_new(NFM_MAX_PASSES=3, NFM_FAKE_NEVER_DELETE=1)
        chk("T a delete that reports success without removing is bounded, not a spin",
            elapsed < 20.0, "%.1fs" % elapsed)
        chk("T and it is reported as a refusal to spin",
            "refusing to spin" in out or rc != 0, "rc=%d out=%r" % (rc, out[:220]))


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
