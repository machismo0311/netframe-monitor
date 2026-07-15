#!/usr/bin/env python3
"""Deterministic prohibited-recommendation screen (NF-AIOPS-004 safety phase).

WHY THIS EXISTS
---------------
The eval harness asserted a safety property that production did not enforce. Roughly one
run in five, the 7B interpreter recommends an action the knowledge base explicitly
forbids: power-cycling the Wazuh VM (corrupts wazuh-indexer, EVT-004) or replacing a
drive whose SMART pending sectors are benign (EVT-003). The harness caught it; nothing on
the live path did, so that recommendation reached report.md, the web page, and the
operator unfiltered.

This module is the missing enforcement. It sits between LLM output and every user-visible
artifact. It is pure code: no model is asked whether its own output is safe, because a
model that reliably followed the restriction would not have produced the output in the
first place.

DESIGN RULES
------------
1. The model is advisory only. This screen is authoritative.
2. Blocks are NEVER silent. The reader is told a recommendation was withheld, which rule
   fired, and why. Silent removal would leave an operator reading a report with a hole in
   it and no way to know.
3. The original text is preserved in the hash-chained audit ledger, not in the report. It
   is recoverable for review without being placed in front of an operator who might act
   on it.
4. Negation is respected: "do NOT power-cycle" is the correct advice, not a violation.
   Blocking it would punish the model for being right.
5. Evidence-gated rules exist because some actions are legitimate given proof. Drive
   replacement is correct when SMART overall-health actually says FAILED, and wrong when
   it does not (EVT-003). The gate is deterministic, never the model's opinion.

CLI:
  netframe_policy.py screen <file>    # screen a file, print the result
  netframe_policy.py rules            # list the active rules
"""
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Words that flip a trigger from a recommendation into correct advice against it.
# Checked in the same line, before the trigger.
NEGATION_RE = re.compile(
    r"\b(do not|don't|never|avoid|without|rather than|instead of|must not|no need to|"
    r"should not|shouldn't|refrain from|not recommended|prohibited|forbidden|"
    r"do NOT|cannot|can't)\b", re.IGNORECASE)

# Services Jarvis may ever be asked to restart (the Tier-1 allowlist in
# netframe_remediate.py). Anything else named in a systemctl imperative is an
# unauthorized remediation suggestion.
ALLOWED_RESTART_UNITS = {
    "netframe-report-web", "netframe-report-web.service",
    "wazuh-indexer", "wazuh-indexer.service",
}


def _no_negation(line):
    """True when the line is an affirmative recommendation, not advice against one."""
    return not NEGATION_RE.search(line)


def _drive_replacement_unevidenced(line, evidence):
    """Drive replacement is a Tier-2 hardware action. It is only evidenced by an explicit
    SMART overall-health FAILED. Pending/reallocated sector counts are NOT sufficient:
    EVT-003 is precisely a benign pending count on /dev/sdc that a model read as failure.
    """
    return not (evidence or {}).get("smart_health_failed", False)


def _unauthorized_restart(line, evidence):
    """A systemctl imperative naming a unit outside the Tier-1 allowlist."""
    for m in re.finditer(r"systemctl\s+(?:restart|stop|disable|mask)\s+([\w.@-]+)", line,
                         re.IGNORECASE):
        if m.group(1).lower() not in ALLOWED_RESTART_UNITS:
            return True
    return False


# Each rule: id, human name, trigger regex, why it is prohibited, and an optional
# `blocked_if` predicate for rules that are conditional rather than absolute.
RULES = [
    {
        "id": "POL-001",
        "name": "power-cycle / hard reset",
        "pattern": re.compile(
            r"\b(power[-\s]?cycl(?:e|es|ing|ed)|hard[-\s]?reset|force[-\s]?(?:reboot|reset|"
            r"stop)|pull(?:ing)? the power|qm\s+reset|cold[-\s]?boot)\b", re.IGNORECASE),
        "why": ("Power-cycling risks an unclean shutdown. On the Wazuh VM this is the known "
                "cause of wazuh-indexer corruption (EVT-004); the correct action is an "
                "in-place graceful restart via the gated allowlist."),
        "ref": "EVT-004",
    },
    {
        "id": "POL-002",
        "name": "drive replacement without evidence",
        "pattern": re.compile(
            r"\b(replac\w*|swap\w*|RMA|pull\w*|remov\w*)\b[^.\n]{0,60}?"
            r"\b(drive|disk|hdd|ssd|/dev/sd[a-z]|sd[a-z]\b)", re.IGNORECASE),
        "why": ("Drive replacement is a Tier-2 hardware action and is only evidenced by an "
                "explicit SMART overall-health FAILED. Pending or reallocated sector counts "
                "alone are not evidence (EVT-003: /dev/sdc's pending count is benign)."),
        "ref": "EVT-003",
        "blocked_if": _drive_replacement_unevidenced,
    },
    {
        "id": "POL-003",
        "name": "destructive storage action",
        # NB: each alternative carries its own boundaries. A single trailing \b on the
        # group silently breaks alternatives ending in a non-word char: `dd if=` followed
        # by `/dev/zero` has no boundary between `=` and `/`, so it escaped the screen
        # entirely until a test caught it.
        "pattern": re.compile(
            r"(\bzpool\s+(?:destroy|remove|labelclear|split)\b|\bzfs\s+destroy\b|\bmkfs\b|"
            r"\bmke2fs\b|\bfsck\b|\bwipefs\b|\bdd\s+if=|\brm\s+-rf\b|"
            r"\bformat\s+the\s+(?:drive|disk|pool)\b|\bzpool\s+clear\s+-F\b)",
            re.IGNORECASE),
        "why": ("Irreversible storage operation. ZFS in particular never requires fsck, and "
                "these commands can destroy a pool outright. Storage actions are Tier 2: "
                "human-executed only, never suggested as a routine step."),
        "ref": "constitution/authority_limits",
    },
    {
        "id": "POL-004",
        "name": "firewall change",
        "pattern": re.compile(
            r"\b(iptables\s+-F|flush\s+(?:the\s+)?(?:firewall|iptables)|disable\s+the\s+"
            r"firewall|ufw\s+disable|pve-firewall\s+stop|allow\s+all\s+(?:traffic|inbound)|"
            r"open\s+(?:the\s+)?(?:port|firewall)|add\s+(?:a\s+)?firewall\s+rule)\b",
            re.IGNORECASE),
        "why": ("Firewall mutation is on the Constitution's never-list. The :8000/:8808/:8809 "
                "allowlists are the only thing standing between unauthenticated services and "
                "the LAN."),
        "ref": "constitution/authority_limits",
    },
    {
        "id": "POL-005",
        "name": "DNS change",
        # Boundaries are per-alternative, not on the group. A leading \b before an
        # alternation containing `/etc/resolv.conf` never matches: the char before `/` is
        # usually a space, and space->/ is not a word boundary, so the whole branch was
        # dead. Same class of bug as the trailing \b in POL-003, mirrored.
        "pattern": re.compile(
            r"(?:\bchang\w*|\bmodif\w*|\bedit\w*|\bupdat\w*|\bdelet\w*|\bremov\w*|\badd\w*|"
            r"\bpoint\w*)[^.\n]{0,50}?"
            r"(?:\bdns\s+record\b|\bdns\.hosts\b|\bpi-?hole\b|\bnameserver\b|\bresolver\b|"
            r"\blocal\s+dns\b|/etc/resolv\.conf)", re.IGNORECASE),
        "why": ("DNS mutation is on the Constitution's never-list. A DNS gap silently broke "
                "vault/grafana/wazuh LAN-wide on 2026-07-15, and Vaultwarden being "
                "unreachable is a DR trap."),
        "ref": "constitution/authority_limits",
    },
    {
        "id": "POL-006",
        "name": "destructive Proxmox action",
        "pattern": re.compile(
            r"\b(qm\s+destroy|pct\s+destroy|pvecm\s+delnode|lvremove|vgremove|pvremove|"
            r"pveceph\s+destroy|qm\s+stop|pct\s+stop|remove\s+the\s+(?:node|guest|vm))\b",
            re.IGNORECASE),
        "why": ("Destructive Proxmox operation. Guest/node removal and forced stops are "
                "Tier 2 and can cost quorum or data; they are never Jarvis's to suggest as "
                "an action."),
        "ref": "constitution/authority_limits",
    },
    {
        "id": "POL-007",
        "name": "unauthorized remediation",
        "pattern": re.compile(r"systemctl\s+(?:restart|stop|disable|mask)\s+[\w.@-]+",
                              re.IGNORECASE),
        "why": ("Names a unit outside the Tier-1 allowlist (rerun-health-check, "
                "restart-report-web, restart-wazuh-indexer). Jarvis may only ever propose "
                "allowlisted actions, and only for explicit human approval."),
        "ref": "constitution/authority_limits",
        "blocked_if": _unauthorized_restart,
    },
    {
        "id": "POL-008",
        "name": "destructive rebuild / reinstall",
        "pattern": re.compile(
            r"\b(reinstall\w*|re-?install\w*|rebuild\w*|recreat\w*|re-?provision\w*|"
            r"reimage\w*|re-?image\w*|wipe\s+and\s+\w+|start\s+from\s+scratch)\b",
            re.IGNORECASE),
        "why": ("Rebuilding or reinstalling a service, guest or node is a Tier-2 action with "
                "an enormous blast radius, and it is almost always proposed in place of "
                "diagnosis. Jarvis may only ever propose the Tier-1 allowlist."),
        "ref": "constitution/authority_limits",
    },
    {
        "id": "POL-009",
        "name": "unevidenced hardware-failure claim",
        # Not an action, but the PREDICATE for one. EVT-003 is exactly this: the model
        # reads benign pending sectors as a dying disk, and an operator who believes the
        # claim performs the destructive action themselves. Blocking the recommendation
        # while leaving the false claim standing would just launder it through the human.
        "pattern": re.compile(
            r"\b(imminent\s+failure|about\s+to\s+fail|going\s+to\s+fail|will\s+fail\s+soon|"
            r"failing\s+(?:drive|disk|hdd|ssd)|(?:drive|disk|hdd|ssd)\s+is\s+failing|"
            r"pre-?fail(?:ure|ing)?|on\s+the\s+verge\s+of\s+failure|imminent\s+drive\s+"
            r"failure|dying\s+(?:drive|disk))\b", re.IGNORECASE),
        "why": ("Asserts hardware failure without an explicit SMART overall-health FAILED. "
                "Pending or reallocated sector counts alone are not evidence (EVT-003: "
                "/dev/sdc's pending count is benign and stable). An unevidenced failure "
                "claim leads the operator to the destructive action themselves."),
        "ref": "EVT-003",
        "blocked_if": _drive_replacement_unevidenced,
    },
]


def evaluate_line(line, evidence=None):
    """-> list of rules this line violates (usually 0 or 1). Deterministic, no model."""
    if not line.strip():
        return []
    if NOTICE_SENTINEL in line:
        return []  # already blocked; do not re-block our own notice (see NOTICE_SENTINEL)
    hits = []
    for rule in RULES:
        if not rule["pattern"].search(line):
            continue
        # "do not power-cycle" is the correct advice, not a violation.
        if not _no_negation(line):
            continue
        pred = rule.get("blocked_if")
        if pred and not pred(line, evidence):
            continue
        hits.append(rule)
    return hits


# Sentinel marking a line this screen already replaced. Screening is IDEMPOTENT: a notice
# necessarily quotes the trigger it blocked ("power-cycle / hard reset"), so without this
# a second pass would block its own output forever. It also lets a caller ask the only
# question that matters - "is there an UNBLOCKED prohibited recommendation in this
# artifact?" - by simply re-screening it.
NOTICE_SENTINEL = "[BLOCKED - Jarvis policy"


def _notice(rule):
    return (f"> **[BLOCKED - Jarvis policy {rule['id']}: {rule['name']}]** A recommendation "
            f"was withheld here because it violates policy. {rule['why']} "
            f"(ref: `{rule['ref']}`)\n>\n"
            f"> The original wording is preserved in the audit ledger (`policy_block`, rule "
            f"{rule['id']}) rather than shown, so it cannot be acted on by mistake. Jarvis "
            f"is advisory only and never executes prohibited actions.")


def screen(text, evidence=None, audit=True, source="interpreter"):
    """Screen LLM prose before it reaches a user-visible artifact.

    Returns {"text", "blocked", "clean"}:
      text    - the artifact-safe text, with each violating line replaced by a visible
                block notice (never silently dropped)
      blocked - [{rule_id, name, why, ref, original, line_no}] for the audit trail
      clean   - True when nothing was blocked
    """
    out, blocked = [], []
    for i, line in enumerate(text.splitlines(), 1):
        hits = evaluate_line(line, evidence)
        if not hits:
            out.append(line)
            continue
        rule = hits[0]
        blocked.append({"rule_id": rule["id"], "name": rule["name"], "why": rule["why"],
                        "ref": rule["ref"], "original": line.strip(), "line_no": i})
        out.append(_notice(rule))
    text_out = "\n".join(out)
    if blocked:
        text_out += _summary(blocked)
        if audit:
            _audit(blocked, source)
    return {"text": text_out, "blocked": blocked, "clean": not blocked}


def _summary(blocked):
    rules = ", ".join(sorted({b["rule_id"] for b in blocked}))
    return ("\n\n---\n\n## Policy enforcement (deterministic, not LLM-generated)\n\n"
            f"**{len(blocked)} recommendation(s) were blocked before reaching this report.** "
            f"Rules triggered: {rules}.\n\n"
            "This screen is code, not model judgement: the model is advisory only and does "
            "not enforce its own restrictions. A block means the model proposed an action "
            "that Jarvis policy forbids; it does not mean the underlying observation was "
            "wrong. The original wording is preserved in the hash-chained audit ledger "
            "(`netframe_audit.py verify`) for review.\n")


def _audit(blocked, source):
    """Preserve originals in the hash-chained, Loki-mirrored ledger. Never fatal: a screen
    that crashes the report would be a denial of service on the safety feature itself."""
    try:
        import netframe_audit
        for b in blocked:
            netframe_audit.record("policy_block", source=source, rule=b["rule_id"],
                                  rule_name=b["name"], ref=b["ref"],
                                  original=b["original"], line_no=b["line_no"])
    except Exception as exc:  # noqa: BLE001
        print(f"WARN: policy block not audited: {exc}", file=sys.stderr)


def evidence_from_state(state):
    """Deterministic evidence for the evidence-gated rules, derived from telemetry only.

    smart_health_failed is true ONLY on an explicit SMART overall-health FAILED. Sector
    counts deliberately do not qualify (EVT-003).
    """
    failed = False
    for checks in (state or {}).get("nodes", {}).values():
        raw = str(checks.get("smart", {}).get("raw_excerpt", ""))
        if re.search(r"self-assessment test result:\s*FAILED", raw, re.IGNORECASE):
            failed = True
    return {"smart_health_failed": failed}


def main():
    if len(sys.argv) > 2 and sys.argv[1] == "screen":
        with open(sys.argv[2]) as fh:
            r = screen(fh.read(), audit=False)
        print(r["text"])
        print(f"\n-- {len(r['blocked'])} blocked", file=sys.stderr)
    elif len(sys.argv) > 1 and sys.argv[1] == "rules":
        for r in RULES:
            gate = " (evidence-gated)" if r.get("blocked_if") else ""
            print(f"  {r['id']}  {r['name']}{gate}\n      {r['why'][:96]}...")
    else:
        print(__doc__)


if __name__ == "__main__":
    main()
