# Student Onboarding/Offboarding Automation - Build Plan

**Goal (Kyle, 2026-07-15):** students get the Student Guide PDF on day one; they send
back their info; Kyle compiles a **master list** (roster). An Ansible playbook reads
that roster and **builds everything out automatically** - onboard, and on leaving the
class, **revoke the key and wipe the account**. Kyle does nothing per-student beyond
maintaining the roster.

**Status: blocked only on the real student roster.** Everything below can be built
and tested with fake entries before the class starts.

The lifecycle:
```
PDF handed out -> student returns {name, email, pubkey} -> Kyle adds row to roster
   -> playbook run -> account live (key loaded, welcome note generated)
student leaves / semester ends -> roster row flipped to left -> playbook run
   -> key revoked, sessions+jobs killed, home+scratch wiped, (later) Access seat freed
```

---

## Phase 0 - Decisions (need Kyle, ~10 min, before any build)

- [ ] **0.1 Roster storage.** The roster holds PII (names, emails) so it CANNOT go in
      the public Home-Lab repo in the clear. Recommended: **ansible-vault-encrypted
      `roster.yml`** inside `Home-Lab/playbooks` (vault password already exists at
      Ares `~/.config/ansible/vault-pass`, gitignored; same pattern as the existing
      vault). Alternative: plaintext roster in a private repo (netframe-monitor) or
      Ares-local only (restic-backed). Pick one.
- [ ] **0.2 Roster format.** Proposed YAML, one entry per student:
      ```yaml
      semester: 2026-fall
      students:
        - user: student01          # assigned slot (or "auto" for next free)
          name: Alice Example
          email: alice@example.edu # needed later for Cloudflare Access
          discord: alice#1234      # optional, where help requests come from
          pubkey: "ssh-ed25519 AAAA... alice@laptop"
          status: active           # active | left
      ```
- [ ] **0.3 Offboard trigger semantics.** Recommended: wipe ONLY rows explicitly
      marked `status: left` (or a `--limit`-style var), never "anyone missing from
      the roster" - a typo must not be able to wipe a home. Confirm.
- [ ] **0.4 What "wipe" means.** Recommended: clear `authorized_keys`, kill jobs +
      sessions, delete contents of `/workspace/students/<u>/` and
      `/workspace/scratch/<u>/`, re-create clean skeleton, keep the Linux account
      itself (generic `student01`-`20` slots get reused next class). Homes are
      PBS-backed nightly, so pre-wipe archives are redundant IF the backup is fresh
      (see 2.6). Confirm no extra archive wanted.

## Phase 1 - Collection pipeline (the "master list" inputs)

- [ ] **1.1 Update the Student Guide PDF ask.** The guide currently tells students to
      send "the key line + your name". It must ask for everything the roster needs:
      **full name, email, pubkey** (Discord handle implicit). One-line edit in
      `QuarkyLab-Student-Guide.tex` Step 1 + recompile.
- [ ] **1.2 Roster template file** committed next to the playbook (empty, with the
      0.2 schema + comments) so filling it is copy-paste per student.
- [ ] **1.3 (Optional QoL)** a tiny `roster-add.sh` prompt script on Ares that
      appends a validated entry (checks pubkey with `ssh-keygen -l`, picks next free
      slot) so Kyle never hand-edits YAML on his phone.

## Phase 2 - The Ansible role (`student_access` in `Home-Lab/playbooks`)

- [ ] **2.1 Inventory + plumbing.** Add QuarkyLab (`192.168.10.179`, root) to the
      playbooks inventory (hardening role already reaches the fleet from Ares).
      New playbook `student-access.yml` -> role `student_access`, reads the
      vaulted roster.
- [ ] **2.2 Guardrails first.** Role refuses to touch any account not matching
      `^student[0-9]{2}$` (hard allowlist; fernanda/researchers/admins can never be
      wiped by it). All destructive tasks gated behind `-e confirm_offboard=yes`
      AND per-user `status: left`. Full `--check` (dry-run) support; dry-run prints
      an exact action plan.
- [ ] **2.3 Onboard tasks** (per `status: active` row): validate pubkey
      (`ssh-keygen -l` via a validation task), assert the account exists and is in
      group `students`, write `~/.ssh/authorized_keys` with the `authorized_key`
      module using `exclusive: yes` (the roster becomes the ONLY source of truth -
      key rotation and revocation are both just roster edits), enforce dir/file
      modes (700/600), ensure `/workspace/scratch/<u>` exists.
- [ ] **2.4 Offboard tasks** (per `status: left` row, gated by 2.2):
      `scancel -u <user>` (kill queued+running SLURM jobs),
      `loginctl terminate-user` + `pkill -u` (kill live sessions),
      remove `authorized_keys`, wipe `/workspace/students/<u>/*` and
      `/workspace/scratch/<u>/*`, restore skeleton + ownership.
- [ ] **2.5 Welcome output.** For each newly-onboarded student, generate a
      ready-to-paste Discord message (their username + the 3 client steps) into a
      local `out/welcome-<user>.txt` on Ares - so "send them their username" is
      copy-paste, not composition.
- [ ] **2.6 Pre-wipe backup assert.** Before any wipe, check the PBS
      `quarkylab-workspace` snapshot is <24h old (query via
      `proxmox-backup-client snapshot list` or the backup_verify JSON on Randy);
      abort the wipe if stale. This makes offboarding safe even if a student asks
      for their files back later.
- [ ] **2.7 Discord summary.** Reuse the `/etc/quarkylab-alert.conf` webhook to post
      "onboarded N / offboarded M / unchanged K" after each run.
- [ ] **2.8 Idempotency test.** Two consecutive runs -> second run reports zero
      changes.

## Phase 3 - Validation (before real students)

- [ ] **3.1 End-to-end fake-student drill** (repeat of the 2026-07-15 manual dry-run,
      but via the playbook): fake entry -> run -> tunnel SSH as that student ->
      sbatch test job -> flip `status: left` -> run with confirm -> verify login
      DENIED, jobs gone, home+scratch empty, PBS snapshot still has the files.
- [ ] **3.2 Guardrail tests:** roster typo (bad user name) -> refused; run without
      `confirm_offboard` -> no wipe; `--check` -> zero changes on the box.
- [ ] **3.3 CI:** yamllint/ansible-lint pass (match existing playbooks CI).

## Phase 4 - Integrations (after core works)

- [ ] **4.1 Cloudflare Access sync** (blocked on the Zero-Trust signup + card):
      task to add `status: active` emails to / remove `left` emails from the Access
      policy via the CF API. Removing a user frees their seat, so the 50-seat pool
      recycles every semester. Until then, key-only gating means onboard/offboard
      is complete without this.
- [ ] **4.2 Runbook updates:** `QuarkyLab-Account-Onboarding.md` gets a "primary
      path = playbook, manual `add-cluster-key.sh` = fallback" section; semester
      start/end checklists (start: roster -> run -> hand out welcomes; end: flip
      all to `left` -> confirm run -> verify Access seats freed).
- [ ] **4.3 Semester-close extras (optional):** class-wide `sacct` usage report
      (per-student GPU-hours from SLURM accounting + `ac -p` connect time) as a
      end-of-class artifact.

---

## Bulletproofing (Kyle asked for these 2026-07-15, fold into the phases at build time)

- [ ] **B.1 Quarantine before wipe:** offboard = revoke key + kill sessions NOW; the
      home/scratch wipe runs after a grace period (~14 days) via a dated marker file
      + timer or a second playbook pass. Students always ask for files after finals.
- [ ] **B.2 Permanent canary student:** reserve one slot (e.g. `student20`) for
      monitoring - a daily timer does a real tunnel login + tiny sbatch job and
      alerts on failure, so a broken student path is an alert, not 20 confused
      students. Integrate with netframe_monitor.
- [ ] **B.3 Roster lint gate:** playbook refuses to run unless the roster validates -
      pubkeys parse, NO duplicate pubkeys across users, no duplicate slots, unique
      emails, active count <= 20, semester ID matches an expected var.
- [ ] **B.4 Tunnel = SPOF, monitor it:** netframe_monitor service check + Grafana
      alert on the `cloudflared` unit on QuarkyLab (single ingress for the class).
      Canary (B.2) covers end-to-end; this covers fast detection.
- [ ] **B.5 Enable Cloudflare Access BEFORE the semester** (the Zero-Trust signup +
      card is the only external dependency; don't do it the week students arrive).
- [ ] **B.6 Restore drill in the semester-close checklist:** after the end-of-class
      wipe, restore one wiped home from PBS and diff it - keeps the B.1 grace-period
      promise honest (pattern: the 2026-07-02 fernanda restore drill).
- [ ] **B.7 Audit for free:** the roster lives in git, so every onboard/offboard has
      a commit trail; tag the repo at semester close (`2026-fall-end`).

**Definition of done:** Kyle's only per-student actions all semester are (1) paste a
returned info blob into the roster and (2) run one command (or let a timer run it).
Everything else - keys, welcome messages, revocation, wipes, alerts, Access seats -
is the playbook's job.
