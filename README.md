# NetFRAME Monitor

**A read-only health monitor with guardrails on the AI.** It collects diagnostics from every node
in a 7-node cluster over SSH as a low-privilege user, then produces a written health report. The
part worth reading is the trust model: a **deterministic policy engine** decides what is allowed, an
**evidence engine** scores how well-supported a claim is, and the language model is reduced to
choosing the wording. The model is never an evidentiary source and can never authorize an action.

Read-only by construction. Nothing in the collection path can change the estate.

> These files are the source of truth for what is deployed on the monitoring host. **Secrets,
> runtime state, and estate-specific configuration are intentionally not in this repo**, see
> [Not included](#not-included-generated--secret). Hosts are referred to by role rather than by
> name or address throughout.

## Architecture

| Layer | Module | Responsibility |
|---|---|---|
| Collection | `netframe_monitor.py` | SSHes each node, runs read-only checks, parses metrics, appends history |
| Admission | `netframe_admission.py` | Decides what may enter the pipeline at all |
| Policy | `netframe_policy.py` | Deterministic "is this allowed?" Never delegated to the model |
| Evidence | `netframe_evidence.py` | Scores how well-supported a conclusion is, and how certain |
| Audit | `netframe_audit.py` | Append-only record of what was decided and why |
| Drift | `netframe_confdrift.py` | Detects configuration drift against the expected baseline |
| Interpretation | `netframe_interpret.py` | Calls a local LLM for phrasing only; falls back to a deterministic report if the model is unavailable |

Behaviour is pinned by fixtures rather than asserted: `eval/policy-fixtures.json` and
`eval/evidence-fixtures.json` are evaluated in CI, and `constitution/authority_limits.md` states
in one place what this system may and may not do.

## Documentation

- **[Session Build Report](docs/SESSION-BUILD-REPORT-2026-07-15.md)** - the AI-Ops trustworthiness
  program: every issue, its root cause and remedy (13 issues), the guardrails installed, the bugs
  the tooling caught before they shipped, a full PR index, and the end-of-session risk register.
- **[Disaster Recovery](docs/DISASTER-RECOVERY.md)** - rebuild-after-total-loss runbook (RTO/RPO,
  self-service restore).
- **[Platform Roadmap](docs/ROADMAP.md)** - current engineering focus, delivered milestones,
  research areas, and what is being built next.
- A **sanitized public edition** of the build report lives in the Home-Lab repo:
  [AI-Ops trustworthiness case study](https://github.com/machismo0311/Home-Lab/blob/main/docs/aiops-trustworthiness-case-study-2026-07-15.md).

## Components

| File | Role |
|---|---|
| `netframe_monitor.py` | Collector. Runs read-only checks (`df`, `journalctl -p err`, `smartctl -H -A`, `zpool`, backup datastores, `nvidia-smi`, guest liveness, service health endpoints), parses numeric metrics, writes the latest run and appends history. |
| `netframe_interpret.py` | Interpreter. Diffs the latest run against the previous one plus window trends, calls a **local** LLM bound to loopback, renders the report. Falls back to a deterministic report if the model is down. |
| `netframe-run.sh` | `ExecStart` wrapper. Runs the collector then the interpreter (the interpreter always runs, even if the collector exits non-zero). |
| `netframe-8808-lock.sh` | Idempotent host-local firewall lock. Restricts the backend report port to the reverse proxy and localhost only. |
| `systemd/*.service`, `*.timer` | Oneshot plus timer (every 15 minutes) and the report web service, rooted **only** at the rendered output directory so keys and state are never served. |

## Access model

- The report is published through a reverse proxy that terminates TLS and enforces
  authentication. The backend is not reachable directly: a host-local firewall rule permits only
  the reverse proxy and localhost.
- The DNS record resolves to a private address, so the page is reachable over the private overlay
  network rather than the public internet.
- **Self-guard.** The monitor independently verifies that authentication is actually being
  enforced on the published page, and raises a warning if an unauthenticated request is ever
  served. A control that is not continuously verified is an assumption, not a control.

## Service checks (tiered)

Beyond host health, the collector tracks the observability stack in three tiers:

- **Tier 1, guest liveness.** From the hypervisor, a scoped list command confirms every guest named
  in the monitored set is running.
- **Tier 2, service health.** Application health endpoints probed over the network.
- **Tier 3, service-internal health.** Where a service binds to loopback inside a container, it is
  probed from *inside* that container through a **fixed, root-owned wrapper that accepts no
  arguments**, so no loopback binding is relaxed and the monitor cannot pass anything of its own
  choosing. DNS services are probed by their actual function, a real DNS answer, rather than by
  process liveness.

## Least privilege

The `monitor` account is granted `NOPASSWD` sudo **only for exact commands**, never for blanket
virtualization verbs that could start, stop, or destroy guests:

| Node role | Granted commands |
|---|---|
| Service host | `journalctl`, `smartctl`, scoped guest-list, fixed health wrapper |
| GPU / compute host | `journalctl`, `smartctl`, `zpool`, scoped guest-list |
| Storage host | `journalctl`, `smartctl`, `zpool`, backup manager |
| SIEM guest | a single status command (disk usage runs unprivileged) |
| Remaining nodes | `journalctl`, `smartctl` |

The pinning is deliberate. A bare `journalctl` grant is a pager shell-escape away from interactive
root, so each grant is pinned to the daemon's exact invocation rather than to the binary.

## Deploy / update

```bash
# from this directory, on a host with ssh access to the monitoring host
scp *.py netframe-run.sh netframe-8808-lock.sh netframe-console-lock.sh \
    <monitor-host>:/opt/netframe-monitor/
scp systemd/*.service systemd/*.timer systemd/*.path <monitor-host>:/etc/systemd/system/
ssh <monitor-host> 'chmod +x /opt/netframe-monitor/*.sh && systemctl daemon-reload \
    && systemctl enable --now netframe-monitor.timer netframe-report-web.service \
       netframe-8808-lock.service netframe-console.service netframe-console-reload.path'
```

> **The ops console is a long-lived daemon** (`Type=simple`): it imports its Python modules once at
> startup, so copying new code does not take effect until a restart, unlike the oneshot report
> timers that re-exec each run. This is handled automatically by a `.path` unit that watches the
> console's source files and does a debounced restart on any change. (It will not resurrect a
> console you deliberately stopped.)

## Not included (generated / secret)

Kept on the monitoring host only, never committed:

- The `monitor` SSH keypair.
- Runtime state and output: latest run, history, rendered report.
- Standing operational context fed to the interpreter, sourced from the vault, not duplicated here.
- All estate-specific addressing, hostnames, and guest identifiers.
