# NetFRAME Platform Roadmap

What is being built, what has shipped, and what comes next.

This is a public engineering roadmap written for readers who want to understand the direction of
the work. It deliberately contains no addressing, topology, host identifiers, or operational
procedures: those live in private documentation, and deciding what to withhold is treated as part
of the engineering rather than an afterthought.

---

## Current focus

**Making operational tooling trustworthy rather than merely capable.**

The central problem is that operational tooling is confident. It reports healthy when it has no
data, averages away the one measurement that mattered, and answers questions it has no basis to
answer. Every one of those failures looks exactly like success.

The current work separates three concerns that are usually tangled together:

- a **deterministic policy engine** decides what is allowed, and is never delegated to a model
- an **evidence engine** scores how well-supported a conclusion is, and how certain
- a **language model** is reduced to choosing the wording, and is never an evidentiary source

Alongside this sits a deterministic investigation engine that replays recorded incidents
byte-for-byte, so a diagnosis can be reproduced rather than trusted.

## Major milestones delivered

| Area | Milestone |
|---|---|
| Compute | Commissioned two GPU compute nodes and brought a 72B-parameter model into production inference behind an OpenAI-compatible routing layer |
| Multi-tenancy | Shared a single research GPU between production research and a university teaching cohort, with hard per-job memory caps, container isolation, and research workloads preempting and requeueing student jobs |
| Networking | Migrated the estate to VLAN-segmented enterprise switching, and built a virtual network lab that boots a routed topology and asserts real reachability in CI |
| Documentation | Diagram-as-code topology generated from a source-of-truth inventory, with CI failing the build when the picture drifts from the truth |
| Observability | Full metrics, logs, and alerting stack with alert routing, plus device-level fault detection that closed a real blind spot |
| Reliability | Tested backup and restore tiering, formal after-action reviews, and an append-only change log with a stated rollback for every change |
| Governance | Evidence-based certification model, architecture decision records, and change management with a defined lifecycle |
| AI operations | Guardrail program covering admission, policy, evidence scoring, audit trail, and fixture-driven evaluation in CI |

## Platform roadmap

**Near term**

- High availability for the network edge, removing remaining single points of failure in routing and DNS
- Expanded off-site backup tier to complete a full 3-2-1 posture
- Detection engineering: moving from health-only alerting toward behavioural detections with tested runbooks
- Publication tooling: a fail-closed release gate so public documentation can be verified rather than reviewed by eye

**Medium term**

- Network core upgrade with the aggregation layer moved onto higher-capacity switching
- Storage pool expansion and capacity planning driven by measured growth rather than estimates
- Broader configuration-as-code coverage, with drift detection reporting against an expected baseline

**Longer term**

- Continuous assurance: automatically and repeatedly answering whether live reality still matches what the documentation claims, and reporting `UNKNOWN` where it cannot tell
- Operator interface work so the platform can be asked questions in plain language, with every answer carrying its evidence and its provenance

## Research areas

- **Multi-tenant GPU scheduling.** Sharing one accelerator between research and teaching without either starving the other, on hardware that predates native partitioning.
- **Retrieval over operational documentation.** Grounding a model in the estate's own written record so answers cite a source rather than sounding plausible.
- **Deterministic investigation and replay.** Treating an investigation as a recorded artifact that reproduces identically on any machine, which makes a diagnosis reviewable.
- **Provenance-typed evidence.** Every claim carries whether it was measured, inferred, assumed, or is unknown, and answer strength is the weakest claim rather than the strongest.

## Upcoming capabilities

- Continuous assurance reporting with explicit `UNKNOWN` states rather than optimistic defaults
- A published, offline-runnable demonstration of the investigation and evidence model
- Deeper mutation testing coverage, including of the release tooling itself
- Structured incident memory so recurring failure classes are detected as classes, not as unrelated events

## Technical debt, by category

Tracked openly at the category level. Specific items, triggers, and affected components are held
privately.

| Category | Nature of the work |
|---|---|
| Test coverage | Older modules predate the current testing standard and need mutation coverage brought to parity |
| Package structure | Some components accreted as flat module sets and warrant packaging for clearer ownership |
| Interface consolidation | More than one retrieval path exists where a single seam is intended |
| Documentation currency | A small number of documents describe intended rather than implemented behaviour, and are being separated explicitly |
| Automation coverage | Several routine procedures remain manual and are candidates for codification |
| Dependency hygiene | Version and provenance pinning is being extended across the toolchain |

Debt is recorded with the trigger that would make it urgent, rather than as an undifferentiated
backlog, so deferral is a decision rather than a drift.

## Future work

The longer arc is to treat a personally operated estate with the same discipline a regulated
production environment would require: changes gated and reversible, claims backed by evidence,
incidents leaving behind an enforced invariant rather than a memory, and documentation that fails
a build when it stops being true.

---

*Operational status, remediation queues, and estate-specific detail are maintained in private
documentation and are intentionally not published here.*
