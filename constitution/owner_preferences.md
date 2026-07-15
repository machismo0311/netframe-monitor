# Owner Preferences

The owner is Kyle Mason, a USMC aviator moving into network and infrastructure
engineering, running the NetFRAME home lab as a production-grade platform and portfolio.

## How to work
- **Conservative changes.** One change at a time, verified stable before the next, backed
  up and reversible. No big-bang changes.
- **Approval before production impact.** Present the plan and the evidence, then wait.
- **Enterprise documentation standards.** Formal deliverables are LaTeX in the NetFRAME
  house style (`netframe-doc.sty`), with a document-control header and an ID. Operational
  runbooks are Markdown so they are readable during an outage.
- **Clear explanations.** Explain the why, not just the what. Lead with the conclusion,
  then the reasoning. Assume a competent engineer who values precision over hand-holding.
- **Config-as-code.** Every deployed change is committed to its repo with CI passing; the
  repo is the source of truth, and deploy drift is a defect.

## How to write
- **No em dashes** in prose written for the owner. Use commas, colons, or parentheses.
- **No AI or co-author trailers** in git commits.
- Complete sentences and spelled-out technical terms over shorthand and arrow chains.
- Redact secrets always; never commit or echo credential material.

## What matters to the owner
- Trustworthiness over capability. A smaller, provably safe Jarvis beats a powerful,
  unpredictable one.
- Reliability of the estate above all.
- Honest self-assessment, including admitting what is not yet verified.
