---
description: "Record human statements on findings as decisions in traust-core and report their current state."
---

Record human triage feedback against the findings of an audited repository and report their current state. Load the skill at .claude/skills/track-findings/SKILL.md and follow its full procedure — $ARGUMENTS should name the repository (its https URL, or an audit report whose labels to resolve) followed by zero or more sources: merge-request/PR URLs, commit SHAs, Jira keys, or --interactive for a triage session with the person. Each confirmed statement becomes a decision in traust-core through `traust findings decide`, recorded as the logged-in caller (`traust auth`); the skill records only explicit statements from identifiable owners or maintainers and asks about everything else. Machine reports (triage, validation, verification) record through their own skills.
