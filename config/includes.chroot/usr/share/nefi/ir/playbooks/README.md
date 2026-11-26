# NEFI incident response playbooks

One YAML file per playbook. Your own playbooks go in `/etc/nefi/ir/playbooks/` (same format; a file
with the same `id` replaces the built-in one).

```yaml
id: my-playbook              # lowercase letters, digits, - and _
title: Shown in the Security Center
description: When to use it
categories: [malware]        # incident categories it is suggested for
steps:
  - id: first-step
    phase: Containment       # free text, groups the steps
    title: What to do
    help: How to do it and why
    page: contain            # optional: page of the Security Center opened by "Open page"
    action: isolate          # optional: automatic action run by "Run action"
```

Allowed actions (anything else is refused): `isolate` (network isolation with a 15-minute safety net),
`collect-evidence` (signed live collection), `memory` (RAM image), `capture` (10 minutes of network
traffic), `ioc-sweep` (look for files with a blocked hash), `recovery-check`.
A playbook never runs by itself: every action starts when you press the button, and is written in
the incident timeline.
