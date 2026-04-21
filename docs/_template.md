# <Rule Name>

## Threat Model

What behavior does this rule detect? What attacker goal does the behavior serve? Which ATT&CK technique(s) does it map to (if applicable)?

## Modality Choice

Why this framework (Sigma / Falco / Panther) and not another? Why this data source (syscall / log type / telemetry stream)?

## Expected FP Profile

What legitimate activity could trigger this rule? What's the tuning posture — aggressive / balanced / conservative?

## Environmental Assumptions

What log source, sensor, or data pipeline is assumed? What's required for the rule to function in a real environment?

## Alternatives Considered

What other rule shapes or data sources were evaluated? Why was this one chosen?

## Source

Where did the threat observation come from?

- If detonation-sourced: link to `analysis/reports/<sample-name>/` and reference the Gorelate query date from its `notes.md`.
- If research-sourced: link to the writeup URL.
