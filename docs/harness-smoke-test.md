# Harness Smoke Test

Diagnostic rule that verifies the pydetect test harness operates correctly end-to-end. Not a real detection rule.

## Threat Model
None. This rule matches the synthetic field `EventID: 42`.

## Modality Choice
Sigma; exists to exercise the harness pipeline from YAML loading through condition evaluation.

## Expected FP Profile
N/A — diagnostic only.

## Environmental Assumptions
None.

## Source/Validation
Synthetic test dataset (`harness_smoke.json`) with hand-labeled attack indices. Will be retired when the first real Sigma rule is added.
