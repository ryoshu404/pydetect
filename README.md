# pydetect ![tests](https://github.com/ryoshu404/pydetect/actions/workflows/test.yml/badge.svg)

> **Note: This README is not final. The project is in active build.**

pydetect is a detection-as-code repository written in Python that authors and tests detection rules across multiple frameworks with per-rule decision documentation. The goal of pydetect is to demonstrate detection engineering as a software discipline — rules in version control, tests that validate rule logic, decision documentation that captures reasoning, and continuous integration that enforces it all.

The repository contains rules in three framework-native DSLs (Sigma, Falco, KQL) backed by a Python pytest harness with per-framework adapters, fail-fast fixture validation at test collection time, and GitHub Actions CI that blocks merges without passing tests.

---

# What It Is

pydetect implements detection engineering as a structured engineering practice:

- Detection rules across three frameworks (Sigma, Falco, KQL) authored in their native DSLs
- A pytest harness with per-framework adapters that evaluate rules against synthetic event fixtures
- Per-rule decision documentation covering threat model, modality choice, expected false-positive profile, and environmental assumptions
- Collection-time fixture validation that fails CI before any test runs if rules lack their fixtures
- GitHub Actions CI gating every push and pull request

Rules are organized into TTP-cluster batches — each batch covers an attacker behavior across the applicable frameworks rather than treating frameworks as independent silos. This reflects how detection engineering actually works in practice: an attacker behavior leaves traces across multiple telemetry layers, and rules across frameworks form a coherent detection story for that behavior.

---

# Methodology

pydetect treats detection rules as production code. Three principles drive the structure:

**Rules in version control with associated tests.** Every rule lives in its framework's native DSL alongside positive and negative fixtures. Positive fixtures are events that should match; negative fixtures are events that should not. Tests assert both, and the harness generates them automatically from the rule files on disk. There is no way to commit a rule without its fixtures — the harness will fail CI collection before any test runs.

**Decision documentation as a first-class artifact.** Every rule ships with a 200-400 word decision doc explaining the threat model, why this framework was chosen, the expected false-positive profile, environmental assumptions, alternatives considered, and source provenance. The decision docs are the differentiator between a rules repository and a tested-with-rationale rules repository. They demonstrate the judgment behind each rule, not just the rule itself.

**Cross-framework cluster coherence.** Rules cluster by TTP rather than living as isolated detections. A Cobalt Strike rule batch contains a Sigma rule for the dropper's process-creation pattern, a Falco rule for the post-exploitation syscall behavior, and a KQL rule for C2 detection at the Defender XDR layer — each cross-referenced in the others' decision docs. This makes the repo read as systems thinking about detection rather than tactical rule authoring.

---

# Repository Structure

```
pydetect/
├── sigma/                           # Sigma rule files (.yml)
├── falco/                           # Falco rule files (.yaml)
├── kql/                             # KQL rule files (.kql)
├── tests/
│   ├── conftest.py                  # fixture loader + collection-time validation
│   ├── adapters/
│   │   ├── sigma_adapter.py         # synthetic Sigma evaluator
│   │   ├── falco_adapter.py         # synthetic Falco evaluator
│   │   └── kql_adapter.py           # synthetic KQL interpreter
│   ├── fixtures/
│   │   └── <rule-name>/
│   │       ├── positive.json        # event that should match
│   │       └── negative.json        # event that should not match
│   ├── test_sigma_rules.py          # parametrized over sigma/*.yml
│   ├── test_falco_rules.py          # parametrized over falco/*.yaml
│   └── test_kql_rules.py            # parametrized over kql/*.kql
├── docs/
│   ├── _template.md                 # decision doc template
│   └── <rule-name>.md               # per-rule decision doc
├── requirements.txt
└── .github/workflows/
    └── test.yml                     # CI: pytest on push and PR
```

Each rule shipped to the repository produces five artifacts: the rule file, two fixture files, the decision doc, and the parametrized test cases generated automatically by the harness.

---

# Frameworks

pydetect covers detection frameworks selected to span the layers of the telemetry stack rather than to demonstrate variants of the same approach. v1 ships with Sigma and KQL; Falco and Panther are v1.1 additions.

## Sigma

SIEM-agnostic detection rules in YAML. Compiles to backend-specific queries (Splunk, Elastic, Sentinel KQL) at deploy time. pydetect's Sigma scope is endpoint and log-based detection: Windows process creation, Sysmon events, PowerShell script block logging. Rules follow SigmaHQ field conventions where applicable.

## KQL

Microsoft Defender XDR detection queries authored against the published Defender table schemas (DeviceProcessEvents, DeviceNetworkEvents, etc.). Rules are stored as raw `.kql` files with metadata in the corresponding decision doc. The KQL adapter is a synthetic Python interpreter covering a bounded operator surface for filter-shape signature queries; aggregating and windowed queries are out of scope (those live in hunting queries, not signatures).

## Falco (v1.1)

Runtime security rules for Linux syscalls and Kubernetes audit events. v1 ships without Falco rules; v1.1 extends pydetect into cloud-native deployment detection (K8s audit events, container runtime behavior, sensitive file access from system processes). Falco's adapter skeleton is in place at `tests/adapters/falco_adapter.py` and will be implemented when the first Falco rule lands.

## Panther (v1.1)

Cloud and SaaS audit log detection rules in Python (CloudTrail, Okta, GitHub audit, Google Workspace). v1 demonstrates the methodology across telemetry-layer-coverage frameworks; v1.1 extends to cloud audit log detection as the next batch of rules.

---

# Testing Harness

The harness is built on pytest with three design decisions that enforce rule-test coupling structurally rather than by convention.

**Adapter contract.** Each framework has an adapter exposing a single function:

```python
def run_<framework>_rule(rule_path: Path, event: dict) -> bool:
    """Returns True if the event matches the rule, False otherwise."""
```

Uniform across Sigma, Falco, and KQL. Tests call the adapter; the adapter handles framework-specific evaluation internally.

**Tests generated from rule globs.** Each framework's test file uses `pytest.parametrize` to generate one positive and one negative test case per rule found on disk. Adding a new rule file to `sigma/` automatically produces two new test cases with no test-file edits required. The set of tests cannot drift from the set of rules.

**Collection-time fixture validation.** Before any test runs, `conftest.py` walks every framework directory and verifies each rule has both `positive.json` and `negative.json` fixtures. Missing fixtures fail pytest collection with an explicit error naming what's missing. This makes it structurally impossible to ship a rule without its tests — the failure surfaces in CI, not as a silent gap.

---

# Decision Documentation

Every rule ships with a decision doc at `docs/<rule-name>.md` conforming to a template. The template covers six sections:

- **Threat Model** — what behavior the rule detects, what attacker goal it serves, ATT&CK technique mapping
- **Modality Choice** — why this framework, why this data source
- **Expected FP Profile** — what legitimate activity could trigger the rule, tuning posture
- **Environmental Assumptions** — what log source, sensor, or pipeline is assumed
- **Alternatives Considered** — what other rule shapes were evaluated and rejected
- **Source** — provenance trail (research writeup URL, sandbox report, schema doc reference)

Target length is 200-400 words. The constraint surfaces ill-scoped rules — if a decision doc takes more than 30 minutes to write, the rule itself is probably not well-scoped.

---

# Design Decisions

## Three Frameworks, Selected for Stack Coverage

pydetect ships rules in Sigma, Falco, and KQL because they span different telemetry layers — endpoint logs, host syscalls, and Microsoft XDR rows respectively. A rules repository in a single framework demonstrates that framework; a rules repository across frameworks selected by telemetry layer demonstrates detection thinking across the stack. Panther — covering SaaS and cloud audit log detections (CloudTrail, Okta, GitHub audit, Google Workspace) — is deferred to v1.1 to keep v1's scope bounded. v1 demonstrates the methodology across three frameworks selected for telemetry-layer coverage; v1.1 extends to SaaS audit logs as the next batch of rules.

## Per-Rule Decision Documentation

The decision doc is the portfolio differentiator. A repository of YAML files demonstrates that a person can write YAML; a repository where each rule has a written rationale demonstrates judgment. The decision doc captures the reasoning that's invisible in the rule itself — why this rule and not another, what the FP envelope looks like, what assumptions the rule makes about its environment. Without decision docs, the repository flattens to a rules folder.

## Synthetic KQL Evaluator over Kustainer

KQL evaluation could be performed by the kustainer Docker image Microsoft publishes, which is real KQL and would handle the full operator surface. pydetect uses a synthetic Python interpreter instead because the rules in scope are signature-shape filter queries — bounded operator surface (`==`, `=~`, `!=`, `has`, `contains`, `startswith`, `endswith`, `in`, `in~`, `matches regex`, boolean combinations). Aggregating queries are out of scope. The synthetic interpreter is sufficient and avoids the Docker-in-CI complexity that real KQL evaluation would require. Kustainer is documented as a v2 escape hatch if the operator surface grows.

## Single Source of Truth for Framework Conventions

The `FRAMEWORKS` dict in `conftest.py` maps framework name to rule file glob (`*.yml` for Sigma, `*.yaml` for Falco, `*.kql` for KQL). Both the fixture validator and the test files import this dict rather than hardcoding their globs. Hardcoded globs in multiple places drift; a single dict makes drift impossible. Adding a new framework is a one-line change in conftest plus a new test file.

## Tests Generated from Rule Files, Not Hand-Written

`pytest.parametrize` over framework rule globs generates tests automatically. The alternative — hand-writing one test function per rule — relies on author discipline to remember to wire each rule's tests. With generated tests, that discipline becomes structural: rules cannot be added without tests because the tests are derived from rule files on disk. This is the difference between "I was careful" and "I built a system that prevents carelessness."

## No LLM-Assisted Rule Generation

Rules are authored by hand. The decision docs explicitly capture human judgment — threat modeling, FP profile reasoning, environmental assumptions. LLM-generated rules would produce rules that look correct without the underlying judgment, and decision docs that summarize the rule rather than reason about it. The differentiator collapses. Rule authorship stays manual; tooling assists with test scaffolding and decision doc templates only.

## Filesystem as Source of Truth

There is no database, no lockfile, no central registry. Rules live as files. Fixtures live as files. Decision docs live as files. The presence of `tests/fixtures/<rule_name>/` is what tells the harness the rule's fixtures exist. This is appropriate for a rules repository — the alternative (a database tracking which rules are tested) would be infrastructure overhead with no benefit at this scale.

---

# Current State

**Harness complete.** The pytest harness, three adapter skeletons, fixture validation, and CI are merged on `main` with all checks passing. The harness is ready to receive rules.

**Rules in progress.** Rule authorship is the active workstream. Rules are organized into TTP-cluster batches (one batch covers a single attacker behavior across applicable frameworks). The first batch is in research and discussion.

**Target ship: late October / early November 2026.** v1 = harness + 9-12 rules across 3-4 TTP batches + per-rule decision docs + green CI + methodology README.

**Work-side application.** The harness pattern is being applied privately to a subset of the author's production KQL detections at the AF Cyber Defense Operations team. The public pydetect repository demonstrates the methodology; the private work-side rollout backs the production-use claim.

---

# Roadmap

## v1.0

- 6-7 rules across Sigma and KQL organized into 3 TTP-cluster batches
- Per-rule decision docs with research-sourced provenance
- Cross-framework cluster coherence (rules within a TTP batch reference each other)
- Green CI with full rule coverage
- Methodology README (this document)
- Work-side KQL rollout in progress at the AF

## v1.1 (cloud-environment extension)

- **Falco adapter and rules.** Linux syscall and Kubernetes audit event detection following the same harness pattern as Sigma and KQL. Adapter skeleton in place at `tests/adapters/falco_adapter.py`. Rules cover cloud-native deployment behavior — container runtime, K8s audit, sensitive file access from system processes.
- **Panther adapter and rules.** Cloud audit log detection in Python — CloudTrail, Okta System Log, GitHub audit, Google Workspace admin audit. Continues the cloud-environment theme from v1's AWS Sigma rules.
- **Analysis pipeline scripts.** Manual-trigger Python scripts that consume Gorelate's `/iocs/flagged` endpoint, fetch samples from MalwareBazaar, submit to Triage, and store reports under `analysis/reports/`. Timeline-dependent on Gorelate v1.
- **One upstream rule submission.** Opportunistic — pick the strongest rule from the v1 batches, conform to SigmaHQ style conventions, and submit a single PR for review. Best-effort rather than hard commitment.

## v2 (post-application)

- Kustainer-based real KQL evaluation if the synthetic interpreter's operator surface proves insufficient against the work-side rule corpus
- Full Falco runtime testing via `.scap` capture playback in CI
- Continued upstream rule submissions
- Framework expansion if the target set shifts (YARA-L for Chronicle, Splunk SPL, etc.)

---

# Related Projects

This project is part of a larger security tooling portfolio.

### [statica](https://github.com/ryoshu404/statica) (v1.0)
Modular static analysis pipeline written in Python. Extracts file hashes, printable strings, and IOCs from arbitrary files.

### [macollect](https://github.com/ryoshu404/macollect) (v1.0)
Modular macOS forensic artifact collector written in Python. Collects persistence mechanisms, process snapshots, code signing metadata, TCC permissions, and Unified Log activity across eight independent collection modules.

### [gorelate](https://github.com/ryoshu404/gorelate) (In Development)
Threat intelligence correlation service written in Go. pydetect consumes Gorelate's `/iocs/flagged` endpoint as the upstream source for the deferred analysis pipeline.

---

# Author

R. Santos
GitHub: https://github.com/ryoshu404

---

# License

MIT
