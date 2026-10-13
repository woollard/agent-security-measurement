# agent-security-measurement

**A source-verified database of publicly disclosed security incidents involving AI agents (January 2024 – September 2026)**

**David M. Woollard — Research and dataset author**

This repository is maintained by David M. Woollard on a personal GitHub account. It is **not** an official Standard AI–maintained repository.

**Version:** 0.1.0 (release candidate). No DOI has been assigned.

The database records **245 candidate incidents** in which an AI agent may have been involved in a security-relevant event: coding assistants, autonomous tool-using models, and evaluation or training agents. Each record carries:
- stable identifiers;
- campaign groupings;
- inclusion decisions;
- mechanism and operating-environment classifications;
- trust-boundary codes;
- links to the sources that support it.

The data are a **curated collection of public disclosures**, not a representative sample of deployed AI systems, and no proportion computed from them is an incident rate.

**Example use.** David M. Woollard, *What Counts as an Agent Security Failure? Population Definitions and Trust Boundaries in Reported AI Agent Incidents*, Standard AI Technical Note 03, October 2026, <https://labs.standard.ai/notes/Note-03.pdf>. The note uses this database to show that the answer to "what kind of failure is most common?" depends on how the incident population is defined. This repository reproduces the note's **principal findings** with `analysis/analyze.py` (§6). It does **not** reproduce every supplementary sensitivity analysis in the note.

---

## Contents

```text
data/
  incidents.csv                       245 incident records: identifiers, descriptions, dates, classifications, sources
  sources.csv                         1,096 evidence claims linking records to sources (URL, location, short quote, verification status)
  campaigns.csv                       one row per campaign: members and campaign-level classification
  annotations/
    environment_recode.csv            operating environment of each in-scope record
    task_domain.csv                   assigned-task domain of lab-origin records
    trust_boundaries.csv              trust-boundary codes (with direct/interpreted basis and realised/attempted flag)
    pilot_sample.csv, pilot_coder2.csv  blind second-coder reliability pilot (15 records)
analysis/
  analyze.py                          reproduces the principal results of Technical Note 03 (standard library only)
  verify.py                           schema, referential-integrity and headline-count checks
docs/
  codebook.md                         every field and code, with definitions and file schemas
  methodology.md                      how records were found, verified, selected and classified
  provenance.md                       where the data came from and how this release was derived
  limitations.md                      disclosure biases and other limits
  redaction_policy.md                 how personal information was handled
CITATION.cff, LICENSE-CODE, LICENSE-DATA, requirements.txt
```

**What kind of data each file is:**
- **Source-derived records:** `data/sources.csv`, and the descriptive columns of `data/incidents.csv` (organisations, agent or model, observed behaviour, consequences, dates, discloser, source URLs). These are analyst-written summaries of what the cited sources say, not verbatim text.
- **Analyst annotations:** the classification columns of `data/incidents.csv` (identifiers, groupings, mechanism, inclusion tier, confirmation, evidence grade, flags) and everything in `data/annotations/`. These are judgements made under the rules in `docs/codebook.md`.
- **Derived:** `data/campaigns.csv` aggregates the records by campaign; `analysis/verify.py` checks that it agrees with them.

## 1. What an incident record represents

A record (`incident_id`) is **one distinguishable security event** reported in a public source, in which an AI agent, coding assistant or autonomous tool-using model may have materially participated in a security-relevant action. Examples:
- an evaluation agent reaching a real third-party system;
- a coding agent deleting a user's production database;
- malware that hijacks a developer's agent configuration;
- a threat actor running an agent to attack organisations.

Each record states:
- **who was involved and what happened:** `organization`, `agent_or_model`, `observed_behavior`, `security_consequence`;
- **when:** occurrence, detection and first public disclosure dates, kept separate and never back-filled;
- **who disclosed it and where:** `first_disclosed_by`, primary and secondary source URLs;
- **how it was classified,** and with what confidence.

Motives attributed to an agent appear only in `inferred_motivation`, with the party making the inference named. Not every record is an "incident" in the analytical sense: research demonstrations, in-sandbox behaviour, duplicates and out-of-scope items are kept for transparency and marked by `analysis_set`.

## 2. How candidate incidents were identified

Candidates were collected from:
- primary reports by affected organisations and agent developers (postmortems, technical reports, system cards);
- developer incident registers;
- security-vendor and researcher write-ups;
- regulator statements;
- public incident databases (AI Incident Database, AIAAIC, OECD AI Incidents Monitor);
- the OWASP GenAI exploit roundups, used only as leads, never as confirmation;
- targeted searches.

All sources were retrieved on 2026-10-12. Each factual claim was recorded with its source location and a short verbatim excerpt, and quotations were checked against retrieved copies. Media was used only where no primary source could be found, and is graded accordingly. See `docs/methodology.md`.

## 3. How the 87-event core population is selected

Every candidate is assigned an inclusion tier (`analysis_set`):

| Tier | Records | Meaning |
|---|---|---|
| `core` | **87** | Real-world event (consequence yes or attempted) within the inclusion criteria, with confirmation at or above a self-report by the affected user |
| `core_low_confidence` | 22 | In scope, but media-only, disputed or unverified |
| `demonstration` | 56 | Research demonstration; no real-world victim |
| `in_sandbox` | 15 | Boundary-testing inside evaluation or training infrastructure, with no effect on an outside party |
| `context_excluded` | 65 | Duplicates (30, marked with `duplicate_of`), out-of-scope, unsupported or non-agentic items |

The full criteria are in `docs/codebook.md` §2.

## 4. Events, campaigns and root causes

| Unit | Identifier | Meaning |
|---|---|---|
| **Event** | `incident_id` | One distinguishable event |
| **Campaign** | `campaign_id` | Events connected by a causal chain or the same agent population, or explicitly linked by the sources. For example, one evaluation run that compromised several systems. The 87 core events form **72 campaigns**. Count campaigns, not events, when asking how many *independent* incidents occurred. |
| **Root cause** | `shared_root_cause_id`, else `campaign_id` | Campaigns by *different* agents that share one environment failure, such as a misconfigured third-party evaluation range. The core forms **68 root-cause units**. |

`data/campaigns.csv` gives each campaign's members and its campaign-level mechanism and environment. The aggregation rule is the modal value across core members, with ties going to the earliest-disclosed member.

## 5. Mechanism and trust-boundary classifications

**Mechanism** (`incident_type`, single coder):

| Value | Meaning |
|---|---|
| `autonomous_objective_pursuit` | The agent pursued its assigned task beyond its authorised scope |
| `agent_operational_failure` | A destructive or unsafe action, with no attacker |
| `prompt_injection_or_hijack` | Attacker content redirected the agent |
| `attacker_controlled_tool_or_supply_chain` | A malicious package, extension, MCP server or agent configuration was involved |
| `malicious_operator_misuse` | A threat actor operated the agent |
| `research_demonstration` | Shown by researchers; no real-world victim |
| `in_sandbox_eval` | Boundary-testing inside evaluation or training infrastructure |

**Operating environment** (`env_v2`, in `data/annotations/environment_recode.csv`): who operated the agent and where it ran. The values are `LAB_EVAL`, `LAB_TRAIN`, `DEV_INTERNAL`, `USER_DEPLOY`, `ATTACKER_OPERATED` and `UNRESOLVED`. It is coded independently of mechanism. Use it instead of the older `setting` column, which was partly derived from mechanism.

**Trust boundaries** (`data/annotations/trust_boundaries.csv`): ten codes, and an event can have several.

| Code | Boundary crossed |
|---|---|
| `AT` | A tool or permission control was circumvented |
| `EG` | A contained environment reached an external network |
| `CR` | Credentials or privileges were obtained |
| `UC` | Untrusted content was treated as instructions |
| `DA` | A development artifact executed |
| `RT` | An unrelated real target was substituted |
| `TP` | A third-party system was accessed |
| `PA` | The agent overreached on its principal's own assets |
| `PB` | Data was published publicly |
| `XA` | Agents communicated across isolation |

Each code is marked as directly stated or interpreted, and as realised or attempted. Technical Note 03 uses two derived measures:
- **outward crossing:** realised CR, TP, RT or EG;
- **own-asset overreach:** realised PA.

**Reliability.** A blind second coder recoded 15 records. Agreement was κ = 0.914 for environment, 0.595 for outward crossing and 0.444 for own-asset overreach. Mechanism labels were not double-coded. Full definitions are in `docs/codebook.md`.

## 6. Reproducing the principal findings

The analysis needs only Python 3.9 or later, with no third-party packages. No network access or credentials are required.

```bash
git clone https://github.com/woollard/agent-security-measurement.git
cd agent-security-measurement
python3 analysis/verify.py                  # schema, referential integrity, published headline counts
python3 analysis/analyze.py                 # print the population-definition and trust-boundary results
python3 analysis/analyze.py --out output    # also write output/population_results.csv and output/boundary_results.csv
```

`verify.py` prints `VERIFICATION PASSED` and exits 0 only if every check passes.

**Expected principal results** (Technical Note 03):

| Result | Value |
|---|---|
| Autonomous pursuit vs attacker-operated misuse, core events | 36/87 vs 20/87 |
| The same, excluding lab, evaluation, training and developer-internal origins | 2/52 vs 20/52 |
| The same, collapsed to root causes | 20/68 vs 20/68 (tie) |
| Outward crossings among agent-acted core events: lab-origin | 30/35 |
| Outward crossings among agent-acted core events: user-deployed | 1/11 |
| Lab-origin outward crossings, excluding OpenAI-operated lab events | 10/10 |

**What is and is not reproduced.**
- **Reproduced:** the corpus counts; the mechanism shares under all nine population definitions (P1–P9) and two post hoc OpenAI exclusions (S2, S3); and the trust-boundary results by operating environment and lab task domain, with and without OpenAI-operated lab events.
- **Not reproduced here:** the note's supplementary sensitivity analyses. These are the 192-specification curve, the leave-one-campaign-out and leave-one-discloser-out checks, the coding variants (direct-basis only, second-coder substitution), the campaign-cluster bootstrap, the uncorrected-heuristic exclusion (S1), the agreement statistics, and the note's figures. They were computed from the frozen study package (`docs/provenance.md`), which is not distributed. Most of their inputs are in the released data, but the code that produced them is not.

## 7. Using the database for your own analyses

- **Start from `analysis_set`.** Choose your population explicitly: core only, core plus low-confidence, or including demonstrations. State the choice; results depend on it.
- **Choose your unit.** Count events, campaigns (`campaign_id`) or root causes, and report which. Connected events are not independent observations.
- **Join annotations on `incident_id`:**
  - `environment_recode.csv` for environment;
  - `trust_boundaries.csv` for boundaries (filter `attempted == "0"` for realised crossings, and `basis == "D"` for directly stated ones only);
  - `task_domain.csv` for lab-origin records.
- **Trace any claim** through `data/sources.csv` (`incident_id`, `source_url`, `location`, `quote`, `verification_status`).
- **Respect the uncertainty markers:** `unknown`, `UNRESOLVED`, interpreted codes, attempted crossings, and evidence grades C and D.
- **Do not compute rates.** There is no denominator of deployed agents, runs or exposures.

`analysis/analyze.py` is a short, self-contained example of these joins.

## 8. Limitations and disclosure biases

- **Disclosure bias.** A record exists only if someone detected the event, chose to publish it, and the search found it. Lab and evaluation events come mostly from developers' own disclosures after transcript reviews; user-deployment events come from user postmortems, vendor acknowledgements and media.
- **Source concentration.** 25 of the 35 lab-origin agent-acted core events involve OpenAI-operated agents. Many 2026 disclosures followed one industry-wide review in July 2026.
- **Uneven search effort.** 2026 was searched far more intensively than 2024–2025.
- **Classification uncertainty.**
  - A single primary coder did all coding; the second-coder pilot was small.
  - Mechanism labels were not double-coded.
  - Some groups are small: for example, 11 user-deployment agent-acted events.
- **No denominators, no causal claims.** Differences between environments are differences between *reported* populations.
- **Redaction.** Personal information about private individuals was selectively removed (`docs/redaction_policy.md`). Redacted records are pseudonymised, not anonymous.

See `docs/limitations.md` for details.

## Citation

Use [`CITATION.cff`](CITATION.cff); GitHub's "Cite this repository" reads it. When you use the findings, please also cite Technical Note 03. No DOI has been assigned.

## Licensing and provenance

- **Code:** the original analysis code (`analysis/`) is licensed under MIT ([`LICENSE-CODE`](LICENSE-CODE)).
- **Data:** the original dataset annotations and derived tables (`data/`) are licensed under CC BY 4.0 ([`LICENSE-DATA`](LICENSE-DATA)).
- **Third-party material is not licensed here:** the referenced reports, the short quoted excerpts in `data/sources.csv`, and trademarks.
- **Provenance:** every record traces to a frozen, checksummed study package (`docs/provenance.md`).
