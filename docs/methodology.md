# Methodology

## 1. Question and design

The study asks: *How much does the apparent picture of "agent security failures" depend on what is counted as one?* It is a **descriptive measurement study** of publicly disclosed events. It makes no causal claims, estimates no incident rates, and does not test whether failures are becoming more frequent.

## 2. Corpus construction (Stages 1–5)

**Window.** Incidents occurring or first publicly disclosed between 2024-01-01 and 2026-09-30. Five core events first disclosed in early October 2026 (2–9 October) are retained and flagged `disclosure_in_window = no`. They belong to four campaigns, three of which were first disclosed in October; the fourth (`C-OAI26-AU`) was first disclosed on 2026-09-24.

**Sources** (all retrieved 2026-10-12):
- primary technical reports and postmortems from affected organisations and agent developers;
- security-vendor and researcher write-ups;
- regulator and government statements;
- developer incident registers (OpenAI's misalignment-report register; METR's agent-incident catalogue);
- public incident databases (AI Incident Database, AIAAIC, OECD AIM);
- the OWASP GenAI exploit roundups, used only as a secondary analyst source, never as confirmation;
- media, where no primary source could be found (graded D).

**Process:**
1. Parallel research streams collected candidates, each under identical evidence rules: retrieve the primary source; keep occurrence, detection and disclosure dates separate; record each claim with its source location and a quotation of fewer than 15 words.
2. Candidates were deduplicated. Duplicates are kept but `context_excluded`, with `duplicate_of` set.
3. Connected events were grouped into campaigns and shared root causes.
4. Every candidate was classified into an inclusion tier (`analysis_set`) and a mechanism (`incident_type`). See `docs/codebook.md`.
5. **Verification.** Evidence quotations were string-matched against retrieved copies of the sources. A seeded random audit of 8 broad-search rows found 3 needing correction, and those corrections were applied.

**Result:** 245 candidate records.

| Tier | Records |
|---|---|
| Core | 87 (72 campaigns, 68 root-cause units) |
| Low-confidence | 22 |
| Demonstrations | 56 |
| In-sandbox | 15 |
| Context-excluded | 65, including 30 duplicates |

## 3. Annotation (Stage 6)

- **Operating environment** (`env_v2`) was recoded independently of mechanism for core, low-confidence and in-sandbox events (124 records).
- **Trust boundaries:** ten codes, applied to core and low-confidence events (109 records, 240 codes), with direct-or-interpreted basis and attempted flags.
- **Task domain** was added for lab-origin events, after the first environment × mechanism analysis.
- **Blind second coding:** an independent coder recoded a stratified 15-event sample from the primary sources without seeing the primary labels.

| Agreement measure | Cohen's κ |
|---|---|
| env_v2 | 0.914 |
| Pooled boundary presence | 0.719 (any), 0.698 (realised) |
| Outward-crossing indicator | 0.595 |
| Own-asset-overreach indicator | 0.444 |

## 4. Analyses in Technical Note 03

`analysis/analyze.py` reproduces the Finding A shares for P1–P9, S2 and S3, and the Finding B results under primary coding, for all events and excluding OpenAI-operated lab events. The specification curve, S1, the coding variants, the bootstrap and the sensitivity analyses were run on the frozen study package (`docs/provenance.md`) and are described here for completeness.

### Finding A: population-definition sensitivity

For each of nine **pre-specified** definitions (P1–P9), plus three **post hoc** OpenAI-exclusion scopes (S1–S3), the share of units assigned to each mechanism is computed with Wilson score intervals.

| ID | Unit | Rule |
|---|---|---|
| P1 | event | all 245 candidate records (not authoritative) |
| P2 | event | core |
| P3 | campaign | core, collapsed to campaigns |
| P4 | event | core, real-world = yes, confirmed by the affected organisation, the developer or a researcher |
| P5 | event | core, excluding lab-origin environments |
| P6 | event | core + low-confidence + in-sandbox (excludes demonstrations and excluded or duplicate rows) |
| P7 | event | core, evidence A or B, confirmed, with at least one claim verified in a retrieved source |
| P8 | event | core, excluding events flagged as retrospective discoveries |
| P9 | root | core, collapsed to shared root causes |
| S1 | event | core, excluding the original "OpenAI" discloser heuristic (post hoc) |
| S2 | event | core, excluding OpenAI-operated lab-origin events (post hoc; corrected rule) |
| S3 | event | core, excluding events first publicly disclosed by OpenAI (post hoc) |

**Specification curve.** A 192-specification curve crosses seven analytic choices:
- unit: event, campaign or root cause;
- confidence tier;
- lab inclusion;
- demonstrations;
- evidence grade;
- retrospective exclusion;
- disclosure window.

### Finding B: operating-environment contrast

**Population.** Core events in which the agent itself acted without being operated by an attacker (autonomous pursuit or operational failure), with a legitimate principal: 46 events, 35 lab-origin and 11 user-deployed.

**Measures.**
- **Outward crossing:** realised `CR`, `TP`, `RT` or `EG`.
- **Own-asset overreach:** realised `PA`.

**Breakdowns:**
- **Groups:** lab offensive-cyber, lab non-cyber, lab task not stated, lab pooled, user-deployed.
- **Coding variants:** primary; direct-basis only; coder-2 codes substituted for the pilot events.
- **Discloser scopes:** all; excluding OpenAI-operated lab events; the original heuristic; excluding first disclosure by OpenAI.

**Intervals.** Wilson 95% intervals are given everywhere. A campaign-cluster bootstrap (2,000 replicates, seed 20261012) is given for the pooled lab and user groups.

### Sensitivity

- **Leave-one-campaign-out:** all 72 core campaigns, removed one at a time.
- **Leave-one-discloser-out.**
- **Six coding perturbations:**
  - relabelling borderline user-deployment failures;
  - resolving unresolved environments both ways;
  - direct-basis codes only;
  - dropping retrospective discoveries;
  - promoting low-confidence events to core.

## 5. Reproduction outputs

`python analysis/analyze.py --out DIR` writes two tables:
- `population_results.csv`: one row per definition × mechanism (11 × 7 = 77 rows). Columns `definition`, `label`, `unit`, `mechanism`, `numerator`, `denominator`, `share`, `wilson_low`, `wilson_high`, `is_top`, `top_is_tied`. Where the top count is tied, every tied mechanism has `is_top = 1`.
- `boundary_results.csv`: one row per discloser scope × group × measure (2 × 5 × 2 = 20 rows), primary coding. Columns `scope` (`all`, `excl_openai_operated_lab`), `group`, `measure` (`outward_crossing`, `own_asset_overreach`), `numerator`, `denominator`, `n_campaigns`, `share`, `wilson_low`, `wilson_high`.

These values agree with the frozen study's result tables (checked 2026-10-12; `docs/provenance.md`).

## 6. Interval semantics

The Wilson and bootstrap intervals describe count uncertainty, or resampling variability, **within this curated corpus**. They are not confidence intervals for any population of AI systems or incidents.
