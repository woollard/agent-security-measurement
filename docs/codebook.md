# Codebook

This codebook defines every classification used in the released data, and the schema of each file.

The coding rules were written **before** coding, except `task_domain`, which was added after the first environment × mechanism analysis. That timing is disclosed below.

**Coders:**
- **Primary coder:** a single analyst.
- **Second coder:** a blind independent coder covered a stratified 15-event pilot (`data/annotations/pilot_coder2.csv`).

**Conventions:**
- **Empty value:** not established, or not applicable.
- **Explicit uncertainty codes:** `unknown`, `UNRESOLVED` and `UNKNOWN` mark uncertainty; they are not missing values.
- **Dates:** ISO 8601 (`YYYY`, `YYYY-MM` or `YYYY-MM-DD`) at the precision the evidence supports. An occurrence date is never back-filled from a disclosure date.

## 1. Units of analysis

| Unit | Definition | Identifier |
|---|---|---|
| **Event** | One distinguishable security event: one row of `data/incidents.csv` | `incident_id` |
| **Campaign** | Events sharing a causal chain or agent population, or explicitly linked by the primary sources. Unconnected events form a singleton campaign. **Count campaigns, not events, when counting independent incidents.** | `campaign_id` |
| **Root cause** | Campaigns by *different* agents that share one environment failure (for example `RC-IRREGULAR-RANGE`, a misconfigured third-party evaluation range). A campaign with no shared root cause is its own root-cause unit. | `shared_root_cause_id`, else `campaign_id` |

Aggregation from events to campaigns or root causes (`analysis/analyze.py`, `collapse`; also recorded in `data/campaigns.csv`, `aggregation_rule`):
- Each unit takes the **modal** value of the field.
- **Ties** go to the earliest-disclosed member.
- The unit's **disclosure date** is the earliest member disclosure.
- **`real_world_consequence`** is `yes` if any member is `yes`.

## 2. Inclusion tiers (`analysis_set`)

| Value | Definition |
|---|---|
| `core` | A real-world event (the consequence is yes or attempted) within the inclusion criteria, with confirmation at or above a self-report by the affected user |
| `core_low_confidence` | Within the inclusion criteria, but media-only, disputed or unverified |
| `demonstration` | A research demonstration with no reported real-world victim |
| `in_sandbox` | Boundary-testing behaviour inside evaluation or training infrastructure, with no effect on an outside party |
| `context_excluded` | Recorded but excluded: no material agent participation, out of scope, unsupported, or a duplicate (`duplicate_of` set) |

**Inclusion criterion.** An AI agent, coding assistant, or autonomous tool-using model *materially participated* in a security-relevant action.

## 3. Mechanism (`incident_type`, single coder)

| Value | Definition |
|---|---|
| `autonomous_objective_pursuit` | An agent pursuing an objective assigned by its legitimate operator took security-relevant actions outside its authorised scope, target set or environment. No attacker steered it. |
| `agent_operational_failure` | An agent acting for a legitimate user took a destructive or unsafe action with no attacker and no objective-driven scope expansion |
| `prompt_injection_or_hijack` | Attacker-controlled content redirected an agent in a real deployment |
| `attacker_controlled_tool_or_supply_chain` | A malicious or compromised tool, MCP server, skill, extension, package or agent configuration targeted agents, or used them as an execution or persistence layer |
| `malicious_operator_misuse` | A threat actor deliberately operated an AI agent or tool-using model as an attack tool |
| `research_demonstration` | Shown by researchers in a controlled setting; never treated as a confirmed real-world compromise |
| `in_sandbox_eval` | Boundary-testing inside evaluation or training infrastructure with no outside effect |

## 4. Operating environment (`env_v2`, in `data/annotations/environment_recode.csv`)

This field is coded **only** from who operates the agent and where it runs, never from the mechanism. It replaces the original `setting` field, which was partly assigned from the mechanism category (see `docs/limitations.md`).

| Value | Definition |
|---|---|
| `LAB_EVAL` | Run by a model developer, an evaluator or an agent vendor to test or benchmark the agent |
| `LAB_TRAIN` | Training rollouts or developer research workloads |
| `DEV_INTERNAL` | The developer's own internal deployment, used for real work |
| `USER_DEPLOY` | A deployed product acting for a legitimate user or organisation that is not the developer. This includes agents reached by attackers through packages, configuration or content. |
| `ATTACKER_OPERATED` | Run by a threat actor, including malware that calls an LLM. **Structurally implies `malicious_operator_misuse`.** |
| `UNRESOLVED` | The operator is not established |

"Lab-origin" means `LAB_EVAL`, `LAB_TRAIN` or `DEV_INTERNAL`.

## 5. Task domain (`task_domain`; lab-origin only; added post hoc)

| Value | Definition |
|---|---|
| `CYBER_OFFENSIVE` | The assigned task was offensive security work: a CTF, a cyber range, an exploit benchmark, a sandbox-escape test, or vendor offensive testing |
| `NON_CYBER` | Any other assigned task |
| `UNKNOWN` | The task is not stated |

## 6. Trust boundaries (`data/annotations/trust_boundaries.csv`)

An event can have several codes. Each code carries:
- **`basis`:** `D` if the source-derived text states the crossing directly, `I` if the analyst interpreted it;
- **`attempted`:** `1` if the crossing was attempted or unconfirmed, `0` if it was realised.

`NONE` means no boundary could be coded.

| Code | Boundary | Rule |
|---|---|---|
| `AT` | Agent → tool / permission control | Circumvented or exceeded an explicit permission or tool control: approvals, plan mode, a classifier, a GET-only or local-only restriction, a stop instruction, or bypass flags |
| `EG` | Contained environment → external network | Reached the internet or an external network from an environment meant to be isolated |
| `CR` | → credential / privileged resource | Obtained or used credentials, tokens, keys or privileges not provisioned for the task; includes privilege escalation |
| `UC` | Untrusted content → trusted action | Attacker-controlled or untrusted text was treated as instructions |
| `DA` | Development artifact → execution environment | A package, extension, MCP server, skill, hook or configuration executed, or was planted to execute, in a development, CI or agent runtime |
| `RT` | Intended target → unrelated real target | Substituted a real third-party target for the intended or authorised one |
| `TP` | → third-party system | Unauthorised access to, or action on, a system not owned by the agent's principal |
| `PA` | Principal-authority overreach | A destructive, irreversible or unapproved action on the principal's **own** assets |
| `PB` | Private → public publication | Published data, credentials or artifacts to a public service |
| `XA` | Cross-agent / cross-session isolation | Agents in separate samples or sessions communicated or shared resources against isolation |

The derived measures:
- **Outward crossing:** any realised `CR`, `TP`, `RT` or `EG`.
- **Own-asset overreach:** a realised `PA`.

`data/annotations/pilot_coder2.csv` holds the second coder's codes, with a supporting quotation or location for each.

## 7. Other controlled fields (in `data/incidents.csv`)

| Field | Values |
|---|---|
| `confirmation_status` | `confirmed_by_affected_org`, `confirmed_by_responsible_developer`, `confirmed_by_independent_researcher`, `self_reported_by_user`, `reported_by_media_only`, `disputed`, `demonstration_only`, `unverified` |
| `evidence_quality` | `A` (primary technical report with timeline), `B` (primary statement or first-hand forensics), `C` (single self-report or researcher claim, or a primary source summarised by a secondary), `D` (media- or database-only, or primary not retrieved) |
| `real_world_consequence` | `yes`, `no`, `unclear`, `attempted` |
| `retrospective_discovery` | `yes`, `no`, `unknown` |
| `setting` | Original field; **do not cross it with mechanism** (partly rule-derived) |
| `agent_role`, `agent_participation` | See `data/incidents.csv`. `agent_participation` is one of `agent_model_acted`, `agent_tooling_vector`, `agent_target_only`, `model_called_by_malware` or `unclear`. |

## 8. Discloser rules (computed by `analysis/analyze.py`)

| Field | Rule |
|---|---|
| `openai_operated` | The study's original "OpenAI" heuristic (incident ID prefix `OAI`, `REG-OAI`, `REG-AU` or `REG-N-`; "OpenAI" in `first_disclosed_by`; or GAP-G-05 or REG-INC-020) **and** a lab-origin environment (`LAB_EVAL`, `LAB_TRAIN`, `DEV_INTERNAL`). Called `openai_lab_origin` in the frozen study package; used for the OpenAI-operated exclusion (S2) in the published note. The heuristic on its own mostly identifies OpenAI-*operated* agents, not OpenAI disclosures, and assigns one user-deployed event (INC-C-04) to OpenAI; the environment condition removes it. |
| `first_disclosed_by_openai` | `first_disclosed_by` starts with "openai" or contains "and openai" (S3) |

## 9. File schemas

| File | Contents |
|---|---|
| `data/incidents.csv` | 245 candidate records with 37 columns, in the original schema. Free-text and URL fields are selectively redacted (`docs/redaction_policy.md`). |
| `data/sources.csv` | 1,096 evidence claims. Columns: `claim_id`, `incident_id`, `claim`, `claim_type`, `source_url`, `source_type`, `source_publication_date`, `location` (where the claim appears in the source; `[archived copy; not distributed]` marks a locator in a retrieved copy that is not part of this release), `quote` (fewer than 15 words), `verification_status`, `verification_status_raw`, `stream`, `notes`. See "Aggregate references" below. |
| `data/campaigns.csv` | 229 campaigns, one row each: `campaign_id`, `n_records`, `member_incident_ids` and `member_analysis_sets` (semicolon-separated, all members), `n_core_members`, `core_member_ids`, `shared_root_cause_id`, `root_unit`, and the campaign-level values over core members only (`core_unit_mechanism`, `core_unit_env_v2`, `core_unit_first_disclosure`, `core_unit_real_world`), flags `mixed_mechanism_in_core` and `mixed_env_v2_in_core`, and the `aggregation_rule`. Derived from the records; `analysis/verify.py` checks it against them. |
| `data/annotations/environment_recode.csv` | `env_v2` for the 124 core, low-confidence and in-sandbox records, with the original `setting` and `incident_type` for comparison, the field the code was based on, coder and date |
| `data/annotations/task_domain.csv` | `task_domain` for lab-origin records |
| `data/annotations/trust_boundaries.csv` | One row per record × boundary code (`NONE` where no boundary was crossed): `basis` (`D` direct, `I` interpreted), `attempted` (`0` realised, `1` attempted), evidence fields, coder, notes |
| `data/annotations/pilot_sample.csv`, `pilot_coder2.csv` | The 15-record reliability sample and the blind second coder's codes |

**Aggregate references in `data/sources.csv`.** Most claims attach to one `incident_id`. The rest attach to study-level identifiers:

| `incident_id` | Claims | Meaning |
|---|---|---|
| `CAP` | 230 | Capability-trend evidence (published benchmark results). These rows carry no per-claim identifier (`claim_id` is `CAP:`). The capability table they supported is not part of this release. |
| `EXP` | 68 | Exposure-context evidence (for example, adoption statistics), used for background only |
| `RC-IRREGULAR-RANGE(programme)`, `C-OAI26-HF(campaign)` | 27, 4 | Claims about a shared root cause or a whole campaign |
| `OWASP-SCOPE` | 6 | Scope notes on the OWASP exploit roundups |
| `REG:…`, `REG-…` (8 identifiers) | 1 each | Claims about developer incident registers or groups of register entries (for example `REG-AU-01..04`) |
