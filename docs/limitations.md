# Limitations

Read these before using any number in this repository.

## What the data are, and are not

- **A curated collection of public disclosures.** The data are not a representative sample of deployed AI systems, AI agents, or security failures. An event appears only if someone detected it, chose to disclose it, and the disclosure was found by this search.
- **No population rates or prevalence.** Shares such as "36 of 87 core events" describe this corpus under one inclusion rule. They are not estimates of how often anything happens.
- **No causal claims.** Differences between operating environments are differences between *reported* populations. They do not show that environments cause different failures.
- **No exposure denominator.** No comparable count of agent deployments, sessions or evaluation runs exists for the period, so no rate can be computed.

## Disclosure bias and source concentration

- **One organisation dominates the lab-origin evidence.** 25 of the 35 lab-origin agent-acted events in Finding B involve OpenAI-operated agents, and 15 of the 16 lab non-cyber events are OpenAI register entries. With OpenAI-operated lab events excluded, the lab group falls to 10 events (all with outward crossings) and the non-cyber lab group to 1 event.
- **The two groups were reported through different channels.** Lab events come mostly from developer and evaluator self-disclosures after transcript reviews. User-deployment events come from user postmortems, vendor acknowledgements and media. The Finding B contrast is confounded with this channel difference.
- **Detection cascades.** Many 2026 disclosures followed a July 2026 industry-wide review prompted by one incident. Disclosure timing reflects when organisations looked, not when events happened.
- **Uneven search effort.** 2026 was searched far more intensively than 2024–2025. Few 2024 events is not evidence of few 2024 incidents.

## Classification uncertainty

- **Single primary coder.** Every annotation has one primary coder. A blind second coder recoded only 15 events.
  - Agreement is high for operating environment (κ = 0.91).
  - It is moderate for the outward-crossing indicator (κ = 0.60).
  - It is weak for own-asset overreach and the tool/permission code (κ = 0.44).
- **Mechanism labels were never double-coded.** They are also confounded with the collection stream that produced each record.
- **The user-deployment group is small.** Finding B's user group has 11 events, and its single outward crossing comes from one event. Remove that event and the share is 0/11.
- **Task domain is post hoc.** It was added after the first environment analysis.
- **The original `setting` field** was partly assigned from mechanism by a default rule, so it must not be crossed with mechanism. Use `env_v2` instead.
- **Retrospective discovery is mostly unknown** (69 of 87 core events), so excluding retrospective discoveries is a weak test.
- **Ties.** The mechanism ranking at the root-cause level is a tie (20 vs 20).

## Definitions and post hoc analyses

- **Overlapping definitions.** The nine definitions overlap by construction (P2–P9 are subsets or aggregations of the core set). P1 includes excluded and duplicate records and is not authoritative.
- **The OpenAI exclusions are post hoc.** They were not among the nine pre-specified definitions. `analysis/analyze.py` reproduces S2 (excluding OpenAI-operated lab events) and S3 (excluding events first disclosed by OpenAI); S1, based on the uncorrected heuristic, is documented in the frozen package only.
- **The original discloser heuristic** mostly marks OpenAI-*operated* agents rather than OpenAI *disclosures*. It misassigns one user-deployed event. The corrected rule (`openai_operated` in `analysis/analyze.py`; `openai_lab_origin` in the frozen package) is used for the published sensitivity analysis.

## Evidence and provenance

- **Some sources are hard to verify.** A small number of claims rest on browser transcriptions of pages that block automated retrieval. Media-only events are graded D.
- **Unresolved disagreements are retained.** Some dates and figures conflict between sources; the discrepancies are kept in the `notes` fields rather than resolved silently.
- **Some locators refer to copies that are not distributed.** Where a claim was checked against a retrieved copy of a source (for example, a page that blocks automated access), the `location` or `notes` field reads `[archived copy; not distributed]`, followed by a line or page locator where one exists. Those copies are not part of this release and are not publicly accessible; the claim can be checked against the public `source_url`.
- **Some evidence claims attach to aggregate identifiers** (for example `REG-AU-01..04`) rather than single events.

## Redaction

- **Redacted fields:** selected free-text and URL fields (see `docs/redaction_policy.md`).
- **Pseudonymised, not anonymous.** Redacted records are pseudonymised. Retained organisational attribution, dates and media coverage may still allow re-identification.
- **No effect on results.** Only free-text and URL fields were changed; every classification and every result reproduced here is unchanged.
