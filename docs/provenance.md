# Provenance

## Source of truth

The authoritative record is the TN03 frozen evidence package, **`frozen_tn03_v1`**, created 2026-10-12 and held privately by the dataset author. It was not modified in building this repository.

| Item | SHA-256 |
|---|---|
| `frozen_tn03_v1.zip` | `96d6b9ae6454a2caeb4b469b325678e35562a651dfa24289b1d2da51d62a9b1d` |
| `frozen_tn03/manifest.sha256` | `a535f0a74cd03a88c10269af08532c878a56468af93c874826191ab7fb363390` |
| `frozen_tn03/reproduce.py` | `792e171fb8b1954300abd68c5af559773569d3aa6f1b6d01e0a409178db8b98c` |

- **Collection.** All sources were retrieved on 2026-10-12.
- **Version control.** The original research workspace was not under version control, so no upstream commit hash exists. File hashes stand in for one.

## File origins

| Repository file | Origin in the frozen package | Transformation |
|---|---|---|
| `data/incidents.csv` | `inputs/stage1_5/agent_security_incidents.csv` | Selective redaction and generalisation of free-text and URL fields (55 cells in 20 records; `docs/redaction_policy.md`) |
| `data/sources.csv` | `inputs/stage1_5/evidence_matrix.csv` | Selective redaction (34 cells), plus generalisation of internal archive pointers and working-file references (141 cells); 175 cells in 57 claims in total |
| `data/annotations/{environment_recode,task_domain,trust_boundaries,pilot_sample,pilot_coder2}.csv` | `inputs/stage6_annotations/` | None (byte-identical) |
| `data/campaigns.csv` | `campaigns_frozen.csv` | None (byte-identical to the frozen package's campaign table) |
| `analysis/analyze.py` | New | A short, standard-library reimplementation of the frozen `reproduce.py` rules for Findings A and B |
| `analysis/verify.py` | New | Schema, referential-integrity and headline-count checks |

## Equivalence with the frozen package

Checked on 2026-10-12, against the private frozen package:
- **Finding A.** `analyze.py` gives the same numerator, denominator, share and Wilson interval as the frozen `definition_results.csv` for every definition × mechanism it covers (77 rows). The one difference is presentational: for P9, where two mechanisms tie at 20/68, both are flagged `is_top`; the frozen table flags only the first.
- **Finding B.** All 20 primary-coding rows (two discloser scopes × five groups × two measures) are identical to the frozen `boundary_results.csv`, including campaign counts and Wilson intervals.
- **Redaction.** Only free-text and URL fields differ from the frozen inputs. No identifier, classification, date or flag used by the analysis changed.

## Consistency with the published note

Checked on 2026-10-12 against Technical Note 03 (<https://labs.standard.ai/notes/Note-03.pdf>, retrieved 2026-10-12, SHA-256 `22367985a7af703285922dfc3446c5e1c40cbb460ead163e037872c2fef1b7dc`, 6 pages), in an earlier version of this repository that also distributed the figures and the full result tables:
- **Figures.** The note's three figures are vector-identical to the figures generated from the frozen study (identical drawing streams, fonts and text). The figures and their script are not distributed here.
- **Numbers.** Every count, fraction, rounded percentage, κ value, specification-curve count, leave-one-campaign-out range and corpus-disposition count stated in the note reproduced from the data, with one exception:
  - **Erratum (note text, not data).** Sections 2 and A of the note say "three October-disclosed core events". The data contain **five** core events first disclosed in October, in four campaigns. **Three campaigns** were first disclosed in October; the fourth was first disclosed on 2026-09-24. Only the note's wording ("events" for "campaigns") is affected.
  - **Not reproducible from this repository.** The note states that the original `setting` field was partly derived from mechanism labels for 42 of 87 core events. This is verified against the frozen package's setting-provenance table, which is not part of this release.

This release reproduces the principal results listed in `README.md` §6 and checks them in `analysis/verify.py`.

## Licensing

- **Licenses:** MIT for the original analysis code; CC BY 4.0 for the original dataset annotations and derived tables.
- **Third-party material is not licensed here:** referenced reports, the short quoted excerpts in `data/sources.csv`, and trademarks.
- **Technical Note 03 URL** (verified 2026-10-12): <https://labs.standard.ai/notes/Note-03.pdf>.

## Not included

The following are held privately by the dataset author and are not distributed:
- the figures, figure scripts and full result tables (sensitivity analyses, specification curve, coder comparison) behind Technical Note 03;
- the capability-measurement table (333 rows of third-party benchmark results);
- the Stage 6 reference outputs used for the original freeze verification;
- the appendix tables, which are pending editorial privacy review;
- raw source downloads;
- working notes;
- the detailed redaction log and the privacy-review file containing the original values.
