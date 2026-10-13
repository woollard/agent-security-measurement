# Redaction policy

**Policy:** selective redaction, not blanket anonymisation. Redacted records are **pseudonymised, not anonymous**.

## Preserved

Everything needed for verification and reproduction is kept:
- stable incident and campaign identifiers;
- publicly documented organisational attribution;
- source provenance;
- mechanism, operating-environment and trust-boundary classifications;
- inclusion and exclusion decisions;
- coding confidence and uncertainty;
- every analytical field.

## Removed or replaced where unnecessary

| Category | Treatment |
|---|---|
| `private_individual_name`, `private_individual_handle` | The names and account handles of private individuals affected by an incident are replaced with role descriptions, such as "affected user" or "affected developer" |
| `incidental_victim` | Identifying details of incidental victims and bystanders are replaced. Examples: a harassment target, a student who reported an attack, a targeted project. |
| `self_disclosing_public_figure_name` | Personal names of people who publicly disclosed incidents affecting themselves or their own companies are replaced with a role. The organisation is retained. Six individuals; approved by the dataset author. |
| `personal_account_url`, `media_url_with_personal_name` | A URL is redacted when the URL itself identifies a redacted individual: a personal social-media account, a personal blog domain, or a media slug containing the name. Where possible, media coverage in `secondary_source_urls` is kept for verification. |
| `pseudonymous_url_not_required` | Pseudonymous forum or Reddit links are removed when the incident's classification does not rest on them. Example: media-only records whose original post was never retrieved. |
| `persona_names` | Names of agent-created sockpuppet personas, which could collide with real people |
| `email_address` | Email addresses not needed for analysis |
| `residual_identifiability` | Incidental details that offer a route to an individual but are not needed for classification are generalised. Example: a pull-request number in a context-excluded record (INC-C-10); the project name is kept. |
| `archive_pointer_generalized`, `internal_path_replaced` | Paths into the author's private research archive and working files are replaced with `[archived copy; not distributed]` (line or page locators kept), or with the public source the file was compiled from. No internal path is published, and the archived copies are not available through this repository. |
| `threat_actor_alias_qualified` | Publicly documented threat-actor aliases are **retained**, but labelled as aliases reported by the cited vendor, not verified identities. Example: "reported alias 'knaithe', per Unit 42; not a verified identity". |

**Searched for and not found:**
- credentials, tokens, secrets and private keys (40-character hexadecimal strings in the data are public file or commit hashes);
- personal email addresses of private individuals;
- phone numbers;
- postal addresses.

**Not removed:**
- names of organisations;
- researchers, executives, spokespeople and journalists acting in a public professional capacity;
- security vendors;
- authors of cited publications.

## Rule for pseudonymous links

A pseudonymous forum, Reddit or issue-tracker link is retained **only when it supports the incident's classification**. That means one of two things:
- it is the user's own report, and the basis of `confirmation_status = self_reported_by_user` (INC-A-11, INC-A-17, INC-A-18);
- it contains the vendor acknowledgement behind `confirmed_by_responsible_developer` (INC-A-19).

Otherwise it is removed (INC-A-16, INC-C-06, INC-C-07, and a second INC-A-18 link). The dataset author holds the rationale for each record.

## Missing or restored verification links

INC-E-04 has one restored link. Its only verification URL, a media article, was restored because two conditions both hold:
- it is necessary for provenance;
- the affected individual publicly disclosed the incident themselves.

The article's URL slug contains the individual's surname, so the record is pseudonymised, not anonymous. The individual's personal social-media post remains redacted.

## Reviewed and deliberately retained

These items were reviewed and deliberately kept, because publicly available attribution is needed for provenance:
- vendor issue-tracker and forum URLs on which the classification rests (the page shows the poster's handle);
- media coverage that names an affected individual, where it is the only accessible verification of a self-disclosed incident whose personal post is redacted (INC-C-01, INC-C-04, INC-C-05, INC-C-11); the article URLs themselves do not contain the person's name;
- an affected company's own blog post (INC-A-01);
- a journalist's byline column about their own experience, written in a professional capacity (INC-E-05);
- a public company CEO's public post, where the CEO is the first-hand discloser (INC-F-06);
- the project name in a context-excluded harassment record (INC-C-10), whose maintainer remains identifiable from the cited coverage.

## Log

A detailed redaction log records each modification: the incident, file and field, category and reason, number of values modified, effect on reproducibility, and editorial status. It never contains the original values. The log and the original values are held privately by the dataset author and are not distributed with this repository.

## Effect on reproducibility

Only free-text and URL fields were changed. No identifier, classification, date or analytical field was modified.
- **Classifications and results are unchanged.** `first_disclosed_by` is used by `analysis/analyze.py` only to detect OpenAI as discloser; redaction changes neither OpenAI flag for any record (checked against the frozen package). All reproduced results are identical to the frozen package (see `docs/provenance.md`).
- **In the frozen package only,** nine "other (…)" discloser labels in one leave-one-discloser-out analysis are built from `first_disclosed_by` and would read differently if regenerated from this release; their values do not change.
