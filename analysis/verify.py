#!/usr/bin/env python3
"""Lightweight checks of the incident database.

Usage: python analysis/verify.py        (standard library only; prints 'VERIFICATION PASSED' and exits 0 on success)

Checks
  1. Schema: every file has the documented columns; controlled fields use only allowed values.
  2. Referential integrity: identifiers are unique; annotations, campaigns, duplicates and evidence claims refer
     to existing records; campaigns.csv agrees with the incident records.
  3. Published headline counts: corpus counts and the principal results of Technical Note 03, recomputed with
     analysis/analyze.py.
"""
import csv, os, re, sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, HERE)
import analyze  # noqa: E402

passes, fails = [], []


def check(cond, msg):
    (passes if cond else fails).append(msg)


def read(rel):
    with open(os.path.join(REPO, rel), newline="", encoding="utf-8") as f:
        rd = csv.DictReader(f)
        return rd.fieldnames, list(rd)


SCHEMA = {
    "data/incidents.csv": ["incident_id", "campaign_id", "shared_root_cause_id", "incident_name", "organization", "agent_or_model",
                           "incident_type", "agent_role", "agent_participation", "setting", "assigned_objective", "observed_behavior",
                           "inferred_motivation", "boundary_crossed", "security_consequence", "real_world_consequence",
                           "occurrence_start", "occurrence_end", "occurrence_precision", "detection_date", "retrospective_discovery",
                           "first_public_disclosure", "disclosure_precision", "first_disclosed_by", "disclosure_in_window",
                           "confirmation_status", "evidence_quality", "analysis_set", "primary_source_url", "secondary_source_urls",
                           "source_publication_date", "source_page_or_section", "in_owasp_roundup", "duplicate_of", "related_events",
                           "source_stream", "notes"],
    "data/sources.csv": ["claim_id", "incident_id", "claim", "claim_type", "source_url", "source_type", "source_publication_date",
                         "location", "quote", "verification_status", "verification_status_raw", "stream", "notes"],
    "data/campaigns.csv": ["campaign_id", "n_records", "member_incident_ids", "member_analysis_sets", "n_core_members",
                           "core_member_ids", "shared_root_cause_id", "root_unit", "core_unit_mechanism", "core_unit_env_v2",
                           "core_unit_first_disclosure", "core_unit_real_world", "mixed_mechanism_in_core", "mixed_env_v2_in_core",
                           "aggregation_rule"],
    "data/annotations/environment_recode.csv": ["incident_id", "analysis_set", "stage5_setting", "stage5_incident_type", "env_v2",
                                                "basis_field", "coder", "coding_date", "notes"],
    "data/annotations/task_domain.csv": ["incident_id", "env_v2", "task_domain", "basis_field", "coder", "notes"],
    "data/annotations/trust_boundaries.csv": ["incident_id", "boundary_code", "basis", "attempted", "evidence_fields", "coder", "notes"],
    "data/annotations/pilot_sample.csv": ["incident_id", "incident_name", "primary_source_url", "secondary_source_urls"],
    "data/annotations/pilot_coder2.csv": ["incident_id", "env_v2", "boundary_code", "basis", "attempted", "supporting_quote_or_location",
                                          "source_used", "retrieval_ok", "notes"],
}
ENUMS = {
    "incident_type": set(analyze.MECHANISMS),
    "analysis_set": {"core", "core_low_confidence", "demonstration", "in_sandbox", "context_excluded"},
    "real_world_consequence": {"yes", "no", "unclear", "attempted"},
    "confirmation_status": {"confirmed_by_affected_org", "confirmed_by_responsible_developer", "confirmed_by_independent_researcher",
                            "self_reported_by_user", "reported_by_media_only", "disputed", "demonstration_only", "unverified"},
    "evidence_quality": {"A", "B", "C", "D"},
    "retrospective_discovery": {"yes", "no", "unknown"},
    "disclosure_in_window": {"yes", "no", "unknown"},
}
ENV = {"LAB_EVAL", "LAB_TRAIN", "DEV_INTERNAL", "USER_DEPLOY", "ATTACKER_OPERATED", "UNRESOLVED"}
BOUNDARIES = {"AT", "EG", "CR", "UC", "DA", "RT", "TP", "PA", "PB", "XA", "NONE"}
# Evidence claims that document study-level material rather than a single record (see docs/codebook.md)
AGGREGATE_REFS = {"CAP", "EXP", "OWASP-SCOPE", "RC-IRREGULAR-RANGE(programme)", "C-OAI26-HF(campaign)", "REG:openai_hub_O5",
                  "REG:openai_hub_O9", "REG:metr_catalogue", "REG-OAI-MR-*", "REG-METR", "REG-TP-01/02", "REG-AU-01..04", "REG-SWEEP"}
DATE = re.compile(r"^(\d{4}(-\d{2}(-\d{2})?)?)?$")

# Published headline values (Technical Note 03, https://labs.standard.ai/notes/Note-03.pdf)
EXPECTED_COUNTS = {"candidate_records": 245, "core_events": 87, "core_campaigns": 72, "core_root_cause_units": 68,
                   "core_low_confidence": 22, "research_demonstrations": 56, "in_sandbox": 15, "context_excluded": 65, "duplicates": 30}
EXPECTED_POPULATIONS = {"P1": (57, 35, 245), "P2": (36, 20, 87), "P3": (24, 20, 72), "P4": (32, 17, 70), "P5": (2, 20, 52),
                        "P6": (40, 22, 124), "P7": (31, 19, 75), "P8": (26, 20, 77), "P9": (20, 20, 68), "S2": (12, 20, 62),
                        "S3": (18, 20, 68)}  # (autonomous pursuit, attacker-operated misuse, denominator)
EXPECTED_BOUNDARIES = {("all", "lab_offensive_cyber"): ("15/16", "4/16"), ("all", "lab_non_cyber"): ("12/16", "1/16"),
                       ("all", "lab_task_not_stated"): ("3/3", "1/3"), ("all", "lab_all"): ("30/35", "6/35"),
                       ("all", "user_deployed"): ("1/11", "10/11"), ("excl_openai_operated_lab", "lab_all"): ("10/10", "1/10"),
                       ("excl_openai_operated_lab", "user_deployed"): ("1/11", "10/11")}


def main():
    data = {}
    for rel, cols in SCHEMA.items():
        fields, rows = read(rel)
        check(fields == cols, f"schema: {rel}")
        data[rel] = rows
    inc = data["data/incidents.csv"]
    ids = [r["incident_id"] for r in inc]
    idset = set(ids)
    check(len(ids) == len(idset), "incident_id unique")
    for col, allowed in ENUMS.items():
        bad = sorted({r[col] for r in inc} - allowed)
        check(not bad, f"allowed values: incidents.{col} {bad if bad else ''}")
    for col in ("occurrence_start", "occurrence_end", "detection_date", "first_public_disclosure"):
        bad = [r["incident_id"] for r in inc if not DATE.match(r[col])]
        check(not bad, f"ISO partial dates: incidents.{col} {bad[:3] if bad else ''}")
    check(all(r["duplicate_of"] in idset for r in inc if r["duplicate_of"]), "duplicate_of targets exist")
    check(all(r["analysis_set"] == "context_excluded" for r in inc if r["duplicate_of"]), "duplicates are excluded from analysis")

    env = data["data/annotations/environment_recode.csv"]
    scope_env = {r["incident_id"] for r in inc if r["analysis_set"] in ("core", "core_low_confidence", "in_sandbox")}
    check({r["incident_id"] for r in env} == scope_env and len(env) == len(scope_env), "environment_recode covers exactly core, low-confidence and in-sandbox records")
    check({r["env_v2"] for r in env} <= ENV, "allowed values: env_v2")
    envmap = {r["incident_id"]: r["env_v2"] for r in env}
    task = data["data/annotations/task_domain.csv"]
    check({r["incident_id"] for r in task} == {i for i, e in envmap.items() if e in analyze.LAB_ENVS}, "task_domain covers exactly lab-origin records")
    check({r["task_domain"] for r in task} <= {"CYBER_OFFENSIVE", "NON_CYBER", "UNKNOWN"}, "allowed values: task_domain")
    tb = data["data/annotations/trust_boundaries.csv"]
    check({r["incident_id"] for r in tb} == {r["incident_id"] for r in inc if r["analysis_set"] in ("core", "core_low_confidence")},
          "trust_boundaries covers exactly core and low-confidence records")
    check(all(r["boundary_code"] in BOUNDARIES and r["basis"] in ("D", "I", "") and r["attempted"] in ("0", "1", "") for r in tb),
          "allowed values: trust_boundaries")
    pilot = {r["incident_id"] for r in data["data/annotations/pilot_sample.csv"]}
    check(len(pilot) == 15 and pilot <= idset and {r["incident_id"] for r in data["data/annotations/pilot_coder2.csv"]} == pilot,
          "independent-coder pilot: 15 existing records, all coded")

    src = data["data/sources.csv"]
    inc_claims = [r["claim_id"] for r in src if r["incident_id"] not in ("CAP",)]
    check(len(set(inc_claims)) == len(inc_claims), "claim_id unique (capability-dataset rows 'CAP:' carry no per-claim id; documented)")
    check({r["incident_id"] for r in src} <= idset | AGGREGATE_REFS, "evidence claims refer to records or documented aggregate references")

    camps = data["data/campaigns.csv"]
    check({r["campaign_id"] for r in camps} == {r["campaign_id"] for r in inc} and len(camps) == len({r["campaign_id"] for r in inc}),
          "campaigns.csv lists every campaign_id exactly once")
    members = {}
    for r in inc:
        members.setdefault(r["campaign_id"], []).append(r)
    ok_members = ok_core = True
    rows = analyze.load()
    for c in camps:
        m = members[c["campaign_id"]]
        ok_members &= c["member_incident_ids"].split(";") == [r["incident_id"] for r in m] and int(c["n_records"]) == len(m)
        core_m = [r for r in rows if r["campaign_id"] == c["campaign_id"] and r["analysis_set"] == "core"]
        ok_core &= int(c["n_core_members"]) == len(core_m)
        if core_m:
            ok_core &= c["core_unit_mechanism"] == analyze.collapse(core_m, "campaign")[0]["incident_type"]
    check(ok_members, "campaigns.csv membership matches incidents.csv")
    check(ok_core, "campaigns.csv core counts and campaign-level mechanism match the aggregation rule")

    counts = analyze.corpus_counts(rows)
    for k, v in EXPECTED_COUNTS.items():
        check(counts[k] == v, f"headline count {k} = {v}")
    pop = analyze.population_results(rows)
    for did, (a, m, n) in EXPECTED_POPULATIONS.items():
        got = {x["mechanism"]: (x["numerator"], x["denominator"]) for x in pop if x["definition"] == did}
        check(got["autonomous_objective_pursuit"] == (a, n) and got["malicious_operator_misuse"] == (m, n),
              f"population {did}: autonomous {a}/{n}, attacker-operated {m}/{n}")
    bnd, n_acted = analyze.boundary_results(rows)
    check(n_acted == 46, "46 agent-acted core events")
    for (scope, group), (o, p) in EXPECTED_BOUNDARIES.items():
        got = {x["measure"]: f"{x['numerator']}/{x['denominator']}" for x in bnd if x["scope"] == scope and x["group"] == group}
        check(got == {"outward_crossing": o, "own_asset_overreach": p}, f"boundaries {scope}/{group}: outward {o}, own-asset {p}")

    print(f"checks passed: {len(passes)}  failed: {len(fails)}")
    for f in fails:
        print("  FAIL:", f)
    print("VERIFICATION PASSED" if not fails else "VERIFICATION FAILED")
    sys.exit(0 if not fails else 1)


if __name__ == "__main__":
    main()
