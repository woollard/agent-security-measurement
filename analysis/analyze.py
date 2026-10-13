#!/usr/bin/env python3
"""Reproduce the principal findings of Technical Note 03 from the incident database.

Usage:
  python analysis/analyze.py                 # print the results
  python analysis/analyze.py --out DIR       # also write population_results.csv and boundary_results.csv to DIR

Standard library only (Python >= 3.9). Reads data/incidents.csv, data/sources.csv and data/annotations/*.csv.

It reproduces two analyses:
  A. Mechanism shares under nine population definitions (P1-P9) and two post hoc OpenAI exclusions (S2, S3).
  B. Outward trust-boundary crossings versus own-asset overreach among core events in which the agent acted
     without an attacker operating it, by operating environment (and lab task domain), with and without
     OpenAI-operated lab events.
The rules below are identical to those of the frozen analysis behind the note (docs/methodology.md).
Shares describe this curated collection of public disclosures; they are not incident rates.
"""
import argparse, csv, math, os
from collections import Counter, OrderedDict, defaultdict

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LAB_ENVS = ("LAB_EVAL", "LAB_TRAIN", "DEV_INTERNAL")
CONFIRMED = ("confirmed_by_affected_org", "confirmed_by_responsible_developer", "confirmed_by_independent_researcher")
VERIFIED = ("verified_in_source", "verified_browser_transcription")
MECHANISMS = ["autonomous_objective_pursuit", "agent_operational_failure", "prompt_injection_or_hijack",
              "attacker_controlled_tool_or_supply_chain", "malicious_operator_misuse",
              "research_demonstration", "in_sandbox_eval"]
OUTWARD = ("CR", "TP", "RT", "EG")


def read(rel):
    with open(os.path.join(REPO, rel), newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def wilson(k, n, z=1.96):
    if n == 0:
        return float("nan"), float("nan")
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return max(0.0, c - h), min(1.0, c + h)


# ----------------------------------------------------------------------------------------------- load
def openai_operated(r):
    """Rule used for the note's OpenAI-operated exclusion: an OpenAI agent in a lab/developer environment.
    (The underlying 'OpenAI' marker is the study's original heuristic over IDs and first_disclosed_by.)"""
    i = r["incident_id"]
    marked = (i.startswith(("OAI", "REG-OAI", "REG-AU", "REG-N-")) or "OpenAI" in r["first_disclosed_by"]
              or i in ("GAP-G-05", "REG-INC-020"))
    return marked and r["env_v2"] in LAB_ENVS


def first_disclosed_by_openai(r):
    s = r["first_disclosed_by"].strip().lower()
    return s.startswith("openai") or "and openai" in s


def load():
    rows = read("data/incidents.csv")
    env = {r["incident_id"]: r["env_v2"] for r in read("data/annotations/environment_recode.csv")}
    task = {r["incident_id"]: r["task_domain"] for r in read("data/annotations/task_domain.csv")}
    verified = Counter(e["incident_id"] for e in read("data/sources.csv") if e["verification_status"] in VERIFIED)
    bounds = defaultdict(list)
    for b in read("data/annotations/trust_boundaries.csv"):
        if b["boundary_code"] != "NONE":
            bounds[b["incident_id"]].append(b)
    for r in rows:
        i = r["incident_id"]
        r["env_v2"], r["task_domain"] = env.get(i, ""), task.get(i, "")
        r["n_verified_claims"] = verified.get(i, 0)
        r["boundaries"] = bounds.get(i, [])
        r["root_unit"] = r["shared_root_cause_id"] or r["campaign_id"]
        r["openai_operated"] = openai_operated(r)
        r["first_disclosed_by_openai"] = first_disclosed_by_openai(r)
    return rows


def collapse(rows, unit):
    """Events -> campaigns or root causes: modal mechanism, ties broken by the earliest-disclosed member."""
    if unit == "event":
        return rows
    key = "campaign_id" if unit == "campaign" else "root_unit"
    groups = OrderedDict()
    for r in rows:
        groups.setdefault(r[key], []).append(r)
    out = []
    for g in groups.values():
        g = sorted(g, key=lambda r: r["first_public_disclosure"] or "9999")
        c = Counter(r["incident_type"] for r in g)
        top = max(c.values())
        out.append({"incident_type": next(r["incident_type"] for r in g if c[r["incident_type"]] == top)})
    return out


# ----------------------------------------------------------------------------------------- Finding A
def core(r):
    return r["analysis_set"] == "core"


DEFINITIONS = [
    ("P1", "All candidate records (not authoritative)", "event", lambda r: True),
    ("P2", "Core included events", "event", core),
    ("P3", "Core events collapsed to campaigns", "campaign", core),
    ("P4", "Confirmed real-world incidents only", "event",
     lambda r: core(r) and r["real_world_consequence"] == "yes" and r["confirmation_status"] in CONFIRMED),
    ("P5", "Excluding lab/evaluation/training/developer-internal origin", "event", lambda r: core(r) and r["env_v2"] not in LAB_ENVS),
    ("P6", "In-scope records excluding research demonstrations", "event",
     lambda r: r["analysis_set"] in ("core", "core_low_confidence", "in_sandbox")),
    ("P7", "High-confidence, primary-source-verified", "event",
     lambda r: core(r) and r["evidence_quality"] in ("A", "B") and r["confirmation_status"] in CONFIRMED and r["n_verified_claims"] > 0),
    ("P8", "Excluding retrospective discoveries", "event", lambda r: core(r) and r["retrospective_discovery"] != "yes"),
    ("P9", "Core collapsed to shared root causes", "root", core),
    ("S2", "Core excluding OpenAI-operated lab events (post hoc)", "event", lambda r: core(r) and not r["openai_operated"]),
    ("S3", "Core excluding events first disclosed by OpenAI (post hoc)", "event", lambda r: core(r) and not r["first_disclosed_by_openai"]),
]


def population_results(rows):
    out = []
    for did, label, unit, pred in DEFINITIONS:
        units = collapse([r for r in rows if pred(r)], unit)
        n = len(units)
        counts = Counter(u["incident_type"] for u in units)
        ranked = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))
        top_n = ranked[0][1]
        for m in MECHANISMS:
            k = counts.get(m, 0)
            lo, hi = wilson(k, n)
            out.append({"definition": did, "label": label, "unit": unit, "mechanism": m, "numerator": k, "denominator": n,
                        "share": round(k / n, 6), "wilson_low": round(lo, 6), "wilson_high": round(hi, 6),
                        "is_top": int(k == top_n and k > 0), "top_is_tied": int(sum(1 for v in counts.values() if v == top_n) > 1)})
    return out


# ----------------------------------------------------------------------------------------- Finding B
def realised(r, code):
    return any(b["boundary_code"] == code and b["attempted"] == "0" for b in r["boundaries"])


GROUPS = [("lab_offensive_cyber", lambda r: r["env_v2"] in LAB_ENVS and r["task_domain"] == "CYBER_OFFENSIVE"),
          ("lab_non_cyber", lambda r: r["env_v2"] in LAB_ENVS and r["task_domain"] == "NON_CYBER"),
          ("lab_task_not_stated", lambda r: r["env_v2"] in LAB_ENVS and r["task_domain"] == "UNKNOWN"),
          ("lab_all", lambda r: r["env_v2"] in LAB_ENVS),
          ("user_deployed", lambda r: r["env_v2"] == "USER_DEPLOY")]
SCOPES = [("all", lambda r: True), ("excl_openai_operated_lab", lambda r: not r["openai_operated"])]


def boundary_results(rows):
    acted = [r for r in rows if core(r) and r["incident_type"] in ("autonomous_objective_pursuit", "agent_operational_failure")
             and r["env_v2"] in LAB_ENVS + ("USER_DEPLOY",)]
    out = []
    for sid, sfun in SCOPES:
        for gid, gfun in GROUPS:
            sub = [r for r in acted if sfun(r) and gfun(r)]
            for measure, f in (("outward_crossing", lambda r: any(realised(r, c) for c in OUTWARD)),
                               ("own_asset_overreach", lambda r: realised(r, "PA"))):
                k, n = sum(1 for r in sub if f(r)), len(sub)
                lo, hi = wilson(k, n)
                out.append({"scope": sid, "group": gid, "measure": measure, "numerator": k, "denominator": n,
                            "n_campaigns": len({r["campaign_id"] for r in sub}), "share": round(k / n, 6) if n else "",
                            "wilson_low": round(lo, 6) if n else "", "wilson_high": round(hi, 6) if n else ""})
    return out, len(acted)


def corpus_counts(rows):
    c = Counter(r["analysis_set"] for r in rows)
    cr = [r for r in rows if core(r)]
    return OrderedDict([("candidate_records", len(rows)), ("core_events", c["core"]),
                        ("core_campaigns", len({r["campaign_id"] for r in cr})),
                        ("core_root_cause_units", len({r["root_unit"] for r in cr})),
                        ("core_low_confidence", c["core_low_confidence"]), ("research_demonstrations", c["demonstration"]),
                        ("in_sandbox", c["in_sandbox"]), ("context_excluded", c["context_excluded"]),
                        ("duplicates", sum(1 for r in rows if r["duplicate_of"]))])


def write(path, rows):
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()), lineterminator="\n")
        w.writeheader()
        w.writerows(rows)


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--out", help="directory for population_results.csv and boundary_results.csv")
    args = ap.parse_args()
    rows = load()
    print("Corpus:", ", ".join(f"{k}={v}" for k, v in corpus_counts(rows).items()))
    pop = population_results(rows)
    print("\nA. Mechanism shares by population definition (autonomous pursuit vs attacker-operated misuse)")
    for did, label, unit, _ in DEFINITIONS:
        a = next(x for x in pop if x["definition"] == did and x["mechanism"] == "autonomous_objective_pursuit")
        m = next(x for x in pop if x["definition"] == did and x["mechanism"] == "malicious_operator_misuse")
        top = [x["mechanism"] for x in pop if x["definition"] == did and x["is_top"]]
        print(f"  {did} {label:<62} {a['numerator']:>3}/{a['denominator']:<4} {m['numerator']:>3}/{m['denominator']:<4} "
              f"[{unit}] top: {' = '.join(top)}")
    bnd, n_acted = boundary_results(rows)
    print(f"\nB. Agent-acted core events (n={n_acted}): outward crossing / own-asset overreach")
    for sid, _ in SCOPES:
        for gid, _ in GROUPS:
            o = next(x for x in bnd if x["scope"] == sid and x["group"] == gid and x["measure"] == "outward_crossing")
            p = next(x for x in bnd if x["scope"] == sid and x["group"] == gid and x["measure"] == "own_asset_overreach")
            print(f"  {sid:<25} {gid:<20} outward {o['numerator']:>2}/{o['denominator']:<3} own-asset {p['numerator']:>2}/{p['denominator']:<3} "
                  f"({o['n_campaigns']} campaigns)")
    if args.out:
        os.makedirs(args.out, exist_ok=True)
        write(os.path.join(args.out, "population_results.csv"), pop)
        write(os.path.join(args.out, "boundary_results.csv"), bnd)
        print(f"\nWrote population_results.csv and boundary_results.csv to {args.out}")
    print("\nShares describe a curated collection of public disclosures; they are not incident rates.")


if __name__ == "__main__":
    main()
