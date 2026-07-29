#!/usr/bin/env python3
"""
Pretty-print a SARIF file's findings so you can eyeball one tool's output
independently, without running the full normalize/retrieve pipeline.

Usage:
    python3 scripts/view_sarif.py scan_out/roslyn.sarif
    python3 scripts/view_sarif.py scan_out/trivy.sarif --max 20
"""
import json
import sys
import argparse


def get_message(res):
    m = res.get("message")
    if isinstance(m, dict):
        return m.get("text") or m.get("markdown") or ""
    return m if isinstance(m, str) else ""


def get_location(res):
    locs = res.get("locations") or []
    if not locs:
        return None
    pl = locs[0].get("physicalLocation") or locs[0].get("resultFile") or {}
    uri = (pl.get("artifactLocation", {}) or {}).get("uri") or pl.get("uri")
    line = (pl.get("region", {}) or {}).get("startLine")
    if uri and line:
        return f"{uri}:{line}"
    return uri


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("sarif_path")
    ap.add_argument("--max", type=int, default=50, help="max findings to print")
    args = ap.parse_args()

    with open(args.sarif_path) as f:
        data = json.load(f)

    runs = data.get("runs", [])
    if not runs:
        print(f"[{args.sarif_path}] no runs in this SARIF file (tool produced zero output)")
        return

    total = 0
    for run in runs:
        driver = run.get("tool", {}).get("driver", {})
        tool_name = driver.get("name", "unknown-tool")
        results = run.get("results", [])
        print(f"\n=== {args.sarif_path} :: tool={tool_name} :: {len(results)} findings ===")

        # ruleId -> shortDescription, if the SARIF carries rule metadata
        rule_desc = {}
        for rule in driver.get("rules", []) or []:
            if isinstance(rule, dict):
                rid = rule.get("id")
                sd = rule.get("shortDescription", {})
                rule_desc[rid] = sd.get("text") if isinstance(sd, dict) else str(sd or "")

        for i, res in enumerate(results):
            if total >= args.max:
                print(f"... truncated at --max={args.max}")
                return
            rid = res.get("ruleId", "?")
            level = res.get("level", "warning")
            msg = get_message(res)
            loc = get_location(res)
            desc = rule_desc.get(rid, "")
            print(f"[{level:9s}] {rid:14s} {loc or ''}")
            print(f"    {msg[:140]}")
            if desc and desc[:100] not in msg:
                print(f"    ({desc[:100]})")
            total += 1

    print(f"\n--- total findings across all runs: {total} ---")


if __name__ == "__main__":
    main()
