#!/usr/bin/env python3
"""NetFRAME infrastructure knowledge model (Phase 3: recognition -> understanding).

Loads the dependency graph (knowledge/topology.json) and computes blast radius
DETERMINISTICALLY: given a failing entity, which entities transitively depend on it and
what is the stated impact of each. The interpreter uses this so its impact statements are
grounded in a real graph, not guessed. Pure stdlib.

Examples:
  netframe_knowledge.py impact randy      # what breaks if Randy degrades
  netframe_knowledge.py deps rke2_pvcs    # what rke2_pvcs depends on
  netframe_knowledge.py entities          # list known entities
"""
import json
import os
import sys

BASE = os.environ.get("NETFRAME_BASE", "/opt/netframe-monitor")
TOPOLOGY = f"{BASE}/knowledge/topology.json"

# telemetry host/service names -> graph entity ids, so a node verdict maps into the graph
ALIASES = {
    "randy": "randy", "quarkylab": "quarkylab", "jarvis": "jarvis",
    "pve2": "pve2", "pve3": "pve3", "pve4": "pve4", "pve5": "pve5",
    "monitoring": "monitoring_ct103", "wazuh": "wazuh_vm",
}


def load(path=TOPOLOGY):
    if not os.path.exists(path):
        return {"entities": {}, "dependencies": []}
    try:
        return json.load(open(path))
    except (ValueError, OSError):
        return {"entities": {}, "dependencies": []}


def blast_radius(entity, graph=None):
    """All entities that transitively depend on `entity`, with the impact chain.
    Returns [{entity, impact, via}] ordered breadth-first (closest dependents first)."""
    graph = graph or load()
    deps = graph.get("dependencies", [])
    # reverse adjacency: dependency -> [(dependent, impact)]
    rev = {}
    for d in deps:
        rev.setdefault(d["on"], []).append((d["dependent"], d.get("impact", "")))
    out, seen, queue = [], {entity}, [(entity, None, None)]
    while queue:
        cur, _, _ = queue.pop(0)
        for dependent, impact in rev.get(cur, []):
            if dependent in seen:
                continue
            seen.add(dependent)
            out.append({"entity": dependent, "impact": impact, "via": cur})
            queue.append((dependent, impact, cur))
    return out


def dependencies_of(entity, graph=None):
    graph = graph or load()
    return [{"on": d["on"], "impact": d.get("impact", "")}
            for d in graph.get("dependencies", []) if d["dependent"] == entity]


def impact_for_failures(failed_hosts, graph=None):
    """Given telemetry host/service names that are non-OK, return a compact blast-radius
    map the interpreter can state. Only entities present in the graph are considered."""
    graph = graph or load()
    result = {}
    for host in failed_hosts:
        ent = ALIASES.get(host, host)
        if ent not in graph.get("entities", {}):
            continue
        radius = blast_radius(ent, graph)
        if radius:
            result[ent] = [{"affects": r["entity"],
                            "impact": r["impact"],
                            "role": graph["entities"].get(r["entity"], {}).get("role", "")}
                           for r in radius]
    return result


def _print_impact(entity):
    graph = load()
    ent = ALIASES.get(entity, entity)
    if ent not in graph.get("entities", {}):
        print(f"unknown entity '{entity}'. Known: {', '.join(sorted(graph['entities']))}")
        return
    radius = blast_radius(ent, graph)
    role = graph["entities"][ent].get("role", "")
    print(f"{ent} ({role})")
    if not radius:
        print("  nothing depends on it in the model.")
        return
    print(f"  if it degrades/fails, {len(radius)} downstream effect(s):")
    for r in radius:
        print(f"   -> {r['entity']}: {r['impact']}  (via {r['via']})")


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return
    cmd = sys.argv[1]
    if cmd == "impact" and len(sys.argv) > 2:
        _print_impact(sys.argv[2])
    elif cmd == "deps" and len(sys.argv) > 2:
        for d in dependencies_of(ALIASES.get(sys.argv[2], sys.argv[2])):
            print(f"  depends on {d['on']}: {d['impact']}")
    elif cmd == "entities":
        g = load()
        for k, v in sorted(g.get("entities", {}).items()):
            print(f"  {k} ({v.get('type')}): {v.get('role', '')}")
    else:
        print(__doc__)


if __name__ == "__main__":
    main()
