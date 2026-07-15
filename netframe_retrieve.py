#!/usr/bin/env python3
"""NetFRAME retrieval layer for the operations console.

Embeds the corpus (known-events ledger, standing context, report sections, the
knowledge graph, the constitution, and past conversations) with nomic-embed-text and
answers retrieve(query, k) with only the most relevant chunks, so the chat brain gets
focused evidence instead of the whole database. Pure stdlib; cosine in Python (the
corpus is small enough that no vector DB is warranted).

CLI:
  netframe_retrieve.py build          # (re)build the embedding index
  netframe_retrieve.py query "..."    # show what would be retrieved
"""
import glob
import json
import math
import os
import re
import sys
import urllib.request

BASE = os.environ.get("NETFRAME_BASE", "/opt/netframe-monitor")
INDEX = f"{BASE}/retrieval-index.json"
OLLAMA = os.environ.get("NETFRAME_OLLAMA_URL", "http://localhost:11434").rstrip("/")
EMBED_MODEL = os.environ.get("NETFRAME_EMBED_MODEL", "nomic-embed-text")
EMBED_URL = f"{OLLAMA}/api/embeddings"


def embed(text):
    req = urllib.request.Request(EMBED_URL,
                                 data=json.dumps({"model": EMBED_MODEL, "prompt": text}).encode(),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode())["embedding"]


def _split_md(text, source):
    """Chunk markdown by heading, keeping each section whole-ish."""
    chunks, cur, title = [], [], source
    for line in text.splitlines():
        if re.match(r"^#{1,3} ", line):
            if cur:
                chunks.append((title, "\n".join(cur).strip()))
            title = line.lstrip("# ").strip()
            cur = [line]
        else:
            cur.append(line)
    if cur:
        chunks.append((title, "\n".join(cur).strip()))
    return [(f"{source}: {t}", c) for t, c in chunks if len(c) > 40]


def _split_events(text):
    """One chunk per EVT-NNN block in the known-events ledger."""
    blocks = re.split(r"(?=^#{0,3}\s*EVT-\d+|\bEVT-\d+)", text, flags=re.M)
    out = []
    for b in blocks:
        b = b.strip()
        m = re.search(r"EVT-\d+", b)
        if m and len(b) > 40:
            out.append((f"known-events: {m.group(0)}", b[:1500]))
    return out


def _topology_chunks():
    path = f"{BASE}/knowledge/topology.json"
    if not os.path.exists(path):
        return []
    try:
        g = json.load(open(path))
    except (ValueError, OSError):
        return []
    out = []
    for eid, e in g.get("entities", {}).items():
        deps = [d for d in g.get("dependencies", []) if d["on"] == eid]
        dependents = ", ".join(f"{d['dependent']} ({d.get('impact', '')})" for d in deps)
        out.append((f"topology: {eid}",
                    f"{eid} [{e.get('type')}] role: {e.get('role', '')}. "
                    f"If it fails, these depend on it: {dependents or 'none'}."))
    return out


def _conversation_chunks():
    path = f"{BASE}/context/conversations.jsonl"
    if not os.path.exists(path):
        return []
    out = []
    for line in open(path):
        line = line.strip()
        if not line:
            continue
        try:
            c = json.loads(line)
            q = c.get("question", "")
            summ = (c.get("summary") or c.get("response", "")[:300])
            if q:
                out.append((f"past-conversation: {c.get('ts', '')[:10]}",
                            f"Q: {q}\nA: {summ}"))
        except ValueError:
            continue
    return out[-40:]  # only recent conversations


def gather():
    chunks = []
    ev = f"{BASE}/context/30-known-events.md"
    if os.path.exists(ev):
        chunks += _split_events(open(ev).read())
    for pat in ("context/00-architecture.md", "context/10-reliability-spofs.md",
                "context/20-recent-changes.md", "context/40-remediation-actions.md",
                "context/pentest-remediation.md", "constitution/*.md",
                "report.md", "report-predict.md", "report-confdrift.md",
                "report-github.md", "report-monthly.md", "report-chief.md"):
        for path in glob.glob(f"{BASE}/{pat}"):
            src = os.path.relpath(path, BASE)
            chunks += _split_md(open(path).read(), src)
    chunks += _topology_chunks()
    chunks += _conversation_chunks()
    return chunks


def build():
    chunks = gather()
    indexed = []
    for i, (source, text) in enumerate(chunks):
        try:
            vec = embed(text)
        except Exception as e:  # noqa: BLE001
            print(f"  skip chunk {i} ({source}): {e}", file=sys.stderr)
            continue
        norm = math.sqrt(sum(x * x for x in vec)) or 1.0
        indexed.append({"id": i, "source": source, "text": text, "vec": vec, "norm": norm})
    json.dump({"model": EMBED_MODEL, "chunks": indexed}, open(INDEX, "w"))
    print(f"indexed {len(indexed)} chunks -> {INDEX}")
    return indexed


def _load():
    if os.path.exists(INDEX):
        try:
            return json.load(open(INDEX)).get("chunks", [])
        except (ValueError, OSError):
            return []
    return []


def retrieve(query, k=8):
    chunks = _load()
    if not chunks:
        return []
    try:
        qv = embed(query)
    except Exception:  # noqa: BLE001 - retrieval is best-effort; caller still has live state
        return []
    qn = math.sqrt(sum(x * x for x in qv)) or 1.0
    scored = []
    for c in chunks:
        dot = sum(a * b for a, b in zip(qv, c["vec"]))
        scored.append((dot / (qn * c["norm"]), c))
    scored.sort(key=lambda s: -s[0])
    return [{"source": c["source"], "text": c["text"], "score": round(sc, 3)}
            for sc, c in scored[:k]]


def main():
    if len(sys.argv) >= 2 and sys.argv[1] == "build":
        build()
    elif len(sys.argv) >= 3 and sys.argv[1] == "query":
        if not _load():
            build()
        for r in retrieve(sys.argv[2]):
            print(f"[{r['score']}] {r['source']}\n    {r['text'][:120].replace(chr(10), ' ')}...")
    else:
        print(__doc__)


if __name__ == "__main__":
    main()
