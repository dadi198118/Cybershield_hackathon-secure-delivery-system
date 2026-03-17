"""
behaviour_monitor.py
Detects suspicious behaviour from verifiers (banks, universities, employers)
who are bulk harvesting citizen documents through legitimate channels.
"""

import time, math, statistics
from collections import defaultdict, deque

_sessions = defaultdict(lambda: {
    "requests":     deque(maxlen=200),
    "docs_seen":    deque(maxlen=200),
    "request_count": 0,
})

RATE_WINDOW   = 60
MAX_REQ_MIN   = 20
MAX_DOCS_MIN  = 10
SEQ_THRESHOLD = 0.75
MIN_ENTROPY   = 2.0
BAD_AGENTS    = ["python-requests", "curl/", "wget/", "scrapy", "sqlmap"]

def _velocity(session, now):
    return sum(1 for t in session["requests"] if now - t < RATE_WINDOW)

def _entropy(items):
    if len(items) < 4:
        return 10.0
    freq = defaultdict(int)
    for i in items:
        freq[str(i)[-4:]] += 1
    total = len(items)
    return -sum((c/total)*math.log2(c/total) for c in freq.values())

def analyse(source, doc_id, user_agent="", extra=None):
    now     = time.time()
    session = _sessions[source]
    signals = []
    score   = 0

    session["requests"].append(now)
    session["docs_seen"].append(doc_id)
    session["request_count"] += 1

    # velocity
    vel = _velocity(session, now)
    if vel > MAX_REQ_MIN:
        score += min(60, 20 + (vel - MAX_REQ_MIN) * 2)
        signals.append(f"HIGH_VELOCITY: {vel} requests/min — bulk harvesting suspected")

    # unique docs
    unique = len(set(list(session["docs_seen"])[-20:]))
    if unique > MAX_DOCS_MIN:
        score += 30
        signals.append(f"BULK_ACCESS: {unique} distinct documents accessed recently")

    # low entropy
    ent = _entropy(list(session["docs_seen"]))
    if len(session["docs_seen"]) >= 6 and ent < MIN_ENTROPY:
        score += 25
        signals.append(f"LOW_ENTROPY: uniform document access pattern ({ent:.2f})")

    # bad agent
    ua = (user_agent or "").lower()
    for bad in BAD_AGENTS:
        if bad in ua:
            score += 35
            signals.append(f"SUSPICIOUS_AGENT: '{bad}' in User-Agent")
            break

    # timing
    very_recent = [t for t in session["requests"] if now - t < 1.0]
    if len(very_recent) >= 3:
        score += 25
        signals.append("TIMING_PROBE: machine-speed requests detected")

    score = min(score, 100)
    if score < 30:
        return {"is_suspicious": False, "score": score, "signals": []}

    return {
        "is_suspicious": True,
        "score":         score,
        "signals":       signals,
        "type":          "Bulk Document Harvesting" if "BULK" in " ".join(signals)
                         else "Automated Scraping",
    }
