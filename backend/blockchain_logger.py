"""
blockchain_logger.py
Tamper-proof blockchain for TrustChain.
Every document issue and verification is an immutable block.
"""

import hashlib, json, time, os

CHAIN_FILE = os.path.join(os.path.dirname(__file__), "..", "data", "trustchain_audit.json")

def _hash(data):
    return hashlib.sha256(data.encode()).hexdigest()

def _make_block(index, event_type, data, previous_hash):
    block = {
        "index":         index,
        "timestamp":     time.strftime("%Y-%m-%d %H:%M:%S"),
        "event_type":    event_type,
        "data":          data,
        "previous_hash": previous_hash,
    }
    block["hash"] = _hash(json.dumps(block, sort_keys=True))
    return block

def _load():
    if not os.path.exists(CHAIN_FILE):
        os.makedirs(os.path.dirname(CHAIN_FILE), exist_ok=True)
        genesis = _make_block(0, "GENESIS", {"msg": "TrustChain started"}, "0"*64)
        _save([genesis])
        return [genesis]
    with open(CHAIN_FILE) as f:
        return json.load(f)

def _save(chain):
    with open(CHAIN_FILE, "w") as f:
        json.dump(chain, f, indent=2)

def log_event(event_type, data):
    chain     = _load()
    new_block = _make_block(len(chain), event_type, data, chain[-1]["hash"])
    chain.append(new_block)
    _save(chain)
    return new_block

def log_document_issue(doc_id, aadhaar_masked, doc_type, issued_by, doc_hash):
    return log_event("DOCUMENT_ISSUED", {
        "doc_id":        doc_id,
        "citizen":       aadhaar_masked,
        "doc_type":      doc_type,
        "issued_by":     issued_by,
        "doc_hash":      doc_hash,
    })

def log_verification(doc_id, verifier, result):
    return log_event("VERIFICATION", {
        "doc_id":   doc_id,
        "verifier": verifier,
        "result":   result,
    })

def log_suspicious(event, details):
    return log_event("SUSPICIOUS", {"event": event, "details": details})

def verify_document_hash(doc_id, current_hash):
    chain = _load()
    for block in reversed(chain):
        if (block["event_type"] == "DOCUMENT_ISSUED"
                and block["data"].get("doc_id") == doc_id):
            original = block["data"]["doc_hash"]
            tampered = current_hash != original
            if tampered:
                log_event("TAMPER_DETECTED", {
                    "doc_id":        doc_id,
                    "original_hash": original,
                    "current_hash":  current_hash,
                })
            return {
                "tampered":      tampered,
                "original_hash": original,
                "current_hash":  current_hash,
                "issued_on":     block["timestamp"],
                "issued_by":     block["data"].get("issued_by"),
            }
    return {"tampered": False, "note": "Document not found on chain"}

def verify_chain():
    chain = _load()
    for i in range(1, len(chain)):
        b    = chain[i]
        prev = chain[i-1]
        chk  = {k: v for k, v in b.items() if k != "hash"}
        if b["hash"] != _hash(json.dumps(chk, sort_keys=True)):
            return {"valid": False, "broken_at": i}
        if b["previous_hash"] != prev["hash"]:
            return {"valid": False, "broken_at": i}
    return {"valid": True, "total_blocks": len(chain)}

def get_document_history(doc_id):
    chain  = _load()
    return [b for b in chain if b["data"].get("doc_id") == doc_id]

def get_summary():
    chain = _load()
    return {
        "total_blocks":   len(chain),
        "docs_issued":    sum(1 for b in chain if b["event_type"] == "DOCUMENT_ISSUED"),
        "verifications":  sum(1 for b in chain if b["event_type"] == "VERIFICATION"),
        "tampers":        sum(1 for b in chain if b["event_type"] == "TAMPER_DETECTED"),
        "suspicious":     sum(1 for b in chain if b["event_type"] == "SUSPICIOUS"),
        "chain_valid":    verify_chain()["valid"],
    }
