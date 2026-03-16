"""
app.py — TrustChain Flask Server

Endpoints:
  POST /api/auth/request-otp       citizen requests OTP
  POST /api/auth/verify-otp        citizen verifies OTP
  GET  /api/citizen/documents      citizen views their documents
  POST /api/document/request       citizen requests a new document
  GET  /api/document/download/<id> citizen downloads a document
  POST /api/document/share/<id>    citizen shares document with verifier
  POST /api/verify                 verifier checks if document is genuine
  GET  /api/admin/stats            admin dashboard stats
  GET  /api/admin/alerts           SSE alert stream
  GET  /api/chain/summary          blockchain summary
  GET  /api/chain/history/<doc_id> blockchain history for a document
  GET  /                           citizen portal
  GET  /admin                      admin dashboard
"""

import os, sqlite3, hashlib, json, time, uuid, queue
from datetime import datetime
from flask import Flask, request, jsonify, Response, send_from_directory
from flask_cors import CORS

from blockchain_logger import (log_document_issue, log_verification,
                                log_suspicious, verify_document_hash,
                                verify_chain, get_document_history, get_summary)
from behaviour_monitor import analyse

BASE_DIR  = os.path.dirname(__file__)
DATA_DIR  = os.path.join(BASE_DIR, "..", "data")
FRONT_DIR = os.path.join(BASE_DIR, "..", "frontend")
DB_PATH   = os.path.join(DATA_DIR, "trustchain.db")

app  = Flask(__name__, static_folder=FRONT_DIR)
CORS(app)

_alert_listeners = []
_stats = {
    "total_requests": 0, "docs_issued": 0,
    "verifications": 0,  "suspicious_blocked": 0,
}

# ── helpers ────────────────────────────────────────────────────────────
def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def doc_hash(content, doc_id, issued_on):
    return hashlib.sha256(f"{content}{doc_id}{issued_on}".encode()).hexdigest()

def otp_for(aadhaar):
    h = hashlib.md5((aadhaar + "OTP_SALT_2024").encode()).hexdigest()
    return str(int(h[:6], 16) % 900000 + 100000)

def broadcast(alert):
    data = json.dumps(alert)
    for q in _alert_listeners:
        try: q.put_nowait(data)
        except queue.Full: pass

def document_content(doc_type, citizen):
    templates = {
        "income_certificate":  f"This is to certify that {citizen['full_name']} residing at {citizen['address']}, {citizen['state']} has an annual income within the prescribed limit as per revenue records.",
        "caste_certificate":   f"This is to certify that {citizen['full_name']} belongs to a recognized category as per government records. Aadhaar: {citizen['aadhaar_no'][:4]}XXXXXXXX.",
        "residence_certificate": f"This is to certify that {citizen['full_name']} is a permanent resident of {citizen['address']}, {citizen['state']} — PIN {citizen['pincode']}.",
        "medical_certificate": f"Health record for {citizen['full_name']} (DOB: {citizen['dob']}). Blood Group: O+. No critical allergies on record. Issued by Health Department.",
        "land_record":         f"Land ownership record for {citizen['full_name']}. Survey No: TC{citizen['pincode']}. Location: {citizen['state']}. Status: Clear title.",
        "birth_certificate":   f"Birth certificate for {citizen['full_name']}. Date of Birth: {citizen['dob']}. Place of Birth: {citizen['state']}. Registration confirmed.",
    }
    return templates.get(doc_type, f"Official document of type {doc_type} issued to {citizen['full_name']}.")

# ── auth ───────────────────────────────────────────────────────────────
@app.route("/api/auth/request-otp", methods=["POST"])
def request_otp():
    data   = request.get_json(force=True) or {}
    aadhar = str(data.get("aadhaar_no", "")).strip()
    if not aadhar or len(aadhar) != 12:
        return jsonify({"status": "error", "message": "Invalid Aadhaar number"}), 400
    conn = db()
    citizen = conn.execute(
        "SELECT * FROM citizens WHERE aadhaar_no=?", (aadhar,)
    ).fetchone()
    conn.close()
    if not citizen:
        return jsonify({"status": "error", "message": "Aadhaar not registered"}), 404
    otp   = otp_for(aadhar)
    phone = "XXXXXXX" + dict(citizen)["phone"][-3:]
    return jsonify({
        "status":     "otp_sent",
        "message":    f"OTP sent to {phone}",
        "_demo_otp":  otp,
    })

@app.route("/api/auth/verify-otp", methods=["POST"])
def verify_otp():
    data   = request.get_json(force=True) or {}
    aadhar = str(data.get("aadhaar_no", "")).strip()
    otp    = str(data.get("otp", "")).strip()
    if otp != otp_for(aadhar):
        return jsonify({"status": "error", "message": "Invalid OTP"}), 401
    conn    = db()
    citizen = conn.execute(
        "SELECT full_name, aadhaar_no, state, dob FROM citizens WHERE aadhaar_no=?",
        (aadhar,)
    ).fetchone()
    conn.close()
    if not citizen:
        return jsonify({"status": "error", "message": "Citizen not found"}), 404
    c = dict(citizen)
    return jsonify({
        "status":   "verified",
        "name":     c["full_name"],
        "aadhaar":  aadhar[:4] + "XXXXXXXX",
        "state":    c["state"],
        "token":    hashlib.md5((aadhar + "SESSION").encode()).hexdigest(),
    })

# ── citizen: view documents ────────────────────────────────────────────
@app.route("/api/citizen/documents", methods=["POST"])
def citizen_documents():
    data   = request.get_json(force=True) or {}
    aadhar = str(data.get("aadhaar_no", "")).strip()
    conn   = db()
    docs   = conn.execute(
        "SELECT doc_id,doc_type,issued_by,issued_on,status FROM documents WHERE aadhaar_no=?",
        (aadhar,)
    ).fetchall()
    conn.close()
    return jsonify({"status": "ok", "documents": [dict(d) for d in docs]})

# ── citizen: request a document ────────────────────────────────────────
@app.route("/api/document/request", methods=["POST"])
def request_document():
    data     = request.get_json(force=True) or {}
    aadhar   = str(data.get("aadhaar_no", "")).strip()
    doc_type = str(data.get("doc_type", "")).strip()

    valid_types = ["income_certificate", "caste_certificate",
                   "residence_certificate", "medical_certificate",
                   "land_record", "birth_certificate"]
    if doc_type not in valid_types:
        return jsonify({"status": "error", "message": "Invalid document type"}), 400

    conn    = db()
    citizen = conn.execute(
        "SELECT * FROM citizens WHERE aadhaar_no=?", (aadhar,)
    ).fetchone()
    if not citizen:
        conn.close()
        return jsonify({"status": "error", "message": "Citizen not found"}), 404

    c         = dict(citizen)
    doc_id    = "DOC" + str(uuid.uuid4())[:8].upper()
    issued_on = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    content   = document_content(doc_type, c)
    dhash     = doc_hash(content, doc_id, issued_on)

    dept_map  = {
        "income_certificate":    "Revenue Department",
        "caste_certificate":     "Revenue Department",
        "residence_certificate": "Municipal Corporation",
        "medical_certificate":   "Health Department",
        "land_record":           "Revenue Department",
        "birth_certificate":     "Municipal Corporation",
    }
    issued_by = dept_map.get(doc_type, "Government of India")

    # write to DB
    conn.execute("""
        INSERT INTO documents
          (doc_id,aadhaar_no,doc_type,issued_by,issued_on,content,doc_hash)
        VALUES (?,?,?,?,?,?,?)
    """, (doc_id, aadhar, doc_type, issued_by, issued_on, content, dhash))
    conn.commit()
    conn.close()

    # write to blockchain
    block = log_document_issue(doc_id, aadhar[:4]+"XXXXXXXX",
                                doc_type, issued_by, dhash)
    _stats["docs_issued"] += 1

    broadcast({
        "type":      "DOCUMENT_ISSUED",
        "timestamp": datetime.now().strftime("%H:%M:%S"),
        "doc_type":  doc_type,
        "issued_to": c["full_name"],
        "doc_id":    doc_id,
        "block":     block["hash"][:16] + "...",
    })

    return jsonify({
        "status":    "issued",
        "doc_id":    doc_id,
        "doc_type":  doc_type,
        "issued_by": issued_by,
        "issued_on": issued_on,
        "doc_hash":  dhash,
        "block_hash": block["hash"][:16] + "...",
        "message":   f"Document issued and recorded on blockchain",
    })

# ── citizen: download document ─────────────────────────────────────────
@app.route("/api/document/download/<doc_id>", methods=["GET"])
def download_document(doc_id):
    conn = db()
    doc  = conn.execute(
        "SELECT * FROM documents WHERE doc_id=?", (doc_id,)
    ).fetchone()
    conn.close()
    if not doc:
        return jsonify({"status": "error", "message": "Document not found"}), 404
    d = dict(doc)
    return jsonify({
        "status":    "ok",
        "doc_id":    d["doc_id"],
        "doc_type":  d["doc_type"],
        "content":   d["content"],
        "issued_by": d["issued_by"],
        "issued_on": d["issued_on"],
        "doc_hash":  d["doc_hash"],
        "verification_url": f"/api/verify",
        "verification_code": d["doc_hash"][:16],
    })

# ── verifier: verify document ──────────────────────────────────────────
@app.route("/api/verify", methods=["POST"])
def verify_document():
    data          = request.get_json(force=True) or {}
    doc_id        = str(data.get("doc_id", "")).strip()
    verifier_name = str(data.get("verifier_name", "Unknown")).strip()
    verifier_type = str(data.get("verifier_type", "institution")).strip()
    ip            = request.headers.get("X-Forwarded-For", request.remote_addr)
    ua            = request.headers.get("User-Agent", "")

    _stats["total_requests"] += 1

    # behaviour check on verifier
    beh = analyse(source=verifier_name or ip, doc_id=doc_id, user_agent=ua)
    if beh["is_suspicious"]:
        _stats["suspicious_blocked"] += 1
        log_suspicious("Bulk verification attempt", {
            "verifier": verifier_name,
            "score":    beh["score"],
            "signals":  beh["signals"],
        })
        broadcast({
            "type":      "SUSPICIOUS",
            "timestamp": datetime.now().strftime("%H:%M:%S"),
            "verifier":  verifier_name,
            "score":     beh["score"],
            "signals":   " | ".join(beh["signals"]),
        })
        return jsonify({
            "status":  "blocked",
            "message": "Unusual verification pattern detected. Access temporarily restricted.",
        }), 429

    conn = db()
    doc  = conn.execute(
        "SELECT * FROM documents WHERE doc_id=?", (doc_id,)
    ).fetchone()
    conn.close()

    if not doc:
        return jsonify({"status": "error", "message": "Document not found"}), 404

    d      = dict(doc)
    result = verify_document_hash(doc_id, d["doc_hash"])
    status = "GENUINE" if not result.get("tampered") else "TAMPERED"

    # log verification to blockchain
    log_verification(doc_id, verifier_name, status)
    _stats["verifications"] += 1

    # save to verifications table
    conn = db()
    conn.execute("""
        INSERT INTO verifications
          (doc_id,verifier_name,verifier_type,verified_on,result,ip)
        VALUES (?,?,?,?,?,?)
    """, (doc_id, verifier_name, verifier_type,
          datetime.now().strftime("%Y-%m-%d %H:%M:%S"), status, ip))
    conn.commit()
    conn.close()

    broadcast({
        "type":      "VERIFICATION",
        "timestamp": datetime.now().strftime("%H:%M:%S"),
        "verifier":  verifier_name,
        "doc_id":    doc_id,
        "result":    status,
    })

    return jsonify({
        "status":     status,
        "doc_id":     doc_id,
        "doc_type":   d["doc_type"],
        "issued_by":  d["issued_by"],
        "issued_on":  d["issued_on"],
        "verified_by": verifier_name,
        "message":    "Document is genuine and untampered." if status == "GENUINE"
                      else "WARNING: Document hash mismatch. This document may be forged.",
    })

# ── admin ──────────────────────────────────────────────────────────────
@app.route("/api/admin/stats")
def admin_stats():
    chain = get_summary()
    return jsonify({**_stats, **chain})

@app.route("/api/admin/alerts")
def alert_stream():
    q = queue.Queue(maxsize=50)
    _alert_listeners.append(q)
    def stream():
        try:
            yield 'data: {"type":"connected"}\n\n'
            while True:
                try:
                    yield f"data: {q.get(timeout=25)}\n\n"
                except queue.Empty:
                    yield ": heartbeat\n\n"
        finally:
            _alert_listeners.remove(q)
    return Response(stream(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache"})

@app.route("/api/chain/summary")
def chain_summary():
    return jsonify(get_summary())

@app.route("/api/chain/history/<doc_id>")
def chain_history(doc_id):
    return jsonify({"history": get_document_history(doc_id)})

@app.route("/api/chain/verify")
def chain_verify():
    return jsonify(verify_chain())

# ── serve frontend ─────────────────────────────────────────────────────
@app.route("/")
def citizen_portal():
    return send_from_directory(FRONT_DIR, "portal.html")

@app.route("/admin")
def admin_portal():
    return send_from_directory(FRONT_DIR, "admin.html")

if __name__ == "__main__":
    if not os.path.exists(DB_PATH):
        import subprocess, sys
        subprocess.run([sys.executable,
                        os.path.join(BASE_DIR, "database_setup.py")])
    print("\n🔐 TrustChain server starting on http://localhost:5000")
    print("   Citizen portal → http://localhost:5000")
    print("   Admin dashboard → http://localhost:5000/admin\n")
    app.run(debug=True, port=5000, threaded=True)
