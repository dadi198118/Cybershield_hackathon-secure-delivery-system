"""
simulator.py — TrustChain Demo Simulator

Scenarios:
  1. legit    — citizen requests and downloads documents normally
  2. verify   — institution verifies a citizen's document
  3. bulk     — institution tries to bulk harvest documents (caught by behaviour monitor)
  4. all      — runs all scenarios

Usage:
  python simulator/simulator.py --scenario all
"""

import requests, time, argparse, random

BASE = "http://localhost:5000/api"
RED   = "\033[91m"; GREEN = "\033[92m"
YELLOW= "\033[93m"; BLUE  = "\033[94m"
RESET = "\033[0m";  BOLD  = "\033[1m"

CITIZENS = [
    {"aadhaar": "234567890123", "name": "Ramesh Kumar"},
    {"aadhaar": "345678901234", "name": "Priya Sharma"},
    {"aadhaar": "456789012345", "name": "Suresh Patel"},
]
DOC_TYPES = ["income_certificate","caste_certificate",
             "residence_certificate","medical_certificate"]

def sep(title):
    print(f"\n{BOLD}{BLUE}{'═'*55}{RESET}")
    print(f"{BOLD}{BLUE}  {title}{RESET}")
    print(f"{BOLD}{BLUE}{'═'*55}{RESET}\n")

def show(label, r):
    d = r.json()
    c = GREEN if r.status_code < 400 else RED
    print(f"  {c}[{r.status_code}]{RESET} {label}")
    msg = d.get('message') or d.get('status','')
    if msg: print(f"       ↳ {msg}")
    return d

# ── Scenario 1: Citizen requests and downloads documents ───────────────
def scenario_legit():
    sep("SCENARIO 1 — Citizen Requests Documents")
    citizen = CITIZENS[0]
    print(f"  Citizen: {citizen['name']} ({citizen['aadhaar'][:4]}XXXXXXXX)\n")

    r = requests.post(f"{BASE}/auth/request-otp",
                      json={"aadhaar_no": citizen["aadhaar"]})
    d = show("Request OTP", r)
    otp = d.get("_demo_otp")
    time.sleep(0.5)

    r = requests.post(f"{BASE}/auth/verify-otp",
                      json={"aadhaar_no": citizen["aadhaar"], "otp": otp})
    show("Verify OTP", r)
    time.sleep(0.5)

    issued_docs = []
    for doc_type in ["income_certificate", "caste_certificate"]:
        print(f"\n  Requesting: {doc_type}")
        r = requests.post(f"{BASE}/document/request",
                          json={"aadhaar_no": citizen["aadhaar"], "doc_type": doc_type})
        d = show(f"Issue {doc_type}", r)
        if d.get("doc_id"):
            issued_docs.append(d["doc_id"])
            print(f"       ↳ Doc ID: {d['doc_id']}")
            print(f"       ↳ {GREEN}Blockchain Hash: {d.get('block_hash')}{RESET}")
        time.sleep(0.4)

    if issued_docs:
        print(f"\n  Downloading document {issued_docs[0]}...")
        r = requests.get(f"{BASE}/document/download/{issued_docs[0]}")
        d = show("Download document", r)
        if d.get("content"):
            print(f"       ↳ Content preview: {d['content'][:80]}...")
    return issued_docs

# ── Scenario 2: Institution verifies a document ────────────────────────
def scenario_verify(doc_ids=None):
    sep("SCENARIO 2 — Institution Verifies Document")
    if not doc_ids:
        issued = scenario_legit()
        doc_ids = issued

    if not doc_ids:
        print(f"  {RED}No documents to verify{RESET}")
        return

    doc_id = doc_ids[0]
    print(f"\n  Bank verifying document: {doc_id}\n")
    r = requests.post(f"{BASE}/verify",
                      json={"doc_id": doc_id,
                            "verifier_name": "State Bank of India",
                            "verifier_type": "bank"})
    d = show("SBI verifies income certificate", r)
    if d.get("status") == "GENUINE":
        print(f"       ↳ {GREEN}Document is GENUINE — bank can proceed with loan{RESET}")
    time.sleep(0.5)

    print(f"\n  University verifying same document...")
    r = requests.post(f"{BASE}/verify",
                      json={"doc_id": doc_id,
                            "verifier_name": "Anna University",
                            "verifier_type": "university"})
    show("Anna University verifies certificate", r)

# ── Scenario 3: Bulk harvesting attempt ───────────────────────────────
def scenario_bulk():
    sep("SCENARIO 3 — Bulk Document Harvesting Attempt")
    print(f"  {YELLOW}A data broker pretending to be a bank tries to verify")
    print(f"  hundreds of documents in rapid succession{RESET}\n")

    # first get some real doc IDs
    print("  First creating some documents to harvest...")
    doc_ids = []
    for c in CITIZENS:
        r = requests.post(f"{BASE}/document/request",
                          json={"aadhaar_no": c["aadhaar"],
                                "doc_type": random.choice(DOC_TYPES)})
        d = r.json()
        if d.get("doc_id"):
            doc_ids.append(d["doc_id"])
    time.sleep(0.5)

    print(f"\n  {RED}Now bulk harvesting — sending rapid verification requests...{RESET}\n")
    for i in range(25):
        doc_id = doc_ids[i % len(doc_ids)] if doc_ids else "FAKEID"
        r = requests.post(f"{BASE}/verify",
                          json={"doc_id": doc_id,
                                "verifier_name": "DataBroker_Corp",
                                "verifier_type": "unknown"},
                          headers={"User-Agent": "python-requests/2.31.0"})
        d = r.json()
        status = d.get("status","")
        color  = RED if status == "blocked" else GREEN
        print(f"  {color}[{r.status_code}]{RESET} Attempt #{i+1}: {status} — {d.get('message','')[:60]}")
        if status == "blocked":
            print(f"\n  {RED}CAUGHT — Bulk harvesting detected and blocked at attempt #{i+1}{RESET}")
            print(f"  {GREEN}Behavioural analysis flagged unusual verification pattern{RESET}")
            break
        time.sleep(0.08)

# ── main ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="TrustChain Demo Simulator")
    parser.add_argument("--scenario",
                        choices=["all","legit","verify","bulk"],
                        default="all")
    args = parser.parse_args()

    print(f"\n{BOLD}🔐 TrustChain Demo Simulator{RESET}")
    print(f"   Target: {BASE}\n")

    try:
        requests.get(f"{BASE}/admin/stats", timeout=2)
    except:
        print(f"{RED}Cannot reach server. Run: python backend/app.py first{RESET}\n")
        exit(1)

    issued = []
    if args.scenario in ("all","legit"):
        issued = scenario_legit()
        time.sleep(1)
    if args.scenario in ("all","verify"):
        scenario_verify(issued)
        time.sleep(1)
    if args.scenario in ("all","bulk"):
        scenario_bulk()

    print(f"\n{GREEN}{BOLD}✓ Simulation complete.{RESET}")
    print(f"  Citizen portal → http://localhost:5000")
    print(f"  Admin dashboard → http://localhost:5000/admin\n")
