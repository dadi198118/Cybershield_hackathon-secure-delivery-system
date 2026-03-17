"""
database_setup.py
Creates the TrustChain SQLite database with:
  - citizens table
  - documents table
  - verifications table
  - departments table
"""

import sqlite3
import hashlib
import os
from datetime import datetime

DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "data")
DB_PATH  = os.path.join(DATA_DIR, "trustchain.db")
os.makedirs(DATA_DIR, exist_ok=True)

def hash_secret(value):
    return hashlib.sha256(value.encode()).hexdigest()

def setup():
    conn = sqlite3.connect(DB_PATH)
    cur  = conn.cursor()

    # ── Citizens ──────────────────────────────────────────────────────
    cur.execute("""
    CREATE TABLE IF NOT EXISTS citizens (
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        aadhaar_no   TEXT UNIQUE NOT NULL,
        full_name    TEXT NOT NULL,
        dob          TEXT NOT NULL,
        gender       TEXT NOT NULL,
        phone        TEXT NOT NULL,
        email        TEXT,
        address      TEXT NOT NULL,
        state        TEXT NOT NULL,
        pincode      TEXT NOT NULL,
        otp_secret   TEXT NOT NULL
    )""")

    # ── Departments ───────────────────────────────────────────────────
    cur.execute("""
    CREATE TABLE IF NOT EXISTS departments (
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        dept_id      TEXT UNIQUE NOT NULL,
        name         TEXT NOT NULL,
        type         TEXT NOT NULL
    )""")

    # ── Documents ─────────────────────────────────────────────────────
    cur.execute("""
    CREATE TABLE IF NOT EXISTS documents (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        doc_id          TEXT UNIQUE NOT NULL,
        aadhaar_no      TEXT NOT NULL,
        doc_type        TEXT NOT NULL,
        issued_by       TEXT NOT NULL,
        issued_on       TEXT NOT NULL,
        content         TEXT NOT NULL,
        doc_hash        TEXT NOT NULL,
        block_hash      TEXT,
        status          TEXT DEFAULT 'active'
    )""")

    # ── Verifications ─────────────────────────────────────────────────
    cur.execute("""
    CREATE TABLE IF NOT EXISTS verifications (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        doc_id          TEXT NOT NULL,
        verifier_name   TEXT NOT NULL,
        verifier_type   TEXT NOT NULL,
        verified_on     TEXT NOT NULL,
        result          TEXT NOT NULL,
        ip              TEXT
    )""")

    conn.commit()

    # ── Seed departments ──────────────────────────────────────────────
    departments = [
        ("DEPT001", "Revenue Department",         "revenue"),
        ("DEPT002", "Education Board",            "education"),
        ("DEPT003", "Health Department",          "health"),
        ("DEPT004", "Transport Department",       "transport"),
        ("DEPT005", "Municipal Corporation",      "municipal"),
    ]
    for d in departments:
        try:
            cur.execute("INSERT INTO departments (dept_id,name,type) VALUES (?,?,?)", d)
        except sqlite3.IntegrityError:
            pass

    # ── Seed citizens ─────────────────────────────────────────────────
    citizens = [
        ("234567890123", "Ramesh Kumar",   "1985-04-12", "M", "9876543210", "ramesh@gmail.com",  "12 MG Road, Bengaluru",    "Karnataka",   "560001"),
        ("345678901234", "Priya Sharma",   "2002-07-22", "F", "9812345678", "priya@yahoo.com",    "45 Anna Nagar, Chennai",   "Tamil Nadu",  "600040"),
        ("456789012345", "Suresh Patel",   "1979-11-03", "M", "9988776655", "suresh@gmail.com",   "78 Ring Road, Ahmedabad",  "Gujarat",     "380001"),
        ("567890123456", "Meena Devi",     "1955-01-18", "F", "9765432109", None,                 "23 Civil Lines, Patna",    "Bihar",       "800001"),
        ("678901234567", "Arjun Singh",    "2001-09-30", "M", "9654321098", "arjun@gmail.com",    "56 Sector 21, Noida",      "UP",          "201301"),
    ]
    for c in citizens:
        aadhaar, name, dob, gender, phone, email, address, state, pincode = c
        try:
            cur.execute("""
                INSERT INTO citizens
                  (aadhaar_no,full_name,dob,gender,phone,email,address,state,pincode,otp_secret)
                VALUES (?,?,?,?,?,?,?,?,?,?)
            """, (aadhaar, name, dob, gender, phone, email, address, state, pincode,
                  hash_secret(aadhaar + "OTP_SALT_2024")))
        except sqlite3.IntegrityError:
            pass

    conn.commit()
    conn.close()
    print(f"[✓] TrustChain DB created → {DB_PATH}")

if __name__ == "__main__":
    setup()
