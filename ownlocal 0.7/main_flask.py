# ============================================================
# OwnLocal Backend — main_flask.py
# Flask + SQLite — Merchant Authentication System
# Run: python main_flask.py
# Docs: http://localhost:5000
# ============================================================

import sqlite3
import os
import hashlib
from flask import Flask, request, jsonify
from flask_cors import CORS

# ─────────────────────────────────────────────────────────────
# APP SETUP
# ─────────────────────────────────────────────────────────────
app = Flask(__name__)
CORS(app)  # Allow frontend to talk to backend (no browser CORS block)

# Database lives in same folder as this script
# Store DB in user-writable directory
BASE_DIR = os.path.join(os.path.expanduser("~"), "ownlocal_data")

# Create folder if it doesn't exist
if not os.path.exists(BASE_DIR):
    os.makedirs(BASE_DIR)

DB_PATH = os.path.join(BASE_DIR, "ownlocal.db")

print(f"📁 Database path: {DB_PATH}")

# ─────────────────────────────────────────────────────────────
# UTILITY: password hashing
# ─────────────────────────────────────────────────────────────
def hash_password(password: str) -> str:
    """SHA-256 hash a password for safe storage. Never store plain text."""
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


# ─────────────────────────────────────────────────────────────
# DATABASE HELPER
# ─────────────────────────────────────────────────────────────
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row  # lets us access columns by name
    return conn


# ─────────────────────────────────────────────────────────────
# CREATE TABLES ON STARTUP
# ─────────────────────────────────────────────────────────────
def create_tables():
    conn = get_db()
    c = conn.cursor()

    # merchant table — the only table we need for auth
    c.execute("""
        CREATE TABLE IF NOT EXISTS merchant (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            shop_name       TEXT    NOT NULL UNIQUE,
            owner_name      TEXT    NOT NULL DEFAULT '',
            password        TEXT    NOT NULL,
            category        TEXT    NOT NULL DEFAULT 'Other',
            pincode         TEXT    NOT NULL DEFAULT '',
            gstin           TEXT    NOT NULL DEFAULT '',
            email           TEXT    NOT NULL DEFAULT '',
            monthly_footfall INTEGER NOT NULL DEFAULT 0,
            joined_at       TEXT    NOT NULL DEFAULT (datetime('now'))
        )
    """)

    # waitlist table (for consumer side)
    c.execute("""
        CREATE TABLE IF NOT EXISTS waitlist (
            id      INTEGER PRIMARY KEY AUTOINCREMENT,
            email   TEXT NOT NULL UNIQUE,
            pincode TEXT NOT NULL DEFAULT ''
        )
    """)

    conn.commit()
    conn.close()
    print("✅ Tables ready.")


# ─────────────────────────────────────────────────────────────
# ENDPOINTS
# ─────────────────────────────────────────────────────────────

@app.route("/")
def root():
    return jsonify({"message": "OwnLocal Flask API running!", "version": "1.0.0"})


# ── SIGNUP ──────────────────────────────────────────────────
@app.route("/signup", methods=["POST"])
def signup():
    """
    Merchant sign-up.

    Flow:
      1. Frontend POSTs JSON with all form fields.
      2. We validate required fields.
      3. We hash the password.
      4. We INSERT into `merchant` table.
      5. We return success — frontend redirects to dashboard.

    Returns 400 if shop_name already exists or fields are missing.
    """
    data = request.get_json(force=True)

    shop_name        = (data.get("shop_name") or "").strip()
    owner_name       = (data.get("owner_name") or "").strip()
    password         = (data.get("password") or "").strip()
    category         = (data.get("category") or "Other").strip()
    pincode          = (data.get("pincode") or "").strip()
    gstin            = (data.get("gstin") or "").strip().upper()
    email            = (data.get("email") or "").strip()
    monthly_footfall = int(data.get("monthly_footfall") or data.get("footfall") or 0)

    # — Validation —
    if not shop_name:
        return jsonify({"detail": "Shop name is required."}), 400
    if not password:
        return jsonify({"detail": "Password is required."}), 400
    if len(password) < 6:
        return jsonify({"detail": "Password must be at least 6 characters."}), 400

    conn = get_db()
    try:
        # Check for duplicate shop name
        existing = conn.execute(
            "SELECT id FROM merchant WHERE shop_name = ?", (shop_name,)
        ).fetchone()
        if existing:
            return jsonify({"detail": "A merchant with this shop name already exists."}), 400

        # Hash password before storing — NEVER store plain text
        hashed_pw = hash_password(password)

        conn.execute(
            """INSERT INTO merchant
               (shop_name, owner_name, password, category, pincode, gstin, email, monthly_footfall)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (shop_name, owner_name, hashed_pw, category, pincode, gstin, email, monthly_footfall)
        )
        conn.commit()
    finally:
        conn.close()

    return jsonify({
        "success":   True,
        "message":   f"Welcome to OwnLocal, {shop_name}! 🏪",
        "shop_name": shop_name
    })


# Alias kept for compatibility with existing FastAPI frontend code
@app.route("/merchants", methods=["POST"])
def merchants_post():
    return signup()


# ── LOGIN ────────────────────────────────────────────────────
@app.route("/login", methods=["POST"])
def login():
    """
    Merchant login.

    Flow:
      1. Frontend POSTs { shop_name, password }.
      2. We hash the incoming password and compare to DB hash.
      3. If match → return success + profile; frontend stores name in localStorage.
      4. If no match → return 401 with error message.

    STRICT RULE: Only merchants already in the DB can log in.
    No mock data, no bypass.
    """
    data = request.get_json(force=True)

    shop_name = (data.get("shop_name") or "").strip()
    password  = (data.get("password") or "").strip()

    if not shop_name or not password:
        return jsonify({"detail": "Shop name and password are required."}), 400

    hashed_pw = hash_password(password)

    conn = get_db()
    try:
        merchant = conn.execute(
            """SELECT id, shop_name, owner_name, category, pincode, email, monthly_footfall, joined_at
               FROM merchant
               WHERE shop_name = ? AND password = ?""",
            (shop_name, hashed_pw)
        ).fetchone()
    finally:
        conn.close()

    if not merchant:
        return jsonify({"detail": "Invalid shop name or password."}), 401

    return jsonify({
        "success":   True,
        "message":   f"Welcome back, {shop_name}! 🏪",
        "shop_name": merchant["shop_name"],
        "profile": {
            "id":               merchant["id"],
            "shop_name":        merchant["shop_name"],
            "owner_name":       merchant["owner_name"],
            "category":         merchant["category"],
            "pincode":          merchant["pincode"],
            "email":            merchant["email"],
            "monthly_footfall": merchant["monthly_footfall"],
            "joined_at":        merchant["joined_at"]
        }
    })


# Alias kept for compatibility with existing frontend code
@app.route("/merchant-login", methods=["POST"])
def merchant_login():
    return login()


# ── MERCHANT PROFILE ─────────────────────────────────────────
@app.route("/merchant-profile", methods=["GET"])
def merchant_profile():
    """Returns public profile for the merchant dashboard (no password returned)."""
    shop_name = request.args.get("shop_name", "").strip()
    if not shop_name:
        return jsonify({"detail": "shop_name query param is required."}), 400

    conn = get_db()
    try:
        row = conn.execute(
            """SELECT id, shop_name, owner_name, category, pincode, email, monthly_footfall, joined_at
               FROM merchant WHERE shop_name = ?""",
            (shop_name,)
        ).fetchone()
    finally:
        conn.close()

    if not row:
        return jsonify({"detail": "Merchant not found."}), 404

    return jsonify(dict(row))


# ── LIST ALL MERCHANTS (admin view) ──────────────────────────
@app.route("/merchants", methods=["GET"])
def get_merchants():
    conn = get_db()
    try:
        rows = conn.execute(
            "SELECT id, shop_name, owner_name, category, pincode, email, monthly_footfall, joined_at FROM merchant ORDER BY joined_at DESC"
        ).fetchall()
    finally:
        conn.close()
    return jsonify({"count": len(rows), "merchants": [dict(r) for r in rows]})


# ── WAITLIST ─────────────────────────────────────────────────
@app.route("/waitlist", methods=["POST"])
def post_waitlist():
    data    = request.get_json(force=True)
    email   = (data.get("email") or "").strip()
    pincode = (data.get("pincode") or "").strip()

    if not email or "@" not in email:
        return jsonify({"detail": "Invalid email address."}), 400

    conn = get_db()
    try:
        existing = conn.execute("SELECT id FROM waitlist WHERE email = ?", (email,)).fetchone()
        if existing:
            return jsonify({"success": True, "message": "You're already on the list! 💖"})
        conn.execute("INSERT INTO waitlist (email, pincode) VALUES (?, ?)", (email, pincode))
        conn.commit()
    finally:
        conn.close()

    return jsonify({"success": True, "message": "You're on the waitlist! 💖"})


@app.route("/waitlist", methods=["GET"])
def get_waitlist():
    conn = get_db()
    try:
        rows = conn.execute("SELECT * FROM waitlist").fetchall()
    finally:
        conn.close()
    return jsonify({"count": len(rows), "waitlist": [dict(r) for r in rows]})


# ── TRANSACTION (equity calculation) ─────────────────────────
@app.route("/transaction", methods=["POST"])
def post_transaction():
    data  = request.get_json(force=True)
    total = float(data.get("total") or 0)
    if total <= 0:
        return jsonify({"detail": "Amount must be > 0"}), 400
    tokens_earned = round(total / 10)
    equity_earned = round(total * 0.02, 2)
    return jsonify({
        "tokensEarned":  tokens_earned,
        "equityEarned":  equity_earned,
        "message":       f"Transaction successful! You earned {tokens_earned} tokens 💖",
        "total_spend":   total,
        "total_equity":  equity_earned,
        "tokens_earned": tokens_earned,
        "equity_earned": equity_earned,
    })


# ── PORTFOLIO ────────────────────────────────────────────────
@app.route("/portfolio", methods=["GET"])
def get_portfolio():
    return jsonify({"total_spend": 0, "total_equity": 0, "total_tokens": 0})


# ─────────────────────────────────────────────────────────────
# STARTUP + RUN
# ─────────────────────────────────────────────────────────────
if __name__ == "__main__":
    create_tables()
    print("🚀 OwnLocal Flask API starting on http://localhost:5000")
    print("📖 Endpoints: /signup (POST) · /login (POST) · /merchant-profile (GET)")
    app.run(debug=True, port=5000)
