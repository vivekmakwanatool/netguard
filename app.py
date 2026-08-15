import os
import json
import sqlite3
import threading
import time
import uuid
from datetime import datetime

from flask import (Flask, render_template, request, redirect, url_for,
                   session, jsonify, flash, g)
from werkzeug.security import generate_password_hash, check_password_hash

from scanner.port_scanner import scan_host, parse_port_range
from scanner.vuln_scanner import evaluate_open_ports
from scanner.web_checks import run_web_checks

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "netguard.db")

app = Flask(__name__)
app.secret_key = os.environ.get("NETGUARD_SECRET_KEY", os.urandom(24).hex())
SCAN_PROGRESS = {}


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exception=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    first_run = not os.path.exists(DB_PATH)
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            target TEXT NOT NULL,
            scan_type TEXT NOT NULL,
            status TEXT NOT NULL,
            started_at TEXT NOT NULL,
            finished_at TEXT,
            summary_json TEXT,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    """)
    conn.commit()
    if first_run:
        default_user = "admin"
        default_pass = "changeme123"
        conn.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            (default_user, generate_password_hash(default_pass)),
        )
        conn.commit()
        print("=" * 60)
        print(" NetGuard: first run — created default login")
        print(f"   username: {default_user}")
        print(f"   password: {default_pass}")
        print(" Change this immediately after logging in (see README).")
        print("=" * 60)
    conn.close()


def login_required(view):
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    wrapped.__name__ = view.__name__
    return wrapped


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        db = get_db()
        user = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        if user and check_password_hash(user["password_hash"], password):
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            return redirect(url_for("dashboard"))
        flash("Invalid username or password.")
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/change-password", methods=["POST"])
@login_required
def change_password():
    new_pw = request.form.get("new_password", "")
    if len(new_pw) < 8:
        flash("Password must be at least 8 characters.")
        return redirect(url_for("dashboard"))
    db = get_db()
    db.execute("UPDATE users SET password_hash = ? WHERE id = ?",
               (generate_password_hash(new_pw), session["user_id"]))
    db.commit()
    flash("Password updated.")
    return redirect(url_for("dashboard"))


@app.route("/")
@login_required
def dashboard():
    db = get_db()
    scans = db.execute(
        "SELECT * FROM scans WHERE user_id = ? ORDER BY started_at DESC LIMIT 25",
        (session["user_id"],),
    ).fetchall()
    return render_template("dashboard.html", scans=scans, username=session.get("username"))


@app.route("/results/<scan_id>")
@login_required
def results(scan_id):
    db = get_db()
    scan = db.execute(
        "SELECT * FROM scans WHERE id = ? AND user_id = ?",
        (scan_id, session["user_id"]),
    ).fetchone()
    if not scan:
        flash("Scan not found.")
        return redirect(url_for("dashboard"))
    summary = json.loads(scan["summary_json"]) if scan["summary_json"] else {}
    return render_template("results.html", scan=scan, summary=summary)


def _run_scan_background(scan_id, user_id, target, scan_type, port_spec):
    SCAN_PROGRESS[scan_id] = {"done": 0, "total": 1, "status": "running"}

    def progress_cb(done, total):
        SCAN_PROGRESS[scan_id] = {"done": done, "total": total, "status": "running"}

    summary = {"target": target, "scan_type": scan_type}
    try:
        if scan_type in ("port", "full"):
            ports = parse_port_range(port_spec or "1-1024")
            port_result = scan_host(target, ports, progress_callback=progress_cb)
            summary["port_scan"] = port_result
            if "error" not in port_result:
                open_ports = [r for r in port_result["results"] if r["state"] == "open"]
                summary["vuln_findings"] = evaluate_open_ports(open_ports)
        if scan_type in ("web", "full"):
            SCAN_PROGRESS[scan_id] = {"done": 0, "total": 1, "status": "running (web checks)"}
            summary["web_findings"] = run_web_checks(target)
        status = "completed"
    except Exception as e:
        summary["error"] = str(e)
        status = "failed"

    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "UPDATE scans SET status = ?, finished_at = ?, summary_json = ? WHERE id = ?",
        (status, datetime.utcnow().isoformat(), json.dumps(summary), scan_id),
    )
    conn.commit()
    conn.close()
    SCAN_PROGRESS[scan_id] = {
        "done": SCAN_PROGRESS.get(scan_id, {}).get("total", 1),
        "total": SCAN_PROGRESS.get(scan_id, {}).get("total", 1),
        "status": status,
    }


@app.route("/scan", methods=["POST"])
@login_required
def start_scan():
    target = request.form.get("target", "").strip()
    scan_type = request.form.get("scan_type", "port")
    port_spec = request.form.get("port_spec", "1-1024").strip()
    authorized = request.form.get("authorized")
    if not target:
        flash("Please enter a target host or URL.")
        return redirect(url_for("dashboard"))
    if not authorized:
        flash("You must confirm you are authorized to scan this target.")
        return redirect(url_for("dashboard"))
    clean_target = target.replace("https://", "").replace("http://", "").split("/")[0]
    scan_id = str(uuid.uuid4())
    db = get_db()
    db.execute(
        "INSERT INTO scans (id, user_id, target, scan_type, status, started_at) VALUES (?, ?, ?, ?, ?, ?)",
        (scan_id, session["user_id"], target, scan_type, "running", datetime.utcnow().isoformat()),
    )
    db.commit()
    thread = threading.Thread(
        target=_run_scan_background,
        args=(scan_id, session["user_id"], clean_target if scan_type == "port" else target, scan_type, port_spec),
        daemon=True,
    )
    thread.start()
    return redirect(url_for("scanning", scan_id=scan_id))


@app.route("/scanning/<scan_id>")
@login_required
def scanning(scan_id):
    db = get_db()
    scan = db.execute(
        "SELECT * FROM scans WHERE id = ? AND user_id = ?",
        (scan_id, session["user_id"]),
    ).fetchone()
    if not scan:
        return redirect(url_for("dashboard"))
    return render_template("scanning.html", scan=scan)


@app.route("/api/progress/<scan_id>")
@login_required
def api_progress(scan_id):
    prog = SCAN_PROGRESS.get(scan_id, {"done": 0, "total": 1, "status": "unknown"})
    return jsonify(prog)


if __name__ == "__main__":
    init_db()
    app.run(host="127.0.0.1", port=5050, debug=True)
