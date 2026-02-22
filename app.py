print("TEST: app.py is running")
import sqlite3
import os
import base64
import json
import numpy as np
import cv2
from deepface import DeepFace

from flask import (
    Flask, render_template, request, redirect,
    url_for, flash, session, g
)
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import random
import csv
from io import StringIO

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "voting.db")

app = Flask(__name__)
app.secret_key = "change_this_to_a_random_secret_key"

# ----------------- DB HELPERS -----------------
def get_db():
    db = getattr(g, "_database", None)
    if db is None:
        db = g._database = sqlite3.connect(
            DB_PATH,
            detect_types=sqlite3.PARSE_DECLTYPES
        )
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, "_database", None)
    if db is not None:
        db.close()

def query_db(query, args=(), one=False):
    cur = get_db().execute(query, args)
    rows = cur.fetchall()
    cur.close()
    return (rows[0] if rows else None) if one else rows

def execute_db(query, args=()):
    db = get_db()
    cur = db.execute(query, args)
    db.commit()
    return cur.lastrowid

def init_db():
    with app.app_context():
        db = get_db()
        with open(os.path.join(BASE_DIR, "schema.sql"), "r") as f:
            db.executescript(f.read())
        db.commit()
    print("✅ Database initialized from schema.sql")

# ----------------- UTILS -----------------
def current_user():
    uid = session.get("user_id")
    if uid:
        return query_db("SELECT * FROM users WHERE id = ?", (uid,), one=True)
    return None

def send_otp_console(user_email, otp_code):
    print("\n============================")
    print(f" OTP for {user_email}: {otp_code}")
    print("============================\n")

def require_role(roles):
    user = current_user()
    if not user or user["role"] not in roles:
        flash("Access denied.")
        return None
    return user

def extract_face_embedding(image_bgr):
    """
    Returns face embedding list using DeepFace.
    """
    try:
        result = DeepFace.represent(
            img_path=image_bgr,
            model_name="Facenet",
            enforce_detection=False
        )
        return result[0]["embedding"]
    except Exception as e:
        print("FACE ERROR:", e)
        return None


def compare_embeddings(emb1, emb2, threshold=10.0):
    """
    Returns True if face matches.
    """
    emb1 = np.array(emb1, dtype="float32")
    emb2 = np.array(emb2, dtype="float32")
    dist = np.linalg.norm(emb1 - emb2)
    print("FACE DISTANCE:", dist)
    return dist < threshold

# ----------------- ROUTES -----------------

@app.route("/")
def index():
    user = current_user()
    elections = query_db("SELECT * FROM elections ORDER BY created_at DESC")
    return render_template("index.html", user=user, elections=elections)

# ---------- AUTH ----------
@app.route("/register", methods=["GET", "POST"])
def register():
    user = current_user()
    if request.method == "POST":
        name = request.form["name"].strip()
        email = request.form["email"].strip().lower()
        password = request.form["password"]

        if not (name and email and password):
            flash("Please fill all fields.")
            return redirect(url_for("register"))

        # check voter list
        allowed = query_db(
            "SELECT * FROM voter_list WHERE email = ? AND allowed = 1",
            (email,),
            one=True
        )
        if not allowed:
            flash("Your email is not in the approved voter list. Contact admin.")
            return redirect(url_for("register"))

        existing = query_db("SELECT * FROM users WHERE email = ?", (email,), one=True)
        if existing:
            flash("Email already registered.")
            return redirect(url_for("register"))

        pw_hash = generate_password_hash(password)
        execute_db(
            "INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)",
            (name, email, pw_hash)
        )
        flash("Registered successfully. Please login.")
        return redirect(url_for("login"))

    return render_template("register.html", user=user)

@app.route("/login", methods=["GET", "POST"])
def login():
    user = current_user()
    if request.method == "POST":
        email = request.form["email"].strip().lower()
        password = request.form["password"]

        user_row = query_db("SELECT * FROM users WHERE email = ?", (email,), one=True)
        if user_row and check_password_hash(user_row["password_hash"], password):
            session["user_id"] = user_row["id"]
            flash("Logged in successfully.")
            return redirect(url_for("index"))
        else:
            flash("Invalid email or password.")

    return render_template("login.html", user=user)

@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out.")
    return redirect(url_for("index"))

# ---------- ADMIN / OFFICER ----------

@app.route("/admin")
def admin():
    user = require_role(("admin", "officer"))
    if not user:
        return redirect(url_for("login"))

    # 🔹 IMPORTANT FIX: include NULL as public (old elections)
    public_elections = query_db(
        "SELECT * FROM elections WHERE election_type='public' OR election_type IS NULL ORDER BY created_at DESC"
    )

    government_elections = query_db(
        "SELECT * FROM elections WHERE election_type='government' ORDER BY created_at DESC"
    )

    return render_template(
        "admin.html",
        user=user,
        public_elections=public_elections,
        government_elections=government_elections
    )


@app.route("/admin/create_election", methods=["GET", "POST"])
def create_election():
    user = require_role(("admin", "officer"))
    if not user:
        return redirect(url_for("login"))

    if request.method == "POST":
        title = request.form["title"].strip()
        description = request.form.get("description", "").strip()
        election_type = request.form.get("election_type", "public")

        if not title:
            flash("Title is required.")
            return redirect(url_for("create_election"))

        execute_db(
            "INSERT INTO elections (title, description, election_type) VALUES (?, ?, ?)",
            (title, description, election_type)
        )

        flash("Election created successfully.")
        return redirect(url_for("admin"))

    return render_template("create_election.html", user=user)


@app.route("/admin/<int:election_id>/add_candidate", methods=["GET", "POST"])
def add_candidate(election_id):
    user = require_role(("admin", "officer"))
    if not user:
        return redirect(url_for("login"))

    election = query_db(
        "SELECT * FROM elections WHERE id = ?",
        (election_id,),
        one=True
    )
    if not election:
        flash("Election not found.")
        return redirect(url_for("admin"))

    if request.method == "POST":
        name = request.form["name"].strip()
        description = request.form.get("description", "").strip()
        department = request.form.get("department", "").strip()
        year = request.form.get("year", "").strip()
        manifesto = request.form.get("manifesto", "").strip()
        photo_url = request.form.get("photo_url", "").strip()

        if not name:
            flash("Candidate name is required.")
            return redirect(url_for("add_candidate", election_id=election_id))

        execute_db(
            """INSERT INTO candidates
               (election_id, name, description, department, year, manifesto, photo_url)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (election_id, name, description, department, year, manifesto, photo_url)
        )

        flash("Candidate added.")
        return redirect(url_for("admin"))

    return render_template("add_candidate.html", user=user, election=election)


# 🆕 DELETE ELECTION (ADMIN ONLY)
@app.route("/admin/<int:election_id>/delete")
def delete_election(election_id):
    user = require_role(("admin",))
    if not user:
        return redirect(url_for("login"))

    execute_db("DELETE FROM votes WHERE election_id=?", (election_id,))
    execute_db("DELETE FROM candidates WHERE election_id=?", (election_id,))
    execute_db("DELETE FROM elections WHERE id=?", (election_id,))

    flash("Election deleted successfully.")
    return redirect(url_for("admin"))


@app.route("/admin/<int:election_id>/results")
def view_results(election_id):
    user = require_role(("admin", "officer"))
    if not user:
        return redirect(url_for("login"))

    election = query_db(
        "SELECT * FROM elections WHERE id = ?",
        (election_id,),
        one=True
    )
    if not election:
        flash("Election not found.")
        return redirect(url_for("admin"))

    candidates = query_db(
        "SELECT * FROM candidates WHERE election_id = ? ORDER BY votes DESC",
        (election_id,)
    )

    return render_template(
        "results.html",
        user=user,
        election=election,
        candidates=candidates
    )


@app.route("/admin/<int:election_id>/export_summary")
def export_summary(election_id):
    user = require_role(("admin", "officer"))
    if not user:
        return redirect(url_for("login"))

    candidates = query_db(
        "SELECT name, votes FROM candidates WHERE election_id = ?",
        (election_id,)
    )

    si = StringIO()
    cw = csv.writer(si)
    cw.writerow(["Candidate", "Votes"])

    for c in candidates:
        cw.writerow([c["name"], c["votes"]])

    return (
        si.getvalue(),
        200,
        {
            "Content-Type": "text/csv",
            "Content-Disposition": f"attachment; filename=election_{election_id}_summary.csv"
        }
    )


@app.route("/admin/<int:election_id>/export_votes")
def export_votes(election_id):
    user = require_role(("admin", "officer"))
    if not user:
        return redirect(url_for("login"))

    rows = query_db(
        """SELECT u.name, u.email, c.name AS candidate, v.voted_at
           FROM votes v
           JOIN users u ON v.user_id = u.id
           JOIN candidates c ON v.candidate_id = c.id
           WHERE v.election_id = ?""",
        (election_id,)
    )

    si = StringIO()
    cw = csv.writer(si)
    cw.writerow(["Voter Name", "Email", "Candidate", "Voted At"])

    for r in rows:
        cw.writerow([r["name"], r["email"], r["candidate"], r["voted_at"]])

    return (
        si.getvalue(),
        200,
        {
            "Content-Type": "text/csv",
            "Content-Disposition": f"attachment; filename=election_{election_id}_votes.csv"
        }
    )


@app.route("/admin/voters/upload", methods=["GET", "POST"], endpoint="upload_voter_list")
def upload_voter_list():
    user = require_role(("admin",))
    if not user:
        return redirect(url_for("login"))

    if request.method == "POST":
        file = request.files.get("file")

        if not file or file.filename == "":
            flash("Please select a CSV file.")
            return redirect(url_for("upload_voter_list"))

        try:
            # ✅ FIX 1: handle Excel CSV (utf-8-sig)
            content = file.stream.read().decode("utf-8-sig")
            reader = csv.DictReader(StringIO(content))

            # ✅ FIX 2: validate headers
            required_headers = {"name", "email", "roll_no"}
            if not reader.fieldnames or not required_headers.issubset(reader.fieldnames):
                flash("Invalid CSV headers. Required: name,email,roll_no")
                return redirect(url_for("upload_voter_list"))

            count = 0
            for row in reader:
                name = (row.get("name") or "").strip()
                email = (row.get("email") or "").strip().lower()
                roll_no = (row.get("roll_no") or "").strip()

                if not email:
                    continue

                # ✅ FIX 3: avoid duplicate email crash
                execute_db(
                    """
                    INSERT OR IGNORE INTO voter_list (name, email, roll_no, allowed)
                    VALUES (?, ?, ?, 1)
                    """,
                    (name, email, roll_no)
                )
                count += 1

            flash(f"✅ {count} voters uploaded successfully.")
            return redirect(url_for("admin"))

        except Exception as e:
            print("CSV ERROR:", e)
            flash("Invalid CSV file format.")
            return redirect(url_for("upload_voter_list"))

    return render_template("upload_voters.html", user=user)

# ---------- OTP & VOTING ----------
@app.route("/vote/<int:election_id>/request_otp", methods=["GET", "POST"])
def request_otp(election_id):
    user = require_role(("voter",))
    if not user:
        return redirect(url_for("login"))

    # generate OTP
    otp = str(random.randint(100000, 999999))
    expires_at = datetime.now() + timedelta(minutes=5)

    execute_db(
        "INSERT INTO otps (user_id, election_id, otp_code, expires_at) VALUES (?, ?, ?, ?)",
        (user["id"], election_id, otp, expires_at)
    )

    flash(f"OTP generated: {otp} (demo purpose)")
    return redirect(url_for("verify_otp_page", election_id=election_id))

@app.route("/vote/<int:election_id>/verify", methods=["GET", "POST"])
def verify_otp_page(election_id):
    user = require_role(("voter",))
    if not user:
        return redirect(url_for("login"))

    if request.method == "POST":
        otp_submitted = request.form["otp"].strip()

        otp_row = query_db(
            """
            SELECT * FROM otps
            WHERE user_id = ? AND election_id = ? AND used = 0
            ORDER BY created_at DESC
            """,
            (user["id"], election_id),
            one=True
        )

        if not otp_row:
            flash("OTP not found or already used.")
            return redirect(url_for("index"))

        expires_at = datetime.fromisoformat(otp_row["expires_at"])
        if datetime.now() > expires_at:
            flash("OTP expired. Please request a new OTP.")
            return redirect(url_for("index"))

        if otp_submitted != otp_row["otp_code"]:
            flash("Invalid OTP.")
            return redirect(url_for("verify_otp_page", election_id=election_id))



        execute_db(
            "UPDATE otps SET used = 1 WHERE id = ?",
            (otp_row["id"],)
        )

        session[f"otp_valid_election_{election_id}"] = True
        flash("OTP verified successfully.")
        return redirect(url_for("face_scan", election_id=election_id))


    return render_template(
        "verify_otp.html",
        user=user,
        election_id=election_id
    )

@app.route("/vote/<int:election_id>/cast", methods=["GET", "POST"])
def cast_vote(election_id):
    user = require_role(("voter",))
    if not user:
        return redirect(url_for("login"))

    if not session.get(f"otp_valid_election_{election_id}"):
        flash("OTP verification required before voting.")
        return redirect(url_for("index"))
    if not session.get(f"face_verified_election_{election_id}"):
        flash("Face scan required before voting.")
        return redirect(url_for("face_scan", election_id=election_id))


    election = query_db(
        "SELECT * FROM elections WHERE id = ?",
        (election_id,),
        one=True
    )
    if not election:
        flash("Election not found.")
        return redirect(url_for("index"))

    if request.method == "POST":
        candidate_id = int(request.form["candidate_id"])

        already_voted = query_db(
            "SELECT * FROM votes WHERE user_id = ? AND election_id = ?",
            (user["id"], election_id),
            one=True
        )
        if already_voted:
            flash("You have already voted.")
            return redirect(url_for("index"))

        execute_db(
            "INSERT INTO votes (user_id, election_id, candidate_id) VALUES (?, ?, ?)",
            (user["id"], election_id, candidate_id)
        )

        execute_db(
            "UPDATE candidates SET votes = votes + 1 WHERE id = ?",
            (candidate_id,)
        )

        session.pop(f"otp_valid_election_{election_id}", None)
        session.pop(f"face_verified_election_{election_id}", None)
        flash("Your vote has been recorded successfully.")
        return redirect(url_for("index"))

        
    candidates = query_db(
        "SELECT * FROM candidates WHERE election_id = ?",
        (election_id,)
    )

    return render_template(
        "cast_vote.html",
        user=user,
        election=election,
        candidates=candidates
    )
@app.route("/vote/<int:election_id>/face_scan", methods=["GET", "POST"])
def face_scan(election_id):
    user = require_role(("voter",))
    if not user:
        return redirect(url_for("login"))

    # OTP must be verified
    if not session.get(f"otp_valid_election_{election_id}"):
        flash("OTP verification required before face scan.")
        return redirect(url_for("index"))

    if request.method == "POST":
        image_data = request.form.get("image_data")

        if not image_data:
            flash("Face image not captured.")
            return redirect(url_for("face_scan", election_id=election_id))

        # Decode base64 image
        header, encoded = image_data.split(",", 1)
        img_bytes = base64.b64decode(encoded)

        np_arr = np.frombuffer(img_bytes, np.uint8)
        img_bgr = cv2.imdecode(np_arr, cv2.IMREAD_COLOR)

        if img_bgr is None:
            flash("Invalid image data.")
            return redirect(url_for("face_scan", election_id=election_id))

        embedding = extract_face_embedding(img_bgr)

        if not embedding:
            flash("No face detected. Try again clearly.")
            return redirect(url_for("face_scan", election_id=election_id))

        # Check if user already has face stored
        face_row = query_db(
            "SELECT * FROM face_data WHERE user_id=?",
            (user["id"],),
            one=True
        )

        if not face_row:
            # Check if this face already belongs to another user
            all_faces = query_db("SELECT * FROM face_data")

            for f in all_faces:
                stored_embedding = json.loads(f["face_embedding"])
                if compare_embeddings(embedding, stored_embedding):
                    flash("❌ Face already registered with another voter. Vote blocked.")
                    return redirect(url_for("index"))

            # Save face for this user
            execute_db(
                "INSERT INTO face_data (user_id, face_embedding) VALUES (?, ?)",
                (user["id"], json.dumps(embedding))
            )
            flash("✅ Face registered successfully.")
        else:
            stored_embedding = json.loads(face_row["face_embedding"])
            if not compare_embeddings(embedding, stored_embedding):
                flash("❌ Face mismatch. Voting blocked.")
                return redirect(url_for("index"))

            flash("✅ Face verified successfully.")

        # Allow voting
        session[f"face_verified_election_{election_id}"] = True
        return redirect(url_for("cast_vote", election_id=election_id))

    return render_template("face_scan.html", user=user, election_id=election_id)

def create_default_admin():
    admin_email = "admin@gmail.com"
    admin_password = "admin123"

    existing = query_db(
        "SELECT * FROM users WHERE email = ?",
        (admin_email,),
        one=True
    )

    if not existing:
        pw_hash = generate_password_hash(admin_password)
        execute_db(
            "INSERT INTO users (name, email, password_hash, role) VALUES (?, ?, ?, 'admin')",
            ("Admin", admin_email, pw_hash)
        )
        print("✅ Default admin created: admin@gmail.com / admin123")

# ----------------- MAIN -----------------
if __name__ == "__main__":
    print("Starting Flask app...")

    if not os.path.exists(DB_PATH):
        print("⚠️  Database not found. Initializing...")
        init_db()

    # ✅ Always ensure admin exists
    with app.app_context():
        create_default_admin()

    app.run(debug=True)
