import os
import sys
import sqlite3
import subprocess
import re
from flask import Flask, render_template, request, redirect, session
from flask_cors import CORS
from datetime import datetime
import user_management as db
from flask_wtf.csrf import generate_csrf
from flask_wtf.csrf import CSRFProtect




# ── Auto-bootstrap the database on every startup ──────────────────────────────
# This ensures students never see "no such table" even if setup_db.py
# was never manually run, or if the .db file is missing / corrupted.
BASE_DIR     = os.path.dirname(os.path.abspath(__file__))
DB_PATH      = os.path.join(BASE_DIR, "database_files", "database.db")
SETUP_SCRIPT = os.path.join(BASE_DIR, "database_files", "setup_db.py")

def _tables_exist():
    """Return True if the required tables are all present."""
    try:
        con = sqlite3.connect(DB_PATH)
        cur = con.cursor()
        tables = {r[0] for r in cur.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()}
        con.close()
        return {"users", "posts", "messages"}.issubset(tables)
    except Exception:
        return False

def init_db():
    os.makedirs(os.path.join(BASE_DIR, "database_files"), exist_ok=True)
    if not os.path.exists(DB_PATH) or not _tables_exist():
        print("[SocialPWA] Setting up database...")
        result = subprocess.run(
            [sys.executable, SETUP_SCRIPT],
            capture_output=True, text=True
        )
        print(result.stdout)
        if result.returncode != 0:
            print("[SocialPWA] WARNING: setup_db failed:", result.stderr)
    else:
        print("[SocialPWA] Database already exists — skipping setup.")

def sanitize_plain_text(value, max_length=1000):
    if value is None:
        return ""
    if not isinstance(value, str):
        value = str(value)

    value = value.strip()
    if len(value) > max_length:
        value = value[:max_length]

    # Remove script blocks
    value = re.sub(r"(?is)<script.*?>.*?</script>", "", value)
    # Remove any remaining HTML tags
    value = re.sub(r"(?is)<.*?>", "", value)

    return value

init_db()

# ─────────────────────────────────────────────────────────────────────────────

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "supersecretkey123")
csrf = CSRFProtect(app)
app.jinja_env.globals["csrf_token"] = generate_csrf

# VULNERABILITY: Wildcard CORS — allows ANY origin to make credentialed requests
#testing 


CORS(app, origins=["http://localhost:5000", "http://localhost:3000"])


@app.after_request
def set_csp(response):
    response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self';"
    return response

def require_login():
    """Redirect to login if not authenticated."""
    if "username" not in session:
        return redirect("/", code=302)
    return None
# ── Home / Login ──────────────────────────────────────────────────────────────

@app.route("/", methods=["POST", "GET"])
@app.route("/index.html", methods=["POST", "GET"])
def home():
    # VULNERABILITY: Open Redirect — blindly follows 'url' query parameter
    

    # VULNERABILITY: Reflected XSS — 'msg' rendered with |safe in template
    if request.method == "GET":
        msg = request.args.get("msg", "")
        return render_template("index.html", msg=msg)

    elif request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        isLoggedIn = db.retrieveUsers(username, password)
        if isLoggedIn:
            session["username"] = username
            posts = db.getPosts()
            return render_template("feed.html", username=username, state=isLoggedIn, posts=posts)
        else:
            return render_template("index.html", msg="Invalid credentials. Please try again.")

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/", code=302)
# ── Sign Up ───────────────────────────────────────────────────────────────────

@app.route("/signup.html", methods=["POST", "GET"])
def signup():
    if request.method == "GET":
        return render_template("signup.html")

    elif request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        DoB      = request.form["dob"]
        bio      = request.form.get("bio", "")
        # VULNERABILITY: No duplicate username check
        # VULNERABILITY: No input validation or password strength enforcement
        db.insertUser(username, password, DoB, bio)
        return render_template("index.html", msg="Account created! Please log in.")
    else:
        return render_template("signup.html")


# ── Social Feed ───────────────────────────────────────────────────────────────

@app.route("/feed.html", methods=["POST", "GET"])
def feed():
    auth_redirect = require_login()
    if auth_redirect:
        return auth_redirect
    current_user = session["username"]

    if request.method == "POST":
        raw_content = request.form["content"]
        post_content = sanitize_plain_text(raw_content, max_length=1000)
        # VULNERABILITY: IDOR — username from hidden form field, can be tampered with
        
        if not post_content:
            posts = db.getPosts()
            return render_template(
                "feed.html",
                username=current_user,
                state=True,
                posts=posts,
                msg="Please enter a valid post."
            )
        
        db.insertPost(current_user, post_content)
        posts = db.getPosts()
        return render_template("feed.html", username=current_user, state=True, posts=posts)
    else:
        posts = db.getPosts()
        return render_template("feed.html", username=current_user, state=True, posts=posts)


# ── User Profile ──────────────────────────────────────────────────────────────

@app.route("/profile")
def profile():
    auth_redirect = require_login()
    if auth_redirect:
        return auth_redirect
    # VULNERABILITY: No authentication check — any visitor can read any profile
    # VULNERABILITY: SQL Injection via 'user' parameter in getUserProfile()
    
    current_user = session["username"]
    requested_user = request.args.get("user", current_user)
    if requested_user != current_user:
        return "Access Denied", 403

    profile_data = db.getUserProfile(requested_user)
    return render_template("profile.html", profile=profile_data, username=current_user) 

# ── Direct Messages ───────────────────────────────────────────────────────────

@app.route("/messages", methods=["POST", "GET"])
def messages():
    auth_redirect = require_login()
    if auth_redirect:
        return auth_redirect
    current_user = session["username"]
    # VULNERABILITY: No authentication — change ?user= to read anyone's inbox
    if request.method == "POST":
        recipient = sanitize_plain_text(request.form.get("recipient", ""), max_length=30)
        body      = sanitize_plain_text(request.form.get("body", ""), max_length=500)
        db.sendMessage(current_user, recipient, body)
        msgs = db.getMessages(current_user)
        return render_template("messages.html", messages=msgs, username=current_user, recipient=recipient)
    else:
        msgs = db.getMessages(current_user)
        return render_template("messages.html", messages=msgs, username=current_user, recipient=current_user)


# ── Success Page ──────────────────────────────────────────────────────────────
    
@app.route("/success.html")
def success():
    msg = request.args.get("msg", "Your action was completed successfully.")
    return render_template("success.html", msg=msg)


# ── Run ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    app.config["TEMPLATES_AUTO_RELOAD"] = True
    app.config["SEND_FILE_MAX_AGE_DEFAULT"] = 0
    app.run(debug=True, host="0.0.0.0", port=5000)
