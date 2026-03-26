import sqlite3 as sql
import time
import random
import os
import hashlib
from werkzeug.security import generate_password_hash, check_password_hash

# ─────────────────────────────────────────────────────────────────────────────
#  user_management.py
#  Handles all direct database operations for the Unsecure Social PWA.
#
#  INTENTIONAL VULNERABILITIES (for educational use):
#    1. SQL Injection      — f-string queries throughout
#    2. Plaintext passwords — no hashing applied at any point
#    3. Timing side-channel — sleep only fires when username EXISTS
#    4. No input validation — any string accepted as username/password
#    5. IDOR-equivalent    — username passed from client-side hidden field
# ─────────────────────────────────────────────────────────────────────────────

# Absolute paths — works regardless of where `python main.py` is called from
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH  = os.path.join(BASE_DIR, "database_files", "database.db")
LOG_PATH = os.path.join(BASE_DIR, "visitor_log.txt")


def insertUser(username, password, DoB, bio=""):
    """
    Insert a new user.
    VULNERABILITY: Password stored as plaintext — no bcrypt/argon2 hashing.
    """
    hashed_password = generate_password_hash(password)
    con = sql.connect(DB_PATH)
    cur = con.cursor()
    cur.execute(
        "INSERT INTO users (username, password, dateOfBirth, bio) VALUES (?,?,?,?)",
        (username, hashed_password, DoB, bio),
    )
    con.commit()
    con.close()


def retrieveUsers(username, password):
    #"""
    #Authenticate a user.
    #VULNERABILITY 1 — SQL Injection via f-strings on both username and password.
    #  Try: username = admin'--   (bypasses password check entirely)
    #  Try: username = ' OR '1'='1'--
    #VULNERABILITY 2 — Timing Side-Channel:
    #  sleep() only fires when username EXISTS, leaking valid usernames via response time.
    #VULNERABILITY 3 — No account lockout or rate limiting.
    
    con = sql.connect(DB_PATH)
    cur = con.cursor()

    # VULNERABILITY: SQL Injection
    cur.execute("SELECT * FROM users WHERE username = ?", (username,))
    user_row = cur.fetchone()
    stored_hash = user_row[2]
    if check_password_hash(stored_hash, password):
        result = user_row
    else:
        result = None


    if user_row is None:
        time.sleep(random.randint(80, 90) / 1000)
        con.close()
        return False 
    else:
        # VULNERABILITY: Timing side-channel — delay ONLY when username found
        time.sleep(random.randint(80, 90) / 1000)

        try:
            with open(LOG_PATH, "r") as f:
                count = int(f.read().strip() or 0)
            with open(LOG_PATH, "w") as f:
                f.write(str(count + 1))
        except Exception:
            pass

        # VULNERABILITY: SQL Injection on password field
        cur.execute("SELECT * FROM users WHERE password = ?", (password,))
        result = cur.fetchone()
        con.close()
        return result is not None


def insertPost(author, content):
    """
    Insert a post.
    REMOVED: SQL Injection via f-string on both author and content.
    VULNERABILITY: author comes from a hidden HTML field — easily spoofed (IDOR).
    """
    con = sql.connect(DB_PATH)
    cur = con.cursor()
    cur.execute("INSERT INTO posts (author, content) VALUES (?, ?)", (author, content))
    con.commit()
    con.close()


def getPosts():
    """
    Get all posts newest-first.
    NOTE: Content returned here is rendered with |safe in feed.html — stored XSS.
    """
    con = sql.connect(DB_PATH)
    cur = con.cursor()
    data = cur.execute("SELECT * FROM posts ORDER BY id DESC").fetchall()
    con.close()
    return data


def getUserProfile(username):
    
    #Get a user profile row.
    #REMOVED: SQL Injection via f-string — try /profile?user=admin'-- DONE
    #VULNERABILITY: No authentication check — any visitor can view any profile.
    
    con = sql.connect(DB_PATH)
    cur = con.cursor()
    cur.execute("SELECT id, username, dateOfBirth, bio, role FROM users WHERE username = ?", (username,))
    row = cur.fetchone()
    con.close()
    return row


def getMessages(username):
    
    #Get inbox for a user.
    #REMOVED: SQL Injection via f-string.
    #VULNERABILITY: No auth check — change ?user= to read anyone's inbox.
    
    con = sql.connect(DB_PATH)
    cur = con.cursor()
    cur.execute("SELECT * FROM messages WHERE recipient = ? ORDER BY id DESC", (username,))
    rows = cur.fetchall()
    con.close()
    return rows


def sendMessage(sender, recipient, body):
    
    #Send a DM.
    #REMOVED: SQL Injection on all three fields. DONE
    #VULNERABILITY: sender taken from hidden form field — can be spoofed.
    
    con = sql.connect(DB_PATH)
    cur = con.cursor()
    cur.execute("INSERT INTO messages (sender, recipient, body) VALUES (?, ?, ?)", (sender, recipient, body))
    con.commit()
    con.close()

# Unsure of if there is anything wrong with the small section of code below. Will check later.
def getVisitorCount():
    """Return login attempt count."""
    try:
        with open(LOG_PATH, "r") as f:
            return int(f.read().strip() or 0)
    except Exception:
        return 0

