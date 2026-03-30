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
    con = sql.connect(DB_PATH) 
    cur = con.cursor()

    cur.execute("SELECT id FROM users WHERE username = ?", (username,))
    if cur.fetchone():
        con.close()
        return False  # User already exists
    hashed_password = generate_password_hash(password)
    cur.execute(
        "INSERT INTO users (username, password, dateOfBirth, bio) VALUES (?,?,?,?)",
        (username, hashed_password, DoB, bio),
    )
    con.commit()
    con.close()
    return True


def retrieveUsers(username, password):
    #"""
    #Authenticate a user.
    
    
    con = sql.connect(DB_PATH)
    cur = con.cursor()

    
    cur.execute("SELECT * FROM users WHERE username = ?", (username,))
    user_row = cur.fetchone()
    

    if user_row:
        stored_hash = user_row[2]  # Assuming password column is index 2
        password_valid = check_password_hash(stored_hash, password)
    else:
        dummy_hash = generate_password_hash("dummy")  # Fixed dummy hash
        password_valid = check_password_hash(dummy_hash, password)
    
    
    time.sleep(0.1)
    

    if user_row is None:
        time.sleep(random.randint(80, 90) / 1000)
        con.close()
        return False 
    else:
        
        time.sleep(random.randint(80, 90) / 1000)

        try:
            with open(LOG_PATH, "r") as f:
                count = int(f.read().strip() or 0)
            with open(LOG_PATH, "w") as f:
                f.write(str(count + 1))
        except Exception:
            pass

        
       
        con.close()
        return password_valid


def insertPost(author, content):
    
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
    
 
    
    con = sql.connect(DB_PATH)
    cur = con.cursor()
    cur.execute("SELECT id, username, dateOfBirth, bio, role FROM users WHERE username = ?", (username,))
    row = cur.fetchone()
    con.close()
    return row


def getMessages(username):
    
   
    con = sql.connect(DB_PATH)
    cur = con.cursor()
    cur.execute("SELECT * FROM messages WHERE recipient = ? ORDER BY id DESC", (username,))
    rows = cur.fetchall()
    con.close()
    return rows


def sendMessage(sender, recipient, body):
    
   
    
    con = sql.connect(DB_PATH)
    cur = con.cursor()
    cur.execute("INSERT INTO messages (sender, recipient, body) VALUES (?, ?, ?)", (sender, recipient, body))
    con.commit()
    con.close()


def getVisitorCount():
    """Return login attempt count."""
    try:
        with open(LOG_PATH, "r") as f:
            return int(f.read().strip() or 0)
    except Exception:
        return 0

