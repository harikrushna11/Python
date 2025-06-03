"""
OWASP Python Large File Example (~1000 LOC)
Test Case: TC03
Vulnerabilities:
1. Broken Authentication (A7) - weak password storage & session token
2. Security Misconfiguration (A6) - debug info leakage, unsafe configs

This large file simulates a Flask-based web app with user auth, API endpoints,
config management, logging, and utility functions.
"""

import os
import random
import string
import hashlib
from flask import Flask, request, jsonify, session, redirect, url_for, render_template_string
from functools import wraps
import logging
import datetime

app = Flask(__name__)

# ======= Security Misconfiguration (A6) =======
# ❌ Unsafe default secret key (debug mode also enabled by default)
app.config['SECRET_KEY'] = "defaultsecretkey123456"  # Weak secret key, should be env var or strong random
app.config['DEBUG'] = True  # ❌ Debug info leakage enabled in production environment

# Setup logger
logger = logging.getLogger('app_logger')
logger.setLevel(logging.DEBUG if app.config['DEBUG'] else logging.INFO)
ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
ch.setFormatter(formatter)
logger.addHandler(ch)

# In-memory user database (simulate persistent storage)
users_db = {}

# === Utility functions ===

def generate_session_token(length=12):
    """Generates a weak session token"""
    # ❌ Weak session token generation (predictable and short)
    chars = string.ascii_letters + string.digits
    token = ''.join(random.choice(chars) for _ in range(length))
    return token

def hash_password(password):
    """Hash password using SHA1 (weak) - Simulating broken auth"""
    # ❌ Weak password hashing, SHA1 is deprecated
    return hashlib.sha1(password.encode()).hexdigest()

def verify_password(stored_hash, password):
    """Verify password by hashing input and comparing"""
    return stored_hash == hash_password(password)

def login_required(f):
    """Decorator to protect routes"""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.cookies.get('session_token')
        if not token or token not in session_store:
            return jsonify({"error": "Authentication required"}), 401
        return f(*args, **kwargs)
    return decorated

# === Session management (in-memory) ===
session_store = {}

# === Routes ===

@app.route('/')
def home():
    return "Welcome to the Large OWASP Python App"

# ---- Registration Endpoint ----
@app.route('/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"error": "Missing username or password"}), 400
    if username in users_db:
        return jsonify({"error": "User exists"}), 400

    # ❌ Broken Auth: Store password in weak hash (SHA1, no salt)
    users_db[username] = {
        "password_hash": hash_password(password),
        "created_at": datetime.datetime.now()
    }

    logger.info(f"User registered: {username}")
    return jsonify({"message": f"User {username} registered successfully"})

# ---- Login Endpoint ----
@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    user = users_db.get(username)
    if not user or not verify_password(user['password_hash'], password):
        logger.warning(f"Failed login attempt for user: {username}")
        return jsonify({"error": "Invalid credentials"}), 401

    # Generate weak session token
    token = generate_session_token()

    # Store session token
    session_store[token] = username

    # Set cookie with session token
    resp = jsonify({"message": f"User {username} logged in"})
    resp.set_cookie('session_token', token, httponly=True)
    return resp

# ---- Logout Endpoint ----
@app.route('/logout', methods=['POST'])
@login_required
def logout():
    token = request.cookies.get('session_token')
    user = session_store.pop(token, None)
    resp = jsonify({"message": "Logged out"})
    resp.delete_cookie('session_token')
    logger.info(f"User logged out: {user}")
    return resp

# ---- User Info Endpoint ----
@app.route('/user-info', methods=['GET'])
@login_required
def user_info():
    token = request.cookies.get('session_token')
    username = session_store.get(token)
    if not username:
        return jsonify({"error": "Invalid session"}), 401
    return jsonify({"username": username, "info": "Some user data here"})

# ---- Debug info leakage endpoint (A6) ----
@app.route('/debug-info', methods=['GET'])
def debug_info():
    # ❌ Exposes internal app config and environment variables in response
    info = {
        "debug": app.config['DEBUG'],
        "secret_key": app.config['SECRET_KEY'],
        "users_count": len(users_db),
        "session_tokens": list(session_store.keys()),
        "environment": os.environ.get("APP_ENV", "development")
    }
    return jsonify(info)

# === Additional utilities and filler code to increase size ===

def generate_random_data(size=100):
    """Generate random strings for dummy data"""
    chars = string.ascii_letters + string.digits
    return [''.join(random.choice(chars) for _ in range(20)) for _ in range(size)]

def simulate_heavy_processing(n=500):
    """Simulate CPU intensive dummy processing"""
    results = []
    for i in range(n):
        results.append(i * i)
    return results

# Dummy classes to simulate business logic

class UserManager:
    def __init__(self):
        self.users = users_db

    def add_user(self, username, password):
        if username in self.users:
            raise Exception("User exists")
        self.users[username] = {
            "password_hash": hash_password(password),
            "created_at": datetime.datetime.now()
        }

    def authenticate(self, username, password):
        user = self.users.get(username)
        if not user:
            return False
        return verify_password(user['password_hash'], password)

    def get_user(self, username):
        return self.users.get(username)

app = Flask(__name__)

# -- Database Setup --
def init_db():
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            password TEXT
        )
    """)
    conn.commit()
    conn.close()

# -- Vulnerable: Hardcoded Credentials (OWASP A2) --
def authenticate_static():
    username = request.args.get("username")
    password = request.args.get("password")
    
    # ❌ Hardcoded credentials
    if username == "admin" and password == "admin123":
        return "Login successful as admin"
    else:
        return "Invalid credentials"

# -- Vulnerable: SQL Injection (OWASP A1) --
@app.route("/login", methods=["GET"])
def login():
    username = request.args.get("username")
    password = request.args.get("password")

    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()

    # ❌ Vulnerable SQL query
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    print(f"Executing: {query}")
    cursor.execute(query)
    result = cursor.fetchone()
    conn.close()

    if result:
        return f"Welcome back, {username}!"
    else:
        return "Login failed"

# -- Safe Registration --
@app.route("/register", methods=["POST"])
def register():
    username = request.form.get("username")
    password = request.form.get("password")

    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
    conn.commit()
    conn.close()
    return "User registered!"

# -- Safe version of login using parameterized queries --
@app.route("/safe_login", methods=["POST"])
def safe_login():
    username = request.form.get("username")
    password = request.form.get("password")

    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username=? AND password=?", (username, password))
    user = cursor.fetchone()
    conn.close()

    if user:
        return f"Secure Welcome, {username}"
    return "Secure Login Failed"
class ReportGenerator:
    def __init__(self, user_manager):
        self.um = user_manager

    def generate_report(self, username):
        user = self.um.get_user(username)
        if not user:
            return None
        # Simulate report generation
        report = {
            "user": username,
            "report_date": datetime.datetime.now().isoformat(),
            "data_points": generate_random_data(100)
        }
        return report

class LoggerService:
    def __init__(self):
        self.logs = []

    def log_event(self, event):
        entry = {
            "timestamp": datetime.datetime.now(),
            "event": event
        }
        self.logs.append(entry)
        logger.info(f"Log event: {event}")

# ==== Adding repetitive functions to inflate LOC to ~1000 ====

def dummy_function_1():
    x = 0
    for i in range(100):
        x += i
    return x

def dummy_function_2():
    result = []
    for i in range(100):
        result.append(i * 2)
    return result

def dummy_function_3():
    s = "hello"
    for _ in range(50):
        s += " world"
    return s

# Repeated pattern to reach ~1000 LOC
def repeated_patterns():
    output = []
    for i in range(50):
        output.append(dummy_function_1())
        output.append(dummy_function_2())
        output.append(dummy_function_3())
    return output

# --- Main run ---
if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)
