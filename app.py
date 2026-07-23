"""
Q4 web app.
- Home page: login form (username, password, login button)
- Register page: create account, password validated against OWASP Top 10 2024
  Proactive Control C7 (Secure Digital Identities), Level 1 password requirements.
- Backend validation is authoritative (never trust client-side checks alone).
  Frontend JS only does a cheap length pre-check for UX; the real check
  (including the common-password lookup) happens server-side.
"""
import os
import re
import requests
from datetime import datetime
from flask import Flask, request, session, redirect, url_for, render_template_string
import mysql.connector

app = Flask(__name__)
app.secret_key = "prac-test-secret"

DB_HOST = os.environ.get("DB_HOST", "mysqldb")
DB_USER = os.environ.get("DB_USER", "user")
DB_PASSWORD = os.environ.get("DB_PASSWORD", "pass")
DB_NAME = os.environ.get("DB_NAME", "testdb")

PASSWORD_LIST_URL = (
    "https://raw.githubusercontent.com/danielmiessler/SecLists/master/"
    "Passwords/Common-Credentials/100k-most-used-passwords-NCSC.txt"
)

MIN_LENGTH = 8
MAX_LENGTH = 64

# Guaranteed to work even if the NCSC list download fails (no internet /
# blocked in the container). The full list below is loaded on top of this.
FALLBACK_COMMON_PASSWORDS = [
    "password", "password1", "password123", "12345678", "123456789",
    "1234567890", "123456", "1234567", "12345", "qwerty", "qwerty123",
    "letmein", "welcome", "monkey", "111111", "000000", "iloveyou",
    "abc123", "123123", "admin", "administrator", "dragon", "sunshine",
    "master", "football", "baseball", "shadow", "michael", "superman",
    "trustno1", "batman", "passw0rd", "starwars", "hello123", "freedom",
]


def get_db():
    return mysql.connector.connect(
        host=DB_HOST, user=DB_USER, password=DB_PASSWORD, database=DB_NAME
    )


def init_db():
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "CREATE TABLE IF NOT EXISTS common_passwords ("
        "pw VARCHAR(128) PRIMARY KEY)"
    )
    cur.execute(
        "CREATE TABLE IF NOT EXISTS `2401073` ("
        "id INT AUTO_INCREMENT PRIMARY KEY, "
        "username VARCHAR(64), "
        "created_at DATETIME)"
    )
    conn.commit()

    cur.execute("SELECT COUNT(*) FROM common_passwords")
    count = cur.fetchone()[0]
    if count == 0:
        # Always load the fallback list first so validation works even if
        # the download below fails.
        cur.executemany(
            "INSERT IGNORE INTO common_passwords (pw) VALUES (%s)",
            [(w,) for w in FALLBACK_COMMON_PASSWORDS],
        )
        conn.commit()
        try:
            resp = requests.get(PASSWORD_LIST_URL, timeout=30)
            resp.raise_for_status()
            words = [w.strip().lower() for w in resp.text.splitlines() if w.strip()]
            cur.executemany(
                "INSERT IGNORE INTO common_passwords (pw) VALUES (%s)",
                [(w,) for w in words],
            )
            conn.commit()
        except Exception as e:
            print(f"Could not load common password list: {e}")
    cur.close()
    conn.close()


def is_common_password(password: str) -> bool:
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT 1 FROM common_passwords WHERE pw = %s", (password.lower(),))
    found = cur.fetchone() is not None
    cur.close()
    conn.close()
    return found


def validate_password(password: str):
    """OWASP Top 10 2024 Proactive Control C7 - Secure Digital Identities,
    Level 1 password requirements: minimum 8 chars, allow up to 64+,
    no forced composition rules, reject known-breached/common passwords."""
    if len(password) < MIN_LENGTH:
        return False, f"Password must be at least {MIN_LENGTH} characters."
    if len(password) > MAX_LENGTH:
        return False, f"Password must be at most {MAX_LENGTH} characters."
    if is_common_password(password):
        return False, "This password is too common. Please choose another."
    return True, ""


HOME_PAGE = """
<h2>Login</h2>
<form method="POST" action="/">
  Username: <input type="text" name="username"><br>
  Password: <input type="password" name="password"><br>
  <button type="submit">Login</button>
</form>
{% if error %}<p style="color:red">{{ error }}</p>{% endif %}
<p><a href="/register">Create an account</a></p>
"""

REGISTER_PAGE = """
<h2>Create Account</h2>
<form method="POST" action="/register" onsubmit="return checkPassword();">
  Username: <input type="text" name="username" id="username"><br>
  Password: <input type="password" name="password" id="password"><br>
  <button type="submit">Register</button>
</form>
<script src="/static/validate.js"></script>
"""

WELCOME_PAGE = """
<h2>Welcome, {{ username }}</h2>
<p>Your password: {{ password }}</p>
<a href="/logout">Logout</a>
"""


@app.route("/", methods=["GET", "POST"])
def home():
    if request.method == "POST":
        # No password is stored, so login only confirms the form works.
        return render_template_string(HOME_PAGE, error=session.pop("error", None))
    return render_template_string(HOME_PAGE, error=session.pop("error", None))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        ok, msg = validate_password(password)
        if not ok:
            session["error"] = msg
            return redirect(url_for("home"))

        conn = get_db()
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO `2401073` (username, created_at) VALUES (%s, %s)",
            (username, datetime.now()),
        )
        conn.commit()
        cur.close()
        conn.close()

        session["username"] = username
        session["password"] = password
        return redirect(url_for("welcome"))
    return render_template_string(REGISTER_PAGE)


@app.route("/welcome")
def welcome():
    if "password" not in session:
        return redirect(url_for("home"))
    return render_template_string(
        WELCOME_PAGE, username=session["username"], password=session["password"]
    )


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))


if __name__ == "__main__":
    init_db()
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
