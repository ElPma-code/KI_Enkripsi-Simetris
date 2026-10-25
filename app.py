import os
import sqlite3

import secrets
from flask import abort

from argon2.exceptions import VerifyMismatchError, VerificationError
from flask import Flask, render_template, request, redirect, url_for, session
from database import DB_PATH, password_hasher

app = Flask(__name__)

# Kunci untuk menandatangani cookie session Flask.
# Simpan di environment variable, bukan source code.
secret_key = os.environ.get("FLASK_SECRET_KEY")

if not secret_key:
    raise RuntimeError("FLASK_SECRET_KEY belum diatur.")

app.config["SECRET_KEY"] = secret_key
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

@app.context_processor
def inject_csrf_token():
    def csrf_token():
        if "_csrf_token" not in session:
            session["_csrf_token"] = secrets.token_hex(32)

        return session["_csrf_token"]

    return {"csrf_token": csrf_token}

# Halaman utama
@app.route("/")
def home():
    return render_template("index.html")


# Halaman login
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")

    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")

    connection = sqlite3.connect(DB_PATH)

    try:
        connection.row_factory = sqlite3.Row

        user = connection.execute(
            "SELECT * FROM users WHERE email = ?",
            (email,)
        ).fetchone()
    finally:
        connection.close()

    if user:
        try:
            password_hasher.verify(user["password_hash"], password)

        except (VerifyMismatchError, VerificationError):
            pass

        else:
            session.clear()
            session["user_id"] = user["id"]

            return redirect(url_for("dashboard"))

    return render_template(
        "login.html",
        error="Email atau password salah."
    ), 401


# Halaman dashboard
@app.route("/dashboard")
def dashboard():
    user_id = session.get("user_id")

    if user_id is None:
        return redirect(url_for("login"))

    connection = sqlite3.connect(DB_PATH)

    try:
        user = connection.execute(
            "SELECT id FROM users WHERE id = ?",
            (user_id,)
        ).fetchone()
    finally:
        connection.close()

    if user is None:
        session.clear()
        return redirect(url_for("login"))

    return render_template("dashboard.html")

# Logout
@app.route("/logout", methods=["POST"])
def logout():
    token = request.form.get("csrf_token", "")
    expected = session.get("_csrf_token", "")

    if not expected or not secrets.compare_digest(token, expected):
        abort(400)

    session.clear()
    return redirect(url_for("login"))

if __name__ == "__main__":
    app.run(debug=True)
