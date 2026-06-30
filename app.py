from flask import Flask, render_template, request, redirect, url_for, session
from flask_bcrypt import Bcrypt
import sqlite3
import re

app = Flask(__name__)
app.secret_key = "mysecretkey"

bcrypt = Bcrypt(app)


# Create Database
conn = sqlite3.connect("users.db")
cursor = conn.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS users(
id INTEGER PRIMARY KEY AUTOINCREMENT,
username TEXT UNIQUE,
password TEXT
)
""")

conn.commit()
conn.close()


# Register Page
@app.route("/")
def home():
    return render_template("register.html")


@app.route("/register", methods=["POST"])
def register():

    username = request.form["username"]
    password = request.form["password"]

    # Password Validation
    if len(password) < 8:
        return "Password must contain at least 8 characters."

    if not re.search(r"[A-Z]", password):
        return "Password must contain one uppercase letter."

    if not re.search(r"[a-z]", password):
        return "Password must contain one lowercase letter."

    if not re.search(r"[0-9]", password):
        return "Password must contain one number."

    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return "Password must contain one special character."

    hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")

    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM users WHERE username=?", (username,))
    existing_user = cursor.fetchone()

    if existing_user:
        conn.close()
        return "Username already exists."

    cursor.execute(
        "INSERT INTO users(username,password) VALUES(?,?)",
        (username, hashed_password)
    )

    conn.commit()
    conn.close()

    return redirect(url_for("login_page"))


# Login Page
@app.route("/login")
def login_page():
    return render_template("login.html")


# Login User
@app.route("/login", methods=["POST"])
def login():

    username = request.form["username"]
    password = request.form["password"]

    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()

    cursor.execute(
        "SELECT password FROM users WHERE username=?",
        (username,)
    )

    user = cursor.fetchone()

    conn.close()

    if user:

        stored_password = user[0]

        if bcrypt.check_password_hash(stored_password, password):

            session["username"] = username

            return redirect(url_for("dashboard"))

        else:
            return "<h2>Invalid Password</h2>"

    return "<h2>User Not Found</h2>"


# Dashboard
@app.route("/dashboard")
def dashboard():

    if "username" in session:

        return render_template(
            "home.html",
            username=session["username"]
        )

    return redirect(url_for("login_page"))


# Logout
@app.route("/logout")
def logout():

    session.pop("username", None)

    return redirect(url_for("login_page"))


if __name__ == "__main__":
    app.run(debug=True)