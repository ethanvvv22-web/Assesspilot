import logging
import os
import sqlite3
import subprocess

from flask import Flask, render_template, request, send_file
from flask_login import LoginManager, login_required
from werkzeug.security import check_password_hash, generate_password_hash

from config import SECRET_KEY

app = Flask(__name__)
app.secret_key = SECRET_KEY
login_manager = LoginManager(app)
logger = logging.getLogger("shop")
DB = "shop.db"


def db():
    return sqlite3.connect(DB)


@app.route("/register", methods=["POST"])
def register():
    email = request.form["email"]
    pw_hash = generate_password_hash(request.form["password"])
    db().execute("INSERT INTO users (email, password_hash) VALUES (?, ?)", (email, pw_hash))
    logger.info("new user registered")
    return "ok"


@app.route("/login", methods=["POST"])
def login():
    email = request.form["email"]
    row = db().execute("SELECT password_hash FROM users WHERE email = ?", (email,)).fetchone()
    if row and check_password_hash(row[0], request.form["password"]):
        return "welcome"
    logger.warning("failed login for %s with password %s", email, request.form["password"])
    return "denied", 401


@app.route("/orders")
@login_required
def orders():
    customer = request.args.get("customer", "")
    rows = db().execute(f"SELECT * FROM orders WHERE customer = '{customer}'").fetchall()
    return {"orders": rows}


@app.route("/invoice")
@login_required
def invoice():
    return send_file(os.path.join("invoices", request.args["name"]))


@app.route("/admin/export")
def admin_export():
    table = request.args.get("table", "orders")
    subprocess.run(f"sqlite3 {DB} '.dump {table}' > export.sql", shell=True)
    return "exported"


@app.route("/profile")
@login_required
def profile():
    return render_template("profile.html", bio=request.args.get("bio", ""))


if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)
