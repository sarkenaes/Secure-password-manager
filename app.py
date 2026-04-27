"""Secure Password Toolkit Flask app.

Combines a password strength checker with an encrypted password manager.
"""

from flask import Flask, flash, redirect, render_template, request, url_for

from checker import check_password_strength
from database import add_entry, delete_entry, init_db, view_entries

app = Flask(__name__)
app.config["SECRET_KEY"] = "change-this-before-deployment"

init_db()


@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    password = ""

    if request.method == "POST":
        password = request.form.get("password", "")
        check_breaches = request.form.get("check_breaches") == "on"
        result = check_password_strength(password, check_breaches=check_breaches)

    return render_template("index.html", result=result, password=password)


@app.route("/add", methods=["GET", "POST"])
def add_password():
    result = None

    if request.method == "POST":
        website = request.form.get("website", "").strip()
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        notes = request.form.get("notes", "").strip()
        check_breaches = request.form.get("check_breaches") == "on"
        result = check_password_strength(password, check_breaches=check_breaches)

        if not website or not username or not password:
            flash("Website, username, and password are required.", "error")
        elif result["strength"] == "weak":
            flash("Password is too weak to save. Improve it first.", "error")
        else:
            add_entry(website, username, password, notes)
            flash("Password saved securely in the encrypted vault.", "success")
            return redirect(url_for("view_passwords"))

    return render_template("add.html", result=result)


@app.route("/vault")
def view_passwords():
    entries = view_entries()
    return render_template("vault.html", entries=entries)


@app.route("/delete/<int:entry_id>", methods=["POST"])
def remove_password(entry_id: int):
    delete_entry(entry_id)
    flash("Entry deleted.", "success")
    return redirect(url_for("view_passwords"))


if __name__ == "__main__":
    app.run(debug=True)
