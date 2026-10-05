"""String-formatted SQL from a form field."""

from flask import Flask, request

app = Flask(__name__)


@app.route("/user", methods=["POST"])
def user(cursor):
    name = request.form.get("name")
    cursor.execute(f"SELECT * FROM users WHERE name = {name!r}")
    return "ok"
