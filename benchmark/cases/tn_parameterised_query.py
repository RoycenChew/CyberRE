"""The classic trap: tainted input reaching cursor.execute SAFELY.

A scanner that matches on "user input reaches execute" flags this. The
placeholder means the value is bound, never parsed as SQL.
"""

from flask import Flask, request

app = Flask(__name__)


@app.route("/user")
def user(cursor):
    name = request.args.get("name")
    cursor.execute("SELECT * FROM users WHERE name = ?", (name,))
    return "ok"
