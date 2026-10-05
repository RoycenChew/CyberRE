"""A header reaching SQL by concatenation."""

from flask import Flask, request

app = Flask(__name__)


@app.route("/audit")
def audit(db):
    actor = request.headers.get("X-Actor")
    db.execute("INSERT INTO audit (actor) VALUES (" + actor + ")")
    return "ok"
