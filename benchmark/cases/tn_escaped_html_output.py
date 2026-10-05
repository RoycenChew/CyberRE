"""Tainted, escaped, and never reaching an execution sink."""

from flask import Flask, request
import html

app = Flask(__name__)


@app.route("/greet")
def greet():
    name = request.args.get("name")
    return "<p>Hello " + html.escape(name) + "</p>"
