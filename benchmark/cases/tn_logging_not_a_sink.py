"""Tainted input reaching something that merely looks dangerous."""

from flask import Flask, request
import logging

app = Flask(__name__)


@app.route("/track")
def track():
    agent = request.headers.get("User-Agent")
    logging.info("agent=%s", agent)
    return "ok"
