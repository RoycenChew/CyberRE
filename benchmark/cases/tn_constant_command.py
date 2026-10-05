"""A command sink with no tainted input at all."""

from flask import Flask, request
import subprocess

app = Flask(__name__)


@app.route("/health")
def health():
    subprocess.run(["systemctl", "is-active", "app"], shell=False)
    return "ok"
