"""Taint surviving one assignment before the sink."""

from flask import Flask, request
import subprocess

app = Flask(__name__)


@app.route("/lookup")
def lookup():
    target = request.args.get("domain")
    command = "dig " + target
    subprocess.run(command, shell=True)
    return "ok"
