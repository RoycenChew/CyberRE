"""Tainted, reaches a command sink, and is correctly escaped."""

from flask import Flask, request
import shlex
import subprocess

app = Flask(__name__)


@app.route("/ping")
def ping():
    host = request.args.get("host")
    subprocess.run("ping -c 1 " + shlex.quote(host), shell=True)
    return "ok"
