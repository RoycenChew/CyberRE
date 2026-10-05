"""The sanitiser is applied at the call site, not inside the callee.

Dropping the caller-applied sanitiser during propagation is a real bug
this analyser once had, so the corpus keeps a case for it.
"""

from flask import Flask, request
import shlex
import subprocess

app = Flask(__name__)


def run_ping(host):
    subprocess.run("ping -c 1 " + host, shell=True)


@app.route("/ping")
def ping():
    raw = request.args.get("host")
    run_ping(shlex.quote(raw))
    return "ok"
