"""Tainted input as a list argument with shell=False.

The value is an argv element, not a shell string, so it cannot inject a
second command. The argument is still worth a look - hence a hard case.
"""

from flask import Flask, request
import subprocess

app = Flask(__name__)


@app.route("/ping")
def ping():
    host = request.args.get("host")
    subprocess.run(["ping", "-c", "1", host], shell=False)
    return "ok"
