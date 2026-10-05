"""A cookie is attacker-controlled too, which is easy to forget."""

from flask import Flask, request
import os

app = Flask(__name__)


@app.route("/theme")
def theme():
    name = request.cookies.get("theme")
    os.popen("cat /themes/" + name)
    return "ok"
