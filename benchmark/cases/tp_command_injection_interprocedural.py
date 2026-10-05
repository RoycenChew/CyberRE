"""Taint crossing one call boundary, which is the limit of the analyser."""

from flask import Flask, request
import os

app = Flask(__name__)


def render(path):
    os.system("cat " + path)


@app.route("/show")
def show():
    page = request.args.get("page")
    render(page)
    return "ok"
