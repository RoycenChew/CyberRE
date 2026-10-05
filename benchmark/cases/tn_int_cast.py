"""int() is a sanitiser: the result cannot carry a shell metacharacter."""

from flask import Flask, request
import os

app = Flask(__name__)


@app.route("/tail")
def tail():
    count = int(request.args.get("n"))
    os.system("tail -n %d /var/log/app.log" % count)
    return "ok"
