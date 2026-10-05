"""os.path.basename defuses a traversal before the command."""

from flask import Flask, request
import os

app = Flask(__name__)


@app.route("/read")
def read():
    name = os.path.basename(request.args.get("file"))
    os.system("cat /data/" + name)
    return "ok"
