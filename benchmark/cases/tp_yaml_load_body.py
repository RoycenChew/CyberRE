"""yaml.load without a safe loader, fed from the request body."""

from flask import Flask, request
import yaml

app = Flask(__name__)


@app.route("/config", methods=["POST"])
def config():
    document = request.data
    return str(yaml.load(document))
