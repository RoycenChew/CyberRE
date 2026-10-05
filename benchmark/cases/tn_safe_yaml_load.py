"""yaml.safe_load is not the sink; yaml.load is."""

from flask import Flask, request
import yaml

app = Flask(__name__)


@app.route("/config", methods=["POST"])
def config():
    document = request.data
    return str(yaml.safe_load(document))
