"""Request body handed to pickle."""

from flask import Flask, request
import pickle

app = Flask(__name__)


@app.route("/restore", methods=["POST"])
def restore():
    blob = request.data
    state = pickle.loads(blob)
    return str(state)
