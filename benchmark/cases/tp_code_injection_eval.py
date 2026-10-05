"""A JSON body field reaching eval."""

from flask import Flask, request

app = Flask(__name__)


@app.route("/calc", methods=["POST"])
def calc():
    expression = request.json
    return str(eval(expression))
