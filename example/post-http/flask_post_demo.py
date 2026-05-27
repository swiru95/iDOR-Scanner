from flask import Flask, request, jsonify

app = Flask(__name__)

users = {"alice": "password1", "bob": "password2"}
tokens = {}

@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")
    if username in users and users[username] == password:
        token = f"token-{username}"
        tokens[token] = username
        return jsonify({"token": token})
    return "Unauthorized", 401

@app.route("/resource")
def resource():
    auth = request.headers.get("Authorization", "").replace("Bearer ", "")
    if auth in tokens:
        return jsonify({"user": tokens[auth], "data": "secret"})
    return "Forbidden", 403

if __name__ == "__main__":
    app.run(port=5001)