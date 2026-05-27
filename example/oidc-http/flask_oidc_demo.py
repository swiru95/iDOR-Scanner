from flask import Flask, request, redirect, jsonify
import uuid

app = Flask(__name__)

# Simulated OIDC IdP endpoints
users = {"alice": "password1", "bob": "password2"}
auth_codes = {}
tokens = {}

CLIENT_ID = "demo-client"
REDIRECT_URI = "http://localhost:5000/callback"

@app.route("/authorize")
def authorize():
    username = request.args.get("username")
    password = request.args.get("password")
    client_id = request.args.get("client_id")
    redirect_uri = request.args.get("redirect_uri")
    state = request.args.get("state")
    if username in users and users[username] == password and client_id == CLIENT_ID:
        code = str(uuid.uuid4())
        auth_codes[code] = username
        return redirect(f"{redirect_uri}?code={code}&state={state}")
    return "Unauthorized", 401

@app.route("/token", methods=["POST"])
def token():
    code = request.form.get("code")
    client_id = request.form.get("client_id")
    redirect_uri = request.form.get("redirect_uri")
    if code in auth_codes and client_id == CLIENT_ID and redirect_uri == REDIRECT_URI:
        username = auth_codes.pop(code)
        access_token = str(uuid.uuid4())
        tokens[access_token] = username
        return jsonify({
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": 3600,
            "id_token": str(uuid.uuid4()),
        })
    return jsonify({"error": "invalid_grant"}), 400

@app.route("/resource")
def resource():
    auth = request.headers.get("Authorization", "").replace("Bearer ", "")
    if auth in tokens:
        return jsonify({"user": tokens[auth], "data": "secret"})
    return "Forbidden", 403

if __name__ == "__main__":
    app.run(port=5000)