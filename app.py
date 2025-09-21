from flask import Flask, jsonify, request
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from datetime import datetime, timedelta
import jwt

app = Flask(__name__)

# Generate and store keys
KEYS = []

def generate_key_pair(kid, expire_seconds=3600):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    
    # PEM format strings
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    expires_at = datetime.utcnow() + timedelta(seconds=expire_seconds)
    
    KEYS.append({
        "kid": kid,
        "private": private_pem,
        "public": public_pem,
        "expires_at": expires_at
    })

# generate 2 keys: one valid, one expired
generate_key_pair("key1", expire_seconds=3600)  # this is the valid key
generate_key_pair("key2", expire_seconds=-3600) # this is the expired key

# ---------------------------
# JWKS endpoint
# ---------------------------
@app.route("/.well-known/jwks.json")
def jwks():
    jwks_keys = []
    now = datetime.utcnow()
    
    for k in KEYS:
        if k["expires_at"] > now:  # only unexpired keys
            pub_key = serialization.load_pem_public_key(k["public"])
            numbers = pub_key.public_numbers()
            jwks_keys.append({
                "kty": "RSA",
                "kid": k["kid"],
                "use": "sig",
                "n": numbers.n,
                "e": numbers.e
            })
    
    return jsonify({"keys": jwks_keys})

# ---------------------------
# /auth endpoint
# ---------------------------
@app.route("/auth", methods=["POST"])
def auth():
    expired = request.args.get("expired") == "true"
    now = datetime.utcnow()
    
    # pick the key
    key = None
    if expired:
        for k in KEYS:
            if k["expires_at"] <= now:
                key = k
                break
    else:
        for k in KEYS:
            if k["expires_at"] > now:
                key = k
                break
    
    if not key:
        return jsonify({"error": "no suitable key found"}), 500
    
    payload = {
        "sub": "fake_user",
        "iat": int(now.timestamp()),
        "exp": int(key["expires_at"].timestamp())
    }
    
    token = jwt.encode(payload, key["private"], algorithm="RS256", headers={"kid": key["kid"]})
    
    return jsonify({"jwt": token})

# ---------------------------
# Run server
# ---------------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
