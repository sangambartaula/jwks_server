from flask import Flask, jsonify, request
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from datetime import datetime, timezone, timedelta
import jwt
import base64

app = Flask(__name__)

# Generate and store keys here
# This includes both valid and invalid keys
# Each entry will have: kid, private key, public key, and the expiration
KEYS = []

# Convert RSA values to base64url
def long_to_base64url(n: int) -> str:
    """Convert a long integer to a base64url-encoded string without padding."""
    n_bytes = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(n_bytes).rstrip(b"=").decode("utf-8")

# Key pair generator
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
    
    # Timezone-aware expiration timestamp
    expires_at = datetime.now(timezone.utc) + timedelta(seconds=expire_seconds)
    
    # Store in KEYS list
    KEYS.append({
        "kid": kid,
        "private": private_pem,
        "public": public_pem,
        "expires_at": expires_at
    })

# Pre generate keys
# Generate 2 keys: one valid, one expired. Valid expires in 1h, invalid expired 1h ago
generate_key_pair("key1", expire_seconds=3600)   # valid key
generate_key_pair("key2", expire_seconds=-3600)  # expired key

# ---------------------------
# JWKS endpoint
# ---------------------------
@app.route("/.well-known/jwks.json")
def jwks():
    jwks_keys = []
    now = datetime.now(timezone.utc)
    
    for k in KEYS:
        if k["expires_at"] > now:  # only unexpired keys
            pub_key = serialization.load_pem_public_key(k["public"])
            numbers = pub_key.public_numbers()
            jwks_keys.append({
                "kty": "RSA",
                "kid": k["kid"],
                "use": "sig",
                "n": long_to_base64url(numbers.n),
                "e": long_to_base64url(numbers.e)
            })
    
    return jsonify({"keys": jwks_keys})

# ---------------------------
# /auth endpoint
# ---------------------------
@app.route("/auth", methods=["POST"])
def auth():
    expired = request.args.get("expired") == "true"
    now = datetime.now(timezone.utc)
    
    # Pick the key
    key = None
    if expired:
        for k in KEYS:
            if k["expires_at"] <= now: # expired key
                key = k
                break
    else:
        for k in KEYS:
            if k["expires_at"] > now: # valid key
                key = k
                break
    
    if not key:
        # If there is no suitable key at all, something went wrong..
        return jsonify({"error": "no suitable key found"}), 500
    
    # JWT Payload
    payload = {
        "sub": "fake_user",
        "iat": int(now.timestamp()),
        "exp": int(key["expires_at"].timestamp())
    }
    
# Sign JWT with the private key
    token = jwt.encode(payload, key["private"], algorithm="RS256", headers={"kid": key["kid"]}) # include key ID in header
    
    return jsonify({"jwt": token})

# ---------------------------
# Run server
# ---------------------------
if __name__ == "__main__":
    # Run the flask app on port 8080.
    app.run(host="0.0.0.0", port=8080)
