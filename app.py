from flask import Flask, jsonify, request
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from datetime import datetime, timezone, timedelta
import jwt
import base64
import sqlite3
import os

app = Flask(__name__)

# Database configuration
DB_FILE = "totally_not_my_privateKeys.db"

# ---------------------------
# Database initialization
# ---------------------------
def init_db():
    """Initialize the database with keys table if it doesn't exist."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    # Create keys table with proper schema as specified in requirements
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS keys(
            kid INTEGER PRIMARY KEY AUTOINCREMENT,
            key BLOB NOT NULL,
            exp INTEGER NOT NULL
        )
    """)
    
    conn.commit()
    conn.close()


def save_key_to_db(private_key_pem: bytes, expiration_timestamp: int) -> int:
    """
    Save a private key to the database using parameterized queries.
    Prevents SQL injection by using parameter binding.
    
    Args:
        private_key_pem: Private key in PEM format (bytes)
        expiration_timestamp: Unix timestamp when the key expires (int)
    
    Returns:
        kid: The key ID assigned by the database
    """
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    # Use parameterized query with ? placeholders to prevent SQL injection
    cursor.execute(
        "INSERT INTO keys (key, exp) VALUES (?, ?)",
        (private_key_pem, expiration_timestamp)
    )
    
    kid = cursor.lastrowid
    conn.commit()
    conn.close()
    
    return kid


def get_valid_key_from_db():
    """
    Retrieve a valid (unexpired) private key from the database.
    Uses parameterized query to prevent SQL injection.
    
    Returns:
        Dictionary with kid, private_key_pem, and exp, or None if no valid key exists
    """
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    now_timestamp = int(datetime.now(timezone.utc).timestamp())
    
    # Use parameterized query with ? placeholder to prevent SQL injection
    cursor.execute(
        "SELECT kid, key, exp FROM keys WHERE exp > ? LIMIT 1",
        (now_timestamp,)
    )
    
    result = cursor.fetchone()
    conn.close()
    
    if result:
        return {
            "kid": result[0],
            "private_key_pem": result[1],
            "exp": result[2]
        }
    
    return None


def get_expired_key_from_db():
    """
    Retrieve an expired private key from the database.
    Uses parameterized query to prevent SQL injection.
    
    Returns:
        Dictionary with kid, private_key_pem, and exp, or None if no expired key exists
    """
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    now_timestamp = int(datetime.now(timezone.utc).timestamp())
    
    # Use parameterized query with ? placeholder to prevent SQL injection
    cursor.execute(
        "SELECT kid, key, exp FROM keys WHERE exp <= ? LIMIT 1",
        (now_timestamp,)
    )
    
    result = cursor.fetchone()
    conn.close()
    
    if result:
        return {
            "kid": result[0],
            "private_key_pem": result[1],
            "exp": result[2]
        }
    
    return None


def get_all_valid_keys_from_db():
    """
    Retrieve all valid (unexpired) private keys from the database.
    Uses parameterized query to prevent SQL injection.
    
    Returns:
        List of dictionaries containing kid, private_key_pem, and exp
    """
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    now_timestamp = int(datetime.now(timezone.utc).timestamp())
    
    # Use parameterized query with ? placeholder to prevent SQL injection
    cursor.execute(
        "SELECT kid, key, exp FROM keys WHERE exp > ? ORDER BY kid",
        (now_timestamp,)
    )
    
    results = cursor.fetchall()
    conn.close()
    
    keys = []
    for result in results:
        keys.append({
            "kid": result[0],
            "private_key_pem": result[1],
            "exp": result[2]
        })
    
    return keys


# ---------------------------
# Utility functions
# ---------------------------
def long_to_base64url(n: int) -> str:
    """Convert a long integer to a base64url-encoded string without padding."""
    n_bytes = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(n_bytes).rstrip(b"=").decode("utf-8")


def generate_and_store_key_pair(expire_seconds: int):
    """
    Generate an RSA key pair and store the private key to the database.
    
    Args:
        expire_seconds: Number of seconds until the key expires
                       (negative value for already-expired keys)
    """
    # Generate RSA private key with standard parameters
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    
    # Serialize private key to PEM format (PKCS8)
    # This allows us to store the key as a BLOB in SQLite
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    # Calculate expiration timestamp
    expires_at = datetime.now(timezone.utc) + timedelta(seconds=expire_seconds)
    expiration_timestamp = int(expires_at.timestamp())
    
    # Save to database
    save_key_to_db(private_pem, expiration_timestamp)


# ---------------------------
# Initialize database and generate initial keys
# ---------------------------
def initialize_keys():
    """Initialize the database and generate default keys if not already present."""
    init_db()
    
    # Check if we already have keys
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM keys")
    key_count = cursor.fetchone()[0]
    conn.close()
    
    # If no keys exist, generate default ones
    if key_count == 0:
        # Generate one valid key (expires in 1 hour)
        generate_and_store_key_pair(expire_seconds=3600)
        # Generate one expired key (expired 1 hour ago)
        generate_and_store_key_pair(expire_seconds=-3600)


# Initialize keys on startup
initialize_keys()


# ---------------------------
# JWKS endpoint
# ---------------------------
@app.route("/.well-known/jwks.json")
def jwks():
    """
    JWKS (JSON Web Key Set) endpoint.
    Returns all valid (non-expired) public keys in JWKS format.
    
    Only returns keys where exp > current_time.
    """
    jwks_keys = []
    
    # Retrieve all valid keys from database
    valid_keys = get_all_valid_keys_from_db()
    
    for key_data in valid_keys:
        try:
            # Deserialize private key from PEM format (stored as BLOB)
            private_key = serialization.load_pem_private_key(
                key_data["private_key_pem"],
                password=None
            )
            public_key = private_key.public_key()
            
            # Extract RSA parameters
            numbers = public_key.public_numbers()
            
            # Build JWKS key entry
            jwks_keys.append({
                "kty": "RSA",
                "kid": str(key_data["kid"]),
                "use": "sig",
                "n": long_to_base64url(numbers.n),
                "e": long_to_base64url(numbers.e)
            })
        except Exception as e:
            # Log error but continue processing other keys
            app.logger.error(f"Error processing key {key_data['kid']}: {str(e)}")
    
    return jsonify({"keys": jwks_keys})


# ---------------------------
# Auth endpoint
# ---------------------------
@app.route("/auth", methods=["POST"])
def auth():
    """
    Authentication endpoint.
    Signs a JWT with a private key from the database.
    
    Query Parameters:
        expired: If present (value doesn't matter), use an expired key;
                otherwise use a valid key
    
    Returns:
        JSON with "jwt" field containing the signed token
    """
    # Check if expired query parameter is present
    expired = request.args.get("expired") is not None
    
    # Retrieve appropriate key from database
    if expired:
        key_data = get_expired_key_from_db()
    else:
        key_data = get_valid_key_from_db()
    
    if not key_data:
        return jsonify({"error": "no suitable key found"}), 500
    
    try:
        # Deserialize private key from PEM format (stored as BLOB)
        private_key = serialization.load_pem_private_key(
            key_data["private_key_pem"],
            password=None
        )
        
        # Create JWT payload
        now = datetime.now(timezone.utc)
        payload = {
            "sub": "fake_user",
            "iat": int(now.timestamp()),
            "exp": key_data["exp"]
        }
        
        # Sign JWT with private key using RS256 algorithm
        token = jwt.encode(
            payload,
            private_key,
            algorithm="RS256",
            headers={"kid": str(key_data["kid"])}
        )
        
        return jsonify({"jwt": token})
    
    except Exception as e:
        app.logger.error(f"Error signing JWT: {str(e)}")
        return jsonify({"error": "failed to sign JWT"}), 500


# ---------------------------
# Run server
# ---------------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)