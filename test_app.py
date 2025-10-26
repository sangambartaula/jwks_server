import pytest
import jwt
import json
from app import app, DB_FILE, initialize_keys
import os
import sqlite3

@pytest.fixture
def client():
    """Create a test client for the Flask app."""
    app.config['TESTING'] = True
    
    # Clean up before test
    if os.path.exists(DB_FILE):
        os.remove(DB_FILE)
    
    # Initialize fresh database for this test
    initialize_keys()
    
    with app.test_client() as test_client:
        yield test_client
    
    # Clean up after test
    if os.path.exists(DB_FILE):
        os.remove(DB_FILE)

def test_jwks_endpoint(client):
    """Test that JWKS endpoint returns valid keys."""
    resp = client.get("/.well-known/jwks.json")
    assert resp.status_code == 200
    data = resp.json
    assert "keys" in data
    assert len(data["keys"]) >= 1
    
    # Verify kid is a string representation of an integer (from database)
    kid = data["keys"][0]["kid"]
    assert isinstance(kid, str)
    assert kid.isdigit()
    
    # Verify all required JWKS fields are present
    for key in data["keys"]:
        assert "kty" in key
        assert key["kty"] == "RSA"
        assert "kid" in key
        assert "use" in key
        assert key["use"] == "sig"
        assert "n" in key
        assert "e" in key

def test_jwks_only_returns_valid_keys(client):
    """Test that JWKS endpoint only returns non-expired keys."""
    resp = client.get("/.well-known/jwks.json")
    assert resp.status_code == 200
    data = resp.json
    
    # Should have at least 1 valid key (the one that expires in 1 hour)
    assert len(data["keys"]) >= 1
    
    # All returned kids should be string integers from database
    for key in data["keys"]:
        assert key["kid"].isdigit()

def test_auth_valid(client):
    """Test authentication endpoint with valid (non-expired) key."""
    resp = client.post("/auth")
    assert resp.status_code == 200
    data = resp.json
    assert "jwt" in data
    
    # Verify JWT structure (3 parts separated by dots)
    token = data["jwt"]
    assert isinstance(token, str)
    assert token.count('.') == 2

def test_auth_expired(client):
    """Test authentication endpoint with expired key."""
    resp = client.post("/auth?expired=true")
    assert resp.status_code == 200
    data = resp.json
    assert "jwt" in data
    
    # Verify JWT structure
    token = data["jwt"]
    assert isinstance(token, str)
    assert token.count('.') == 2

def test_jwt_payload_valid(client):
    """Test that JWT payload contains expected claims."""
    resp = client.post("/auth")
    assert resp.status_code == 200
    token = resp.json["jwt"]
    
    # Decode JWT without verification
    decoded = jwt.decode(token, options={"verify_signature": False})
    
    # Verify payload contains expected claims
    assert "sub" in decoded
    assert decoded["sub"] == "fake_user"
    assert "iat" in decoded
    assert "exp" in decoded
    assert isinstance(decoded["iat"], int)
    assert isinstance(decoded["exp"], int)

def test_jwt_verification_with_jwks(client):
    """Test that JWT from /auth can be verified with public key from JWKS."""
    # Get valid JWT
    auth_resp = client.post("/auth")
    assert auth_resp.status_code == 200
    token = auth_resp.json["jwt"]
    
    # Get JWKS
    jwks_resp = client.get("/.well-known/jwks.json")
    assert jwks_resp.status_code == 200
    jwks_data = jwks_resp.json
    
    # Extract kid from JWT header
    token_header = jwt.get_unverified_header(token)
    token_kid = token_header.get("kid")
    assert token_kid is not None
    
    # Find matching key in JWKS
    matching_key = None
    for key in jwks_data["keys"]:
        if key["kid"] == token_kid:
            matching_key = key
            break
    
    assert matching_key is not None, f"No key found in JWKS for kid {token_kid}"
    
    # Reconstruct public key from JWKS
    from app import long_to_base64url
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.backends import default_backend
    import base64
    
    # Decode base64url values
    def base64url_to_int(value):
        """Convert base64url string to integer."""
        padding = 4 - len(value) % 4
        if padding != 4:
            value += "=" * padding
        decoded = base64.urlsafe_b64decode(value)
        return int.from_bytes(decoded, byteorder='big')
    
    n = base64url_to_int(matching_key["n"])
    e = base64url_to_int(matching_key["e"])
    
    public_numbers = rsa.RSAPublicNumbers(e, n)
    public_key = public_numbers.public_key(default_backend())
    
    # Verify JWT signature
    decoded = jwt.decode(token, public_key, algorithms=["RS256"])
    assert decoded["sub"] == "fake_user"

def test_auth_uses_different_keys(client):
    """Test that valid auth and expired auth use different keys."""
    # Get valid JWT
    valid_resp = client.post("/auth")
    valid_token = valid_resp.json["jwt"]
    valid_header = jwt.get_unverified_header(valid_token)
    valid_kid = valid_header.get("kid")
    
    # Get expired JWT
    expired_resp = client.post("/auth?expired=true")
    expired_token = expired_resp.json["jwt"]
    expired_header = jwt.get_unverified_header(expired_token)
    expired_kid = expired_header.get("kid")
    
    # They should have different kids (different keys from database)
    assert valid_kid != expired_kid

def test_multiple_jwks_calls_consistent(client):
    """Test that JWKS endpoint returns consistent data on multiple calls."""
    resp1 = client.get("/.well-known/jwks.json")
    data1 = resp1.json
    
    resp2 = client.get("/.well-known/jwks.json")
    data2 = resp2.json
    
    # Should have the same number of keys
    assert len(data1["keys"]) == len(data2["keys"])
    
    # Keys should be identical
    for key1, key2 in zip(data1["keys"], data2["keys"]):
        assert key1["kid"] == key2["kid"]
        assert key1["n"] == key2["n"]
        assert key1["e"] == key2["e"]

def test_database_persistence(client):
    """Test that keys are stored in the database."""
    # Make a request to initialize database
    resp = client.get("/.well-known/jwks.json")
    assert resp.status_code == 200
    
    # Check that database file exists
    assert os.path.exists(DB_FILE), "Database file should exist"
    
    # Verify database has keys
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM keys")
    key_count = cursor.fetchone()[0]
    conn.close()
    
    assert key_count >= 2, "Database should have at least 2 keys (1 valid, 1 expired)"