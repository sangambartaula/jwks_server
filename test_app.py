import pytest
import requests
from threading import Thread
from app import app
import time

# Run the Flask app in a background thread for testing
@pytest.fixture(scope="module", autouse=True)
def start_server():
    thread = Thread(target=lambda: app.run(port=8080))
    thread.daemon = True
    thread.start()
    time.sleep(1)  # wait a moment for server to start
    yield
    # No need to stop Flask; it will exit when tests are done

def test_jwks_endpoint():
    resp = requests.get("http://127.0.0.1:8080/.well-known/jwks.json")
    assert resp.status_code == 200
    data = resp.json()
    assert "keys" in data
    assert len(data["keys"]) >= 1
    assert "kid" in data["keys"][0]

def test_auth_valid():
    resp = requests.post("http://127.0.0.1:8080/auth")
    assert resp.status_code == 200
    data = resp.json()
    assert "jwt" in data

def test_auth_expired():
    resp = requests.post("http://127.0.0.1:8080/auth?expired=true")
    assert resp.status_code == 200
    data = resp.json()
    assert "jwt" in data
