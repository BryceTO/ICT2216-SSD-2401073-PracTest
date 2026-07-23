"""
Integration / UI test over HTTP for the Q4 Flask app.
Run against a live instance: pytest tests/test_app.py
"""
import time
import requests

BASE_URL = "http://localhost:8000"


def wait_for_app(timeout=60):
    start = time.time()
    while time.time() - start < timeout:
        try:
            r = requests.get(BASE_URL + "/", timeout=3)
            if r.status_code == 200:
                return True
        except requests.exceptions.ConnectionError:
            pass
        time.sleep(2)
    raise RuntimeError("App did not become available in time")


def test_home_page_loads():
    wait_for_app()
    r = requests.get(BASE_URL + "/")
    assert r.status_code == 200
    assert "Login" in r.text


def test_weak_password_rejected():
    r = requests.post(
        BASE_URL + "/register",
        data={"username": "testuser1", "password": "password123"},
        allow_redirects=True,
    )
    assert "Login" in r.text  # bounced back to home page


def test_strong_password_creates_account():
    r = requests.post(
        BASE_URL + "/register",
        data={"username": "testuser2", "password": "Xk9$mQ2vLp7zUnique"},
        allow_redirects=True,
    )
    assert "Welcome" in r.text
