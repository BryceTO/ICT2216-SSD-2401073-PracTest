"""
Integration / UI test over HTTP for the Q4 Flask app.
Run against a live instance: pytest tests/test_app.py
"""
import re
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


def get_csrf_token(session, path="/register"):
    r = session.get(BASE_URL + path)
    match = re.search(r'name="csrf_token" value="([^"]+)"', r.text)
    assert match, "CSRF token not found on page"
    return match.group(1)


def test_home_page_loads():
    wait_for_app()
    r = requests.get(BASE_URL + "/")
    assert r.status_code == 200
    assert "Login" in r.text


def test_weak_password_rejected():
    session = requests.Session()
    token = get_csrf_token(session)
    r = session.post(
        BASE_URL + "/register",
        data={"username": "testuser1", "password": "password123", "csrf_token": token},
    )
    assert "Login" in r.text  # bounced back to home page


def test_strong_password_creates_account():
    session = requests.Session()
    token = get_csrf_token(session)
    r = session.post(
        BASE_URL + "/register",
        data={
            "username": "testuser2",
            "password": "Xk9$mQ2vLp7zUnique",
            "csrf_token": token,
        },
    )
    assert "Welcome" in r.text
