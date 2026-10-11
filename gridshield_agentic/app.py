
import hmac
import os
import secrets

from flask import (
    Flask,
    abort,
    redirect,
    render_template_string,
    request,
    session,
    url_for,
)
from dotenv import load_dotenv
from werkzeug.security import check_password_hash

load_dotenv(interpolate=False)

app = Flask(__name__)

secret_key = os.getenv("GRIDSHIELD_WEB_SECRET_KEY", "")
officer_username = os.getenv("GRIDSHIELD_OFFICER_USERNAME", "")
officer_password_hash = os.getenv("GRIDSHIELD_OFFICER_PASSWORD_HASH", "")

if not secret_key or not officer_username or not officer_password_hash:
    raise RuntimeError(
        "Configure GRIDSHIELD_WEB_SECRET_KEY, "
        "GRIDSHIELD_OFFICER_USERNAME, and "
        "GRIDSHIELD_OFFICER_PASSWORD_HASH in .env"
    )

app.secret_key = secret_key
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=(
        os.getenv("GRIDSHIELD_HTTPS_ONLY", "false").lower() == "true"
    ),
)

LOGIN_PAGE = """
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>GridShield Officer Login</title>
</head>
<body>
    <h1>GridShield</h1>
    <h2>Officer Login</h2>
    {% if error %}<p role="alert">{{ error }}</p>{% endif %}
    <form method="post">
        <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
        <label>
            Username
            <input name="username" required autocomplete="username">
        </label>
        <br><br>
        <label>
            Password
            <input type="password" name="password" required
                   autocomplete="current-password">
        </label>
        <br><br>
        <button type="submit">Log in</button>
    </form>
</body>
</html>
"""

DASHBOARD_PAGE = """
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>GridShield Officer Dashboard</title>
</head>
<body>
    <h1>GridShield Officer Dashboard</h1>
    <p>Authenticated officer: {{ username }}</p>
    <p>Login is working. The pending-approval queue will be connected next.</p>
    <form method="post" action="{{ url_for('logout') }}">
        <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
        <button type="submit">Log out</button>
    </form>
</body>
</html>
"""


def valid_csrf_token():
    supplied = request.form.get("csrf_token", "")
    expected = session.get("csrf_token", "")
    return bool(supplied and expected and hmac.compare_digest(supplied, expected))


@app.route("/", methods=["GET"])
def index():
    if session.get("officer_authenticated"):
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get("officer_authenticated"):
        return redirect(url_for("dashboard"))

    session.setdefault("csrf_token", secrets.token_urlsafe(32))
    error = None

    if request.method == "POST":
        if not valid_csrf_token():
            abort(400, description="Invalid CSRF token.")

        username = request.form.get("username", "")
        password = request.form.get("password", "")

        username_ok = hmac.compare_digest(username, officer_username)
        password_ok = check_password_hash(officer_password_hash, password)

        if username_ok and password_ok:
            session.clear()
            session["officer_authenticated"] = True
            session["officer_username"] = officer_username
            session["csrf_token"] = secrets.token_urlsafe(32)
            return redirect(url_for("dashboard"))

        error = "Invalid username or password."
        session["csrf_token"] = secrets.token_urlsafe(32)

    return render_template_string(
        LOGIN_PAGE,
        error=error,
        csrf_token=session["csrf_token"],
    )


@app.route("/dashboard", methods=["GET"])
def dashboard():
    if not session.get("officer_authenticated"):
        return redirect(url_for("login"))

    return render_template_string(
        DASHBOARD_PAGE,
        username=session.get("officer_username", ""),
        csrf_token=session["csrf_token"],
    )


@app.route("/logout", methods=["POST"])
def logout():
    if not session.get("officer_authenticated"):
        return redirect(url_for("login"))

    if not valid_csrf_token():
        abort(400, description="Invalid CSRF token.")

    session.clear()
    return redirect(url_for("login"))


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
