import os
from flask import Flask, redirect, url_for, session, request, jsonify, render_template
from authlib.integrations.flask_client import OAuth
from dotenv import load_dotenv

load_dotenv()  # Load environment variables from .env file

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")  # Load from environment
print(f"Secret Key: {app.secret_key}")

oauth = OAuth(app)

google = oauth.register(
    name="google",
    client_id=os.getenv("GOOGLE_CLIENT_ID"),
    client_secret=os.getenv("GOOGLE_CLIENT_SECRET"),
    authorize_url="https://accounts.google.com/o/oauth2/auth",
    access_token_url="https://oauth2.googleapis.com/token",
    userinfo_endpoint="https://www.googleapis.com/oauth2/v3/userinfo",
    client_kwargs={"scope": "openid email profile"},
    server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
)

github = oauth.register(
    name="github",
    client_id=os.getenv("GITHUB_CLIENT_ID"),
    client_secret=os.getenv("GITHUB_CLIENT_SECRET"),
    authorize_url="https://github.com/login/oauth/authorize",
    access_token_url="https://github.com/login/oauth/access_token",
    api_base_url="https://api.github.com/",
    client_kwargs={"scope": "user:email"},
)


@app.route("/")
def home():
    return render_template("home.html")

@app.route("/login")
def login_page():
    return render_template("login.html")

@app.route("/register")
def register_page():
    return render_template("register.html")

@app.route("/reghost")
def reghost_page():
    return render_template("reghost.html")

@app.route("/loghost")
def loghost_page():
    return render_template("hostlogin.html")  

@app.route("/hosthome")
def hosthome_page():
    return render_template("host-home.html") 

@app.route("/clienthome")
def clienthome_page():
    return render_template("index.html") 

@app.route("/auth/google")
def google_login():
    redirect_uri = url_for("google_callback", _external=True)
    return google.authorize_redirect(redirect_uri)


@app.route("/auth/google/callback")
def google_callback():
    token = google.authorize_access_token()
    user_info = google.get("https://www.googleapis.com/oauth2/v2/userinfo").json()
    session["user"] = user_info
    return redirect(url_for("hosthome_page"))  

@app.route("/auth/github")
def github_login():
    return github.authorize_redirect(url_for("github_callback", _external=True))

@app.route("/auth/github/callback")
def github_callback():
    token = github.authorize_access_token()
    user_info = github.get("user").json()

    # GitHub does not always return an email, so request it separately
    email = user_info.get("email")
    if not email:
        emails = github.get("user/emails").json()
        email = next((e["email"] for e in emails if e["primary"]), None)

    # Store user info in session
    session["user"] = {
        "id": user_info["id"],
        "name": user_info["name"],
        "email": email,
        "picture": user_info.get("avatar_url"),
    }

    return redirect(url_for("hosthome_page"))

if __name__ == "__main__":
    app.run(debug=True)
