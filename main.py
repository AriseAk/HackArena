import os
import io
from flask import Flask, redirect, url_for, session, request, jsonify, render_template
from authlib.integrations.flask_client import OAuth
from dotenv import load_dotenv
from flask import Flask, render_template, request, redirect, url_for, flash
from werkzeug.utils import secure_filename
from flask import send_from_directory
from flask import Flask, request, render_template, redirect, url_for, flash, send_file
from pymongo import MongoClient
import gridfs
from bson.objectid import ObjectId
from io import BytesIO
from flask import request, send_file

load_dotenv()  

app = Flask(__name__)

UPLOAD_FOLDER = "uploads"
ALLOWED_EXTENSIONS = {"py", "txt", "cpp", "java"} 

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024  
app.secret_key = os.getenv("SECRET_KEY")  
print(f"Secret Key: {app.secret_key}")

oauth = OAuth(app)

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

client = MongoClient(os.getenv("MONGO_CLIENT"))
db = client["file_uploads_db"]  # Database
fs = gridfs.GridFS(db)

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


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route("/upload", methods=["GET", "POST"])
def upload_file():
    if request.method == "POST":
        if "file" not in request.files:
            flash("No file part")
            return redirect(request.url)
        
        file = request.files["file"]
        if file.filename == "":
            flash("No selected file")
            return redirect(request.url)

        # Save file to MongoDB GridFS
        file_id = fs.put(file.read(), filename=file.filename)

        flash(f"File '{file.filename}' uploaded successfully!")
        return redirect(url_for("list_files"))

    return render_template("upload.html")

@app.route("/files")
def list_files():
    files = fs.find()
    return render_template("files.html", files=[{"filename": f.filename, "id": str(f._id)} for f in files])

# @app.route("/file/<file_id>")
# def serve_file(file_id):
#     """Serve a file with an option to view or download."""
#     file = fs.get(ObjectId(file_id))  # Retrieve file from MongoDB GridFS
#     file_data = file.read()
#     mimetype = file.content_type or "application/octet-stream"

#     if request.args.get("download") == "true":
#         return send_file(
#             io.BytesIO(file_data),
#             mimetype=mimetype,
#             as_attachment=True,  # Forces download
#             download_name=file.filename
#         )

#     return send_file(
#         io.BytesIO(file_data),
#         mimetype=mimetype,  # Open in browser if supported
#         download_name=file.filename
#     )

@app.route("/file/<file_id>")
def serve_file(file_id):
    """Serve a file directly in the browser if supported."""
    file = fs.get(ObjectId(file_id))  # Retrieve file from MongoDB GridFS
    return send_file(
        io.BytesIO(file.read()),
        mimetype=file.content_type,  # Ensure the correct MIME type
        download_name=file.filename  # Necessary for some browsers
    )



if __name__ == "__main__":
    app.run(debug=True)
