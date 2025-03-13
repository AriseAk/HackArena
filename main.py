# import os
# import io
# from flask import Flask, redirect, url_for, session, request, jsonify, render_template
# from authlib.integrations.flask_client import OAuth
# from dotenv import load_dotenv
# from flask import Flask, render_template, request, redirect, url_for, flash
# from werkzeug.utils import secure_filename
# from flask import send_from_directory
# from flask import Flask, request, render_template, redirect, url_for, flash, send_file
# from pymongo import MongoClient
# import gridfs
# from bson.objectid import ObjectId
# from io import BytesIO
# from flask import request, send_file
import os
import io
from flask import Flask, redirect, url_for, session, request, jsonify, render_template, flash, send_file
from authlib.integrations.flask_client import OAuth
from dotenv import load_dotenv
from werkzeug.utils import secure_filename
from pymongo import MongoClient
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash
from pymongo.errors import DuplicateKeyError
import gridfs
from bson.objectid import ObjectId


load_dotenv()  

flag=False

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
fu = client["file_uploads_db"]  # Database
fs = gridfs.GridFS(fu)
db = client['userinfo']
collection = db['users']
hosts=db['hosts']

collection.create_index("username", unique=True)
hosts.create_index("username", unique=True)

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

@app.route("/login",methods=["GET","POST"])
def login_page():
    if request.method=="POST":
        username=request.form.get("username")
        password=request.form.get("password")

        try:
            # Query the database to find the user
            user = collection.find_one({'username': username})

            if check_password_hash(user["hash"], password):  # Compare hashed passwords securely in practice
                # Store user info in session for a logged-in state
                session['username'] = username
                session['client'] = {
                    'name': user.get('name'),
                    'githubusername': user.get('githubusername'),
                    'linkedinusername': user.get('linkedinusername')
                }
                return redirect('/clienthome')  # Redirect to the dashboard or desired page
            else:
                flash("Invalid username or password!")
                return render_template("login.html")

        except Exception as e:
            flash("An unexpected error occurred: " + str(e))
            return render_template("login.html")
    else:
        return render_template("login.html")

@app.route("/register",methods=["GET","POST"])
def register_page():
    if request.method=="POST":
        username=request.form.get("username")
        password=request.form.get("password")
        confirm=request.form.get("confirm")
        print(username,password,confirm)
        if password != confirm:
            flash("Passwords do not match!")
            return render_template("register.html")

        hash = generate_password_hash(password)
        try:
            # Insert the user document into the collection
            collection.insert_one({'username': username, 'hash': hash})
            return redirect('/login')  # Redirect to the login page after successful registration
        except DuplicateKeyError:
            # Handle duplicate username case
            flash("Username has already been registered!")
            return render_template("register.html")
        except Exception as e:
            # Handle any other unexpected errors
            flash("An unexpected error occurred: " + str(e))
            return render_template("register.html")
    else:
        return render_template("register.html")

@app.route("/reghost",methods=["GET","POST"])
def reghost_page():
    if request.method=="POST":
        username=request.form.get("username")
        password=request.form.get("password")
        confirm=request.form.get("confirm")
        compname=request.form.get("compname")
        if password != confirm:
            flash("Passwords do not match!")
            return render_template("reghost.html")

        hash = generate_password_hash(password)
        try:
            # Insert the user document into the collection
            hosts.insert_one({'username': username, 'hash': hash, 'companyname':compname})
            return redirect('/loghost')  # Redirect to the login page after successful registration
        except DuplicateKeyError:
            # Handle duplicate username case
            flash("Username has already been registered!")
            return render_template("reghost.html")
        except Exception as e:
            # Handle any other unexpected errors
            flash("An unexpected error occurred: " + str(e))
            return render_template("reghost.html")
    else:
        return render_template("reghost.html")

@app.route("/loghost",methods=["GET","POST"])
def loghost_page():
    if request.method=="POST":
        username=request.form.get("username")
        password=request.form.get("password")

        try:
            # Query the database to find the user
            host = hosts.find_one({'username': username})

            if check_password_hash(host["hash"], password):  # Compare hashed passwords securely in practice
                # Store user info in session for a logged-in state
                session['username'] = username
                session['host'] = {
                    'name': host.get('name'),
                    'githubusername': host.get('githubusername'),
                    'linkedinusername': host.get('linkedinusername'),
                    'companyname': host.get('companyname')
                }
                return redirect('/hosthome')  # Redirect to the dashboard or desired page
            else:
                flash("Invalid username or password!")
                return render_template("hostlogin.html")

        except Exception as e:
            flash("An unexpected error occurred: " + str(e))
            return render_template("hostlogin.html")
    else:
        return render_template("hostlogin.html") 

@app.route("/hosthome",methods=["GET","POST"])
def hosthome_page():
    host = session.get('host')
    return render_template("host-home.html", host=host)  

@app.route("/clienthome",methods=["GET","POST"])
def clienthome_page():
    user = session.get('client')
    return render_template("index.html", user=user) 

@app.route("/client/auth/google")
def google_login():
    global flag
    flag=False
    redirect_uri = url_for("google_callback", _external=True)
    return google.authorize_redirect(redirect_uri)

@app.route("/host/auth/google")
def hgoogle_login():
    global flag
    flag=True
    redirect_uri = url_for("google_callback" ,_external=True)
    return google.authorize_redirect(redirect_uri)


@app.route("/auth/google/callback")
def google_callback():
    global flag
    if flag==False:
        token = google.authorize_access_token()
        user_info = google.get("https://www.googleapis.com/oauth2/v2/userinfo").json()
        session["user"] = user_info
        print(session["user"]['email'])
        user = collection.find_one({'username': session["user"]['email']})
        if not user:
            collection.insert_one({'username': session["user"]['email'],'name':session["user"]['name']})
        session['username'] = session["user"]['email']
        session['client']={
            'name': session["user"]['name']
        }
        return redirect('/clienthome') 
     
    else:
        token = google.authorize_access_token()
        user_info = google.get("https://www.googleapis.com/oauth2/v2/userinfo").json()
        session["user"] = user_info
        print(session["user"]['email'])
        host = hosts.find_one({'username': session["user"]['email']})
        if not host:
            hosts.insert_one({'username': session["user"]['email'],'name':session["user"]['name']})
        session['username'] = session["user"]['email']
        session['host']={
            'name':session["user"]['name']
        }
        print("Redirecting to:", url_for('hosthome_page'))
        return redirect('/hosthome')

@app.route("/client/auth/github")
def github_login():
    global flag
    flag=False
    return github.authorize_redirect(url_for("github_callback", _external=True))

@app.route("/host/auth/github")
def hgithub_login():
    global flag
    flag=True
    return github.authorize_redirect(url_for("github_callback", _external=True))

@app.route("/auth/github/callback")
def github_callback():
    global flag
    if flag==False:
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
        session['username']=session['user']['name']
        session['client']={
            'name':session['user']['email']
        }
        return redirect("/clienthome")
    
    else:
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
        session['username']=session['user']['name']
        session['host']={
            'name':session['user']['email']
        }
        return redirect("/hosthome")

@app.route("/logout")
def logout():
    session.clear()
    return redirect('/') 

@app.route("/client/edit", methods=["GET", "POST"])
def edit():
    if "username" not in session:
        flash("You need to be logged in to edit your profile!")
        return redirect(url_for("login_page"))

    if request.method == 'POST':
        name = request.form.get("name")
        gitusername = request.form.get("gitusername")
        linkedinusername = request.form.get("linkedinusername")
        print(name, gitusername, linkedinusername)

        try:
            # Update the existing document using session['username']
            collection.update_one(
                {"username": session['username']},
                {"$set": {
                    'name': name,
                    'githubusername': gitusername,
                    'linkedinusername': linkedinusername
                }}
            )
            session['client'] = {
                'name': name,
                'githubusername': gitusername,
                'linkedinusername': linkedinusername
            }
            flash("Profile updated successfully!")
            return redirect('/clienthome')
        except Exception as e:
            flash("An error occurred: " + str(e))
            return render_template("edit.html")

    else:
        # Pre-fill existing data if available
        user = collection.find_one({"username": session['username']})
        return render_template("edit.html")
    
@app.route("/host/edit", methods=["GET", "POST"])
def hedit():
    if "username" not in session:
        flash("You need to be logged in to edit your profile!")
        return redirect(url_for("loghost_page"))

    if request.method == 'POST':
        name = request.form.get("name")
        gitusername = request.form.get("gitusername")
        linkedinusername = request.form.get("linkedinusername")
        compname = request.form.get("compname")
        print(name, gitusername, linkedinusername, compname)

        # try:
            # Update the existing host document using session['username']
        hosts.update_one(
            {"username": session['username']},
            {"$set": {
                'name': name,
                'githubusername': gitusername,
                'linkedinusername': linkedinusername,
                'companyname': compname
            }}
        )
        session['host'] = {
                'name': name,
                'githubusername': gitusername,
                'linkedinusername': linkedinusername,
                'companyname': compname
            }
        flash("Host profile updated successfully!")
        return redirect('/hosthome')
        # except Exception as e:
        #     flash("An error occurred: " + str(e))
        #     return render_template("hedit.html")

    else:
        # Pre-fill existing data if available
        host = hosts.find_one({"username": session['username']})
        return render_template("hedit.html")

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
    file = fs.get(ObjectId(file_id))  
    return send_file(
        io.BytesIO(file.read()),
        mimetype=file.content_type, 
        download_name=file.filename 
    )

if __name__ == "__main__":
    app.run(debug=True)
