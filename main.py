import os
import io
from flask import Flask, redirect, url_for, session, request, jsonify, render_template, flash, send_file
from authlib.integrations.flask_client import OAuth
from dotenv import load_dotenv
from werkzeug.utils import secure_filename
from pymongo import MongoClient
from werkzeug.security import check_password_hash, generate_password_hash
from pymongo.errors import DuplicateKeyError
import gridfs
from bson.objectid import ObjectId
from datetime import datetime, timezone
from slugify import slugify


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
hi = client['hackinfo']
hic = hi['hackathoninfo'] #Hackathon information client

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
                    'gitusername': user.get('gitusername'),
                    'email': user.get('email')
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
                    'gitusername': host.get('githubusername'),
                    'email': host.get('email'),
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
 
@app.route("/hosthome", methods=["GET", "POST"])
def hosthome_page():
    host = session.get('host')
    if host:
        hackathons = hic.find({'username': host['email']})  # Fetch hackathons created by the logged-in host
        hacks = [
            {
                'id': str(hack['_id']),  
                'title': hack['title'],
                'date': hack['date'],
                'duration': hack['duration']
            }
            for hack in hackathons
        ]
        return render_template("host-home.html", host=host, hacks=hacks)
    return redirect('/loghost')

@app.route("/clienthome", methods=["GET", "POST"])
def clienthome_page():
    user = session.get('client')
    if user:
        today = datetime.now(timezone.utc)
        hackathons = hic.find({'rdate': {'$gte': today}})

        hacks = [
            {
                'id': str(hack['_id']),  # Pass the _id to the template
                'title': hack.get('title'),
                'date': hack.get('date'),
                'duration': hack.get('duration')
            }
            for hack in hackathons
        ]

        return render_template("index.html", user=user, hacks=hacks)
    return redirect('/login')

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
            'name': session["user"]['name'],
            'email':session["user"]['email']
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
            'name':session["user"]['name'],
            'email':session["user"]['email']
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
        session['username']=session['user']['email']
        session['client']={
            'name':session['user']['name'],
            'email':session["user"]['email']
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
        session['username']=session['user']['email']
        session['host']={
            'name':session['user']['email'],
            'email':session["user"]['email']
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
        email = request.form.get("email")
        print(name, gitusername, email)

        try:
            # Update the existing document using session['username']
            collection.update_one(
                {"username": session['username']},
                {"$set": {
                    'name': name,
                    'gitusername': gitusername,
                    'email': email
                }}
            )
            session['client'] = {
                'name': name,
                'gitusername': gitusername,
                'email': email
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
        email = request.form.get("email")
        compname = request.form.get("compname")
        print(name, gitusername, email, compname)

        # try:
            # Update the existing host document using session['username']
        hosts.update_one(
            {"username": session['username']},
            {"$set": {
                'name': name,
                'gitusername': gitusername,
                'email': email,
                'companyname': compname
            }}
        )
        session['host'] = {
                'name': name,
                'gitusername': gitusername,
                'email': email,
                'companyname': compname
            }
        flash("Host profile updated successfully!")
        return redirect('/hosthome')
    
    else:
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

@app.route("/host/add/hack", methods=["POST", "GET"])
def addhack():
    if request.method == 'POST':
        title = request.form.get("title")
        mode = request.form.get("mode")
        date = request.form.get("date")
        duration = request.form.get("duration")
        teamsize = request.form.get("team-size")
        rdate = request.form.get("rdate")
        prize = request.form.get("prize")
        username = session['host']['email']

        hic.insert_one({
            'username': username, 
            'title': title,
            'mode': mode,
            'date': date,
            'duration': duration,
            'team-size': teamsize,
            'rdate': datetime.strptime(rdate, '%Y-%m-%d'), # Ensure rdate is stored as datetime
            'prize': prize
        })

        return redirect('/hosthome')
    else:
        return render_template("hackathon-details.html")
    
@app.route("/hackathon/<hack_id>", methods=["GET", "POST"])
def hackathon_details(hack_id):
    hack = hic.find_one({'_id': ObjectId(hack_id)})
    if not hack:
        flash("Hackathon not found!")
        return redirect('/clienthome')
    reg=0
    add = client[slugify(hack['title'])]
    helper = add['hackinfo']
    reg=helper.count_documents({})*int(hack['team-size'])
    today = datetime.now(timezone.utc)
    rdate = hack.get('rdate')
    today = today.replace(tzinfo=None)
    days_remaining = (rdate - today).days if rdate else None
    hack['_id'] = str(hack['_id'])
    return render_template("hackathon-user.html", hack=hack, days_remaining=days_remaining,reg=reg)

@app.route("/hackathon/<hack_id>/reg", methods=["GET", "POST"])
def team_reg(hack_id):
    if request.method == "POST":
        hack = hic.find_one({'_id': ObjectId(hack_id)})
        add = client[slugify(hack['title'])]
        helper = add['hackinfo']
        
        helper.create_index("teamname", unique=True)

        teamname = request.form.get('team_name')
        
        try:
            helper.insert_one({'teamname': teamname})
        except DuplicateKeyError:
            return "Error: Team name already exists. Please choose a different one."

        for i in range(1, int(hack['team-size']) + 1):
            member_name = request.form.get(f'member_name_{i}')
            member_email = request.form.get(f'member_email_{i}')
            
            helper.update_one(
                {"teamname": teamname},
                {"$set": {
                    f'member{i}': {
                        'name': member_name,
                        'email': member_email
                    }
                }}
            )
        
        return redirect("/clienthome")
    else:
        hack = hic.find_one({'_id': ObjectId(hack_id)})
        return render_template("teams.html",hack=hack)


if __name__ == "__main__":
    app.run(debug=True)
