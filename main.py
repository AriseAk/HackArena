import os
import io
from flask import Flask, redirect, url_for, session, request, render_template, flash, send_file, url_for
from authlib.integrations.flask_client import OAuth
from dotenv import load_dotenv
from pymongo import MongoClient
from werkzeug.security import check_password_hash, generate_password_hash
from pymongo.errors import DuplicateKeyError
from bson.objectid import ObjectId
from datetime import datetime, timezone
from slugify import slugify
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from bson import ObjectId
from gridfs import GridFSBucket
import io

load_dotenv()  

flag=False

app = Flask(__name__)

UPLOAD_FOLDER = "uploads"
ALLOWED_EXTENSIONS = {"py", "txt", "cpp", "java"} 

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024 

app.secret_key = os.getenv("SECRET_KEY")  

oauth = OAuth(app)

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

client = MongoClient(os.getenv("MONGO_CLIENT"))
db = client['userinfo']
collection = db['users']
hosts=db['hosts']
hi = client['hackinfo']
hic = hi['hackathoninfo'] #Hackathon information client
collection.create_index("username", unique=True)
hosts.create_index("username", unique=True)

google = oauth.register(
    name='google',
    client_id='YOUR_CLIENT_ID',
    client_secret='YOUR_CLIENT_SECRET',
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    access_token_url='https://accounts.google.com/o/oauth2/token',
    redirect_uri='https://hackarena.onrender.com/auth/google/callback',
    client_kwargs={'scope': 'openid email profile'}
)

github = oauth.register(
    name='github',
    client_id='YOUR_GITHUB_CLIENT_ID',
    client_secret='YOUR_GITHUB_CLIENT_SECRET',
    authorize_url='https://github.com/login/oauth/authorize',
    access_token_url='https://github.com/login/oauth/access_token',
    redirect_uri='https://hackarena.onrender.com/auth/github/callback',
    client_kwargs={'scope': 'user:email'}
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

@app.route("/hackathon/<hack_id>/upload", methods=["GET", "POST"])
def upload_file(hack_id):
    if request.method == "POST":
        hack = hic.find_one({'_id': ObjectId(hack_id)})
        if not hack:
            flash("Hackathon not found!")
            return redirect('/clienthome')

        if "file" not in request.files:
            flash("No file part")
            return redirect(request.url)
        
        teamname = request.form.get('teamname')
        file = request.files["file"]
        if file.filename == "":
            flash("No selected file")
            return redirect(request.url)
        
        add = client[slugify(hack['title'])]  # Database
        bucket = GridFSBucket(add, bucket_name=slugify(teamname))  # Use collection as bucket name

        # Save file to GridFSBucket
        file_id = bucket.upload_from_stream(file.filename, file)

        flash(f"File '{file.filename}' uploaded successfully!")
        return redirect(url_for("list_files", hack_id=hack_id, teamname=teamname))
    else:
        hack = hic.find_one({'_id': ObjectId(hack_id)})
        return render_template("upload.html", hack=hack)

@app.route("/hackathon/<hack_id>/<teamname>/files",methods=['POST','GET'])
def list_files(hack_id,teamname):
    hack = hic.find_one({'_id': ObjectId(hack_id)})
    # teamname = request.args.get('teamname')
    if not teamname:
        flash("Teamname is required!")
        return redirect(url_for('upload_file', hack_id=hack_id))

    add = client[slugify(hack['title'])]
    bucket = GridFSBucket(add, bucket_name=slugify(teamname))

    # List files using .find()
    files = add[f"{slugify(teamname)}.files"].find()

    return render_template("files.html", hack=hack, teamname=teamname, files=[
        {"filename": f['filename'], "id": str(f['_id'])} for f in files
    ])

@app.route("/hackathon/<hack_id>/<teamname>/<file_id>")
def serve_file(hack_id, teamname, file_id):
    hack = hic.find_one({'_id': ObjectId(hack_id)})
    if not hack:
        flash("Hackathon not found!")
        return redirect('/clienthome')

    add = client[slugify(hack['title'])]
    bucket = GridFSBucket(add, bucket_name=slugify(teamname))

    file = bucket.open_download_stream(ObjectId(file_id))
    return send_file(
        io.BytesIO(file.read()),
        mimetype=file.content_type if hasattr(file, 'content_type') else 'application/octet-stream',
        download_name=file.filename
    )

@app.route("/host/<hack_id>/files", methods=["POST", "GET"])
def hlist_files(hack_id):
    hack = hic.find_one({'_id': ObjectId(hack_id)})
    if not hack:
        flash("Hackathon not found!")
        return redirect('/clienthome')

    add = client[slugify(hack['title'])]
    # Get all team collections under the database
    team_names = [col.replace(".files", "") for col in add.list_collection_names() if col.endswith(".files")]
    team_files = {}
    for team in team_names:
        bucket = GridFSBucket(add, bucket_name=team)
        files = add[f"{team}.files"].find()
        team_files[team] = [{"filename": f["filename"], "id": str(f["_id"])} for f in files]
    return render_template("hfiles.html", hack=hack, team_files=team_files)

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

@app.route('/host/<hack_id>', methods=["GET", "POST"])
def hhackathon_details(hack_id):
    hack = hic.find_one({'_id': ObjectId(hack_id)})
    if not hack:
        flash("Hackathon not found!")
        return redirect('/hosthome')
    reg=0
    add = client[slugify(hack['title'])]
    helper = add['hackinfo']
    reg=helper.count_documents({})*int(hack['team-size'])
    today = datetime.now(timezone.utc)
    rdate = hack.get('rdate')
    today = today.replace(tzinfo=None)
    days_remaining = (rdate - today).days if rdate else None
    hack['_id'] = str(hack['_id'])
    return render_template("host-details.html", hack=hack, days_remaining=days_remaining,reg=reg)

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

@app.route("/hackathon/<hack_id>/find", methods=["GET", "POST"])
def find_team(hack_id):
    hack = hic.find_one({'_id': ObjectId(hack_id)})
    if not hack:
        flash("Hackathon not found!")
        return redirect('/clienthome')
    add = client[slugify(hack['title'])]
    helper = add['findingteam']
    helper.insert_one({'username':session['username']})
    return redirect(url_for('find', hack_id=hack_id))

@app.route("/hackathon/<hack_id>/team", methods=["GET", "POST"])
def find(hack_id):
    hack = hic.find_one({'_id': ObjectId(hack_id)})
    if not hack:
        flash("Hackathon not found!")
        return redirect('/clienthome')
    add = client[slugify(hack['title'])]
    helper = add['findingteam']
    name=request.form.get("name")
    about=request.form.get("about")
    helper.update_one(
                {"username": session['username']},
                {"$set": {
                    'name':name,
                    'about':about,
                    'email':session['client']['email']
                }}
            )
    people=helper.find({"username": {"$ne": session['username']}})
    return render_template("find.html",hack=hack,people=people)

@app.route("/<hack_id>/<sender>/email", methods=["GET", "POST"])
def send(hack_id,sender):
    # try:
    hack = hic.find_one({'_id': ObjectId(hack_id)})
    if not hack:
        flash("Hackathon not found!")
        return redirect('/clienthome')
    add = client[slugify(hack['title'])]
    helper = add['findingteam']
    send=helper.find_one({'_id':ObjectId(sender)})
    semail=send['email']
    sname=send['name']
    remail=session['client']['email']
    rname=session['client']['name']
    SMTP_SERVER = "smtp.gmail.com"
    SMTP_PORT = 587
    SENDER_EMAIL = os.getenv("EMAIL_USER")  # Your email (set in .env)
    SENDER_PASSWORD = os.getenv("EMAIL_PASSWORD")  # Your app password (set in .env)
    subject = "Hackathon Team Request Notification"
    # Message to sender (sending recipient's details)
    body_to_sender = f"""
Hi {sname},

You have been requested from {rname} for the hackathon '{hack['title']}'.

Here are their details:
- Name: {rname}
- Email: {remail}

Good luck!
    """

    # Message to recipient (sending sender's details)
    body_to_recipient = f"""
Hi {rname},

You have sent request to {sname} for the hackathon '{hack['title']}'.

Here are their details:
- Name: {sname}
- Email: {semail}

Good luck!
    """
    # Send email to sender
    send_email(SENDER_EMAIL, SENDER_PASSWORD, SMTP_SERVER, SMTP_PORT, semail, subject, body_to_sender)
    
    # Send email to recipient
    send_email(SENDER_EMAIL, SENDER_PASSWORD, SMTP_SERVER, SMTP_PORT, remail, subject, body_to_recipient)

    flash("Emails sent successfully!")
    return redirect(url_for('find', hack_id=hack_id))


# Function to send an email
def send_email(sender_email, sender_password, smtp_server, smtp_port, recipient_email, subject, body):
    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = recipient_email
    msg['Subject'] = subject

    msg.attach(MIMEText(body, 'plain'))

    # Connect to the SMTP server
    with smtplib.SMTP(smtp_server, smtp_port) as server:
        server.starttls()  # Upgrade to secure connection
        server.login(sender_email, sender_password)
        server.sendmail(sender_email, recipient_email, msg.as_string())

if __name__ == "__main__":
    app.run(debug=True)
