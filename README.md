
# 🚀 **HackArena**  

HackArena is a platform designed to **host and manage hackathons** effortlessly. Inspired by the DevNovate track from the **Build with India Hackathon**, HackArena allows organizers to create and manage hackathons, while participants can register, form teams, upload project files, and track progress in real time.  

---

## 🌟 **Features**  
✅ **Host Hackathons** – Create and manage hackathons with flexible settings.  
✅ **Team Registration** – Allow participants to register, form teams, and manage members.  
✅ **File Upload & Retrieval** – Secure file upload using **MongoDB GridFS**.  
✅ **OAuth Login** – Login with Google using OAuth for easy authentication.  
✅ **Profile Management** – Display participant profiles and allow team discovery.  
✅ **Secure & Scalable** – Built with Flask and MongoDB for a scalable backend.  

---

## 🏗️ **Tech Stack**  
- **Backend:** Flask, MongoDB (GridFS)  
- **Frontend:** HTML, CSS (Jinja Templates)  
- **Authentication:** OAuth (Google)  
- **Hosting:** Render  

---

## 🚀 **Getting Started**  

### **1. Clone the Repository**  
```bash
git clone https://github.com/AriseAk/HackArena.git
cd hackarena
```

---

### **2. Create a Virtual Environment**  
```bash
python -m venv venv
source venv/bin/activate  # On Linux/macOS
# On Windows:
venv\Scripts\activate
```

---

### **3. Install Dependencies**  
```bash
pip install -r requirements.txt
```

---

### **4. Set Up Environment Variables**  
Create a `.env` file in the root directory and add:

```plaintext
MONGO_URI=mongodb+srv://your-mongo-uri
SECRET_KEY=your-secret-key
OAUTH_CLIENT_ID=your-client-id
OAUTH_CLIENT_SECRET=your-client-secret
EMAIL_USER=your-email@gmail.com
EMAIL_PASS=your-email-password
```

---

### **5. Run the Flask App**  
Run the app locally:  

```bash
python app.py
```

or use Gunicorn:  

```bash
gunicorn app:app
```

---

### **6. Open in Browser**  
Open your browser and go to:  

```
http://localhost:5000
```

---

## 🌍 **Deploy on Render**  

### **1. Create a GitHub Repository**  
Push your project to GitHub:

```bash
git init
git add .
git commit -m "Initial commit"
git branch -M main
git remote add origin https://github.com/yourusername/hackarena.git
git push -u origin main
```

---

### **2. Deploy on Render**  
- Go to [Render](https://render.com)  
- Create a new **Web Service**  
- Connect your GitHub repository  

---

### **3. Set Configuration**  
- **Build Command:**  
```bash
pip install -r requirements.txt
```
- **Start Command:**  
```bash
gunicorn app:app
```
- **Environment Variables:**  
Set the environment variables in Render settings.  

---

### **4. Flask Port Binding**  
Ensure Flask binds to the correct port in `app.py`:  

```python
port = int(os.getenv("PORT", 5000))
app.run(host="0.0.0.0", port=port)
```

---

## 📂 **Folder Structure**  
```
📂 hackarena
├── 📂 templates
├── 📂 static
├── 📄 app.py
├── 📄 requirements.txt
├── 📄 .env
├── 📄 Procfile
└── 📄 README.md
```

---

## 🛠️ **Endpoints**  

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET    | `/`       | Home page |
| GET/POST | `/login` | OAuth login with Google |
| GET/POST | `/hackathon/<hack_id>` | View hackathon details |
| POST   | `/hackathon/<hack_id>/register` | Register a team |
| GET    | `/profile/<user_id>` | View user profile |
| POST   | `/upload/<hack_id>/<teamname>` | Upload project file |
| GET    | `/download/<hack_id>/<teamname>/<file_id>` | Download project file |

---

## 💡 **How It Works**  
1. Organizers create a hackathon.  
2. Participants register and create teams.  
3. Teams can upload files and track progress.  
4. All data is securely stored in MongoDB (GridFS).  
5. OAuth ensures quick and secure login.  

---

## 🚀 **Future Plans**  
- ✅ Real-time chat for team members  
- ✅ Improved search and filtering for hackathons  
- ✅ Integration with GitHub for project tracking  

---

## 🤝 **Contributing**  
Feel free to fork the repository and create a pull request!  

1. Fork it  
2. Create your feature branch (`git checkout -b feature/awesome-feature`)  
3. Commit your changes (`git commit -m "Add some feature"`)  
4. Push to the branch (`git push origin feature/awesome-feature`)  
5. Create a new pull request  

---

## 🏆 **Credits**  
- Built by the HackArena team  
- Inspired by DevNovate and Build with India Hackathon
  
---

## 🌐 **Live Demo**  
👉 [https://hackarena.onrender.com](https://hackarena.onrender.com)  

---

🔥 **HackArena – Empowering the next generation of developers!** 😎  
