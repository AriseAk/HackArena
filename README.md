# HackArena

A platform for hosting and managing hackathons — built for organizers and participants alike.

---

## Overview

HackArena lets organizers create hackathons with custom settings, while participants can register, form or find teams, upload project files, and track submission deadlines. Inspired by the DevNovate track from the Build with India Hackathon.

Live demo: [hackarena.onrender.com](https://hackarena.onrender.com)

---

## Features

- **Hackathon management** — Create and configure hackathons with mode, duration, team size, prize pool, and registration deadlines
- **Team registration** — Register with an existing team or use the team-finder to connect with other participants
- **File uploads** — Submit project files securely via MongoDB GridFS, viewable per team
- **OAuth login** — Sign in with Google or GitHub; no passwords required
- **Dual roles** — Separate flows for hosts (organizers) and clients (participants)
- **Email notifications** — Sends connection requests between participants looking for teammates

---

## Tech Stack

| Layer | Technology |
|---|---|
| Backend | Flask (Python) |
| Database | MongoDB + GridFS |
| Auth | OAuth 2.0 (Google, GitHub) via Authlib |
| Templates | Jinja2 + HTML/CSS |
| Hosting | Render |

---

## Getting Started

### Prerequisites

- Python 3.8+
- A MongoDB Atlas cluster
- Google and/or GitHub OAuth credentials

### Installation

```bash
# Clone the repo
git clone https://github.com/AriseAk/HackArena.git
cd hackarena

# Create and activate a virtual environment
python -m venv venv
source venv/bin/activate      # macOS/Linux
# venv\Scripts\activate       # Windows

# Install dependencies
pip install -r requirements.txt
```

### Environment Variables

Create a `.env` file in the project root:

```env
MONGO_CLIENT=mongodb+srv://your-mongo-uri
SECRET_KEY=your-secret-key

GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret

GITHUB_CLIENT_ID=your-github-client-id
GITHUB_CLIENT_SECRET=your-github-client-secret

EMAIL_USER=your-email@gmail.com
EMAIL_PASSWORD=your-app-password
```

### Run Locally

```bash
python main.py
```

Visit `http://localhost:5000` in your browser.

---

## Deployment (Render)

1. Push your project to GitHub
2. Create a new **Web Service** on [Render](https://render.com) and connect the repository
3. Set the following:

| Setting | Value |
|---|---|
| Build Command | `pip install -r requirements.txt` |
| Start Command | `gunicorn main:app` |

4. Add your environment variables in the Render dashboard
5. Ensure Flask binds to the correct port in `main.py`:

```python
port = int(os.getenv("PORT", 5000))
app.run(host="0.0.0.0", port=port)
```

---

## Project Structure

```
hackarena/
├── templates/          # Jinja2 HTML templates
├── static/             # CSS and static assets
├── main.py             # Application entry point and routes
├── requirements.txt
├── .env                # Environment variables (not committed)
├── Procfile
└── README.md
```

---

## API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| GET | `/` | Home page |
| GET/POST | `/login` | Participant login |
| GET/POST | `/register` | Participant registration |
| GET/POST | `/loghost` | Host login |
| GET/POST | `/reghost` | Host registration |
| GET | `/clienthome` | Participant dashboard |
| GET | `/hosthome` | Host dashboard |
| GET/POST | `/hackathon/<hack_id>` | View hackathon details |
| GET/POST | `/hackathon/<hack_id>/reg` | Register a team |
| GET/POST | `/hackathon/<hack_id>/upload` | Upload project file |
| GET | `/hackathon/<hack_id>/<teamname>/files` | View team's files |
| GET | `/hackathon/<hack_id>/<teamname>/<file_id>` | Download a file |
| GET/POST | `/hackathon/<hack_id>/find` | Join team-finder board |
| GET | `/host/<hack_id>/files` | View all submissions (host) |
| GET | `/host/add/hack` | Create a new hackathon |

---

## How It Works

1. A **host** registers, creates a hackathon, and sets the details (date, duration, team size, prize pool)
2. **Participants** browse open hackathons and register individually or as a team
3. Participants without a team can use the **team-finder** to list themselves and send connection requests via email
4. Teams upload their project files before the deadline
5. Hosts can view all team submissions from their dashboard

---

## Roadmap

- Real-time team chat
- Search and filtering for hackathons
- GitHub integration for project submission tracking

---

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature`
3. Commit your changes: `git commit -m "Add your feature"`
4. Push and open a pull request

---

## Credits

Built by the HackArena team. Inspired by the DevNovate track from the Build with India Hackathon.