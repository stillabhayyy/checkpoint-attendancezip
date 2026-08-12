# Replit setup

## Run

The project runs as a Flask web app through the `Start application` workflow:

```bash
python app.py
```

The server listens on `0.0.0.0:5000`, which makes the app available in the
Replit preview. Flask is provided through the Nix-managed
`python313Packages.flask` dependency.

The app uses SQLite and creates `attendance.db` in the project directory on
first start. Camera and geolocation features require a secure browser context
such as Replit preview HTTPS or localhost.