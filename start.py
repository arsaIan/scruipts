import subprocess
import os

# Configuration 
# Change as per your needs
host = "0.0.0.0"
port = "5001"
workers = "2"
app_path = "app:app"  


script_dir = os.path.dirname(os.path.abspath(__file__))

# logs
access_log = os.path.join(script_dir, "access.log")
error_log = os.path.join(script_dir, "error.log")


cmd = [
    "gunicorn",
    app_path,
    "--bind", f"{host}:{port}",
    "--workers", workers,
    "--daemon",
    "--access-logfile", access_log,
    "--error-logfile", error_log
]

try:
    subprocess.run(cmd, check=True)
    print(f"Gunicorn started on {host}:{port} in background.")
    print(f"Logs: access → {access_log}, error → {error_log}")
except subprocess.CalledProcessError as e:
    print("❌ Failed to start Gunicorn:", e)
