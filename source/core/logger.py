import os
import datetime
from .database import DatabaseManagment

install_location = f'{os.getenv("HOME")}/.SuperSploit'
log_path = f"{install_location}/.data/.logs/activity.log"

class Logger:
    @staticmethod
    def _write_log(entry):
        """Internal method to handle file I/O safely."""
        try:
            os.makedirs(os.path.dirname(log_path), exist_ok=True)
            with open(log_path, "a") as f:
                f.write(entry + "\n")
        except Exception as e:
            from .errors import Error
            Error.silent(f"Logging Failed: {e}")

    @staticmethod
    def start_session():
        """Marks the beginning of a new framework session."""
        db = DatabaseManagment.get()
        session_id = db.get("SESSION_ID", "UNKNOWN")
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        divider = "-" * 50
        entry = f"{divider}\n[{timestamp}] [SESSION: {session_id}] --- SUPERSPLOIT FRAMEWORK LAUNCHED ---"
        Logger._write_log(entry)

    @staticmethod
    def log_execution(exploit_type, success=True):
        """Logs the execution details of an exploit."""
        db = DatabaseManagment.get()
        session_id = db.get("SESSION_ID", "UNKNOWN")
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        exploit = db.get("EXPLOIT", "Unknown")
        target = db.get("R_HOST", "N/A")
        
        entry = f"[{timestamp}] [SESSION: {session_id}] TYPE: {exploit_type} | EXPLOIT: {exploit} | TARGET: {target} | SUCCESS: {success}"
        Logger._write_log(entry)