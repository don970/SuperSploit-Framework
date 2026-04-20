from core import Input
import uuid
import datetime
from source.core.database import DatabaseManagment
from source.core.logger import Logger # We will create this next

def initialize_session():
    db = DatabaseManagment.get()
    # Generate an 8-character unique session ID
    session_id = uuid.uuid4().hex[:8]
    db.set("SESSION_ID", session_id)
    
    # Trigger the initial staged log entry for the session
    Logger.start_session()

# Ensure this runs before the main CLI loop starts
if __name__ == "__main__":
    initialize_session()
    # ... rest of your startup logic ...

class Main:
    def __init__(self):
        try:
            """calls the main input handler"""
            Input.get()
        except KeyboardInterrupt:
            print(f"Good bye. );")
            exit()


Main()