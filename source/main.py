from core import Input
import uuid
import datetime
from core.database import DatabaseManagment
from core.logger import Logger # We will create this next
from core.set import SetV

def initialize_session():
    db = DatabaseManagment.get()
    # Generate an 8-character unique session ID
    session_id = uuid.uuid4().hex[:8]
    SetV.SetV(f"SESSION_ID {session_id}")
    
    # Trigger the initial staged log entry for the session
    Logger.start_session()


class Main:
    def __init__(self):
        initialize_session()
        try:
            """calls the main input handler"""
            Input.get()
        except KeyboardInterrupt:
            print(f"Good bye. );")
            exit()


Main()