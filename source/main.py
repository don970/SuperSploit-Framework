from core import Input
import uuid
from core.database import DatabaseManagment
from core.logger import Logger # We will create this next
from core.set import SetV
import sys

install_location = DatabaseManagment.getInstall()

def initialize_session():
    # check sys path and add install if not present
    if f"{install_location}/source" not in sys.path:
        sys.path.append(f"{install_location}/source")

    db = DatabaseManagment.get()
    # Generate an 8-character unique session ID
    session_id = uuid.uuid4().hex[:8]
    SetV.SetV(f"set SESSION_ID {session_id}")
    
    # Trigger the initial staged log entry for the session
    Logger.start_session()


class Main:
    def __init__(self):
        initialize_session()
        # Start the background target synchronization thread
        DatabaseManagment.start_background_sync()
        try:
            """calls the main input handler"""
            Input.get()
        except KeyboardInterrupt:
            print(f"\n[*] Gracefully shutting down...")
        finally:
            # Flush any pending target updates to the disk
            DatabaseManagment.sync_targets_to_disk()
            print(f"Good bye. );")
            exit(0)


Main()