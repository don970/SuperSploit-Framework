import os
import sys

from .ToStdOut import ToStdout
write = ToStdout.write

installation = f'{os.getenv("HOME")}/.SuperSploit'

class Error:
    def __init__(self, data):
        """Error Handling Method tries to write to stdout if fails uses sys.stderr and writes to 'installation_dictionary/.data/.errors/error.log'.
        The reason for this is to just display the error and not have it interfere with the program."""
        try:
            if "str" not in str(type(data)):
                try:
                    data = data.decode()
                    pass
                except Exception:
                    data = f"{str(data)}"
                    pass
            if not data.endswith("\n"):
                data = f"{data}\n"
            with open(f"{installation}/.data/.errors/error.log", "a") as stdout:
                stdout.write(data)
                stdout.close()
            write(data)
            return
        except Exception as e:
            """here we raise OsError because the only real possible error is a io or file not found"""
            sys.stderr.write(str(e))
            raise OSError

    @staticmethod
    def silent(data):
        if "str" not in str(type(data)):
            try:
                data = data.decode()
                pass
            except Exception:
                data = f"{str(data)}"
                pass
        if not data.endswith("\n"):
            data = f"{data}\n"
        with open(f"{installation}/.data/.errors/error.log", "a") as stdout:
            stdout.write(data)
            stdout.close()
        write(data)
        return