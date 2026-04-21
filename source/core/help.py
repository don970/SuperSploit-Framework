import os
from .ToStdOut import ToStdout
from .errors import Error

install_location = f'{os.getenv("HOME")}/.SuperSploit'
help_dir = f"{install_location}/.data/.help"
write = ToStdout.write

class Help:
    @staticmethod
    def display(topic=None):
        topic = topic.split()[1]
        """
        Dynamically fetches and displays modular help text files.
        If no topic is specified, loads the main overview.
        """
        if not topic:
            topic = "main"
            
        # Sanitize input to prevent directory traversal
        safe_topic = os.path.basename(topic).lower().strip()
        help_file = os.path.join(help_dir, safe_topic)

        if os.path.exists(help_file):
            try:
                with open(help_file, "r") as file:
                    write(f"\n{file.read()}\n")
            except Exception as e:
                Error.silent(f"Failed to read help file {safe_topic}: {e}")
                write(f"[-] Could not load help for '{safe_topic}'. Check error logs.")
        else:
            write(f"[-] No specific help documentation found for '{safe_topic}'.")
            write("[*] Type 'help' to see the main command menu.\n")