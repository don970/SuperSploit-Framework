from core import Input


class Main:
    def __init__(self):
        try:
            """calls the main input handler"""
            Input.get()
        except KeyboardInterrupt:
            print(f"Good bye. );")
            exit()


Main()