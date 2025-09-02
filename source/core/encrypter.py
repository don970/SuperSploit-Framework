import os.path
import json
from cryptography.fernet import Fernet as f
from prompt_toolkit import prompt


installation = f'{os.getenv("HOME")}/.SuperSploit'
with open(".data/.config/Aliases.json") as file:
    aliases = json.load(file)
    file.close()


class Encrypter:
    def __init__(self):
        return

    @classmethod
    def encrypt_file(cls, path):
        # create variables
        global key
        saved_key = False
        keys = []
        enc_data = ''
        data = path.split(" ")[1]

        #  check if file exist
        if not os.path.exists(data):
            raise FileNotFoundError

        # check for existing keys
        for x in os.listdir(f"{installation}/.data/.security"):
            if "key" in x:
                keys.append(f"{installation}/.data/.security/{x}")

        if prompt("Would you like to use a saved key [y/n]: ").startswith("y"):
            saved_key = True
            for i in keys:
                print(f"{keys.index(i)}: {i}")
            choice = int(prompt("Please enter the index of the key: "))
            print("[*] Attempting to load key")
            key = cls.loadKey(keys[choice])
            print("[*] Key loaded")
        else:
            saved_key = False
            print("[*] Generating key")
            key = f.generate_key()
            print("[*] Key generated")

        # pass key to encoder
        enc = f(key)


        try:
            # write key
            if not saved_key:
                keyname = f"key_{len(keys)}"
                print("[*] Writing key")
                with open(f"{installation}/.data/.security/{keyname}", "wb") as file:
                    file.write(key)
                    file.close()



            # store bytes from file and encrypt data
            print(f"[*] Encrypting {data} ...\n")
            with open(data, "rb") as raw:
                data01 = raw.read()
                print(f"[*] Data: {data01}\n")
                enc_data = enc.encrypt(data01)
                print(f"[*] Encrypted data: {enc_data}\n")
                raw.close()

            # write encrypted bytes
            print("[*] Writing encrypted file")
            with open(data, "wb") as raw0:
                raw0.write(enc_data)
                raw0.close()
            return True

        except FileNotFoundError as e:
            print(f"[!] Encryption of {data} failed.\n[*]{e}")
            return False

    @classmethod
    def load_key(cls, path):
        return open(path, "rb").read()

    @classmethod
    def decrypt_file(cls, path):
        path = path.split(" ")[1]
        keys = []
        key_parent_folder = f".data/.security"
        for x in os.listdir(f"{installation}/.data/.security/"):
            if "key" in x:
                keys.append(f"{key_parent_folder}/{x}")

        print(f"[*] Showing stored keys")
        for i in keys:
            print(f"{keys.index(i)}: {i}")

        choice = int(prompt("Please enter the index of the key: "))

        print("[*] Attempting to load key")
        key = cls.loadKey(keys[choice])
        decoder = f(key)
        print("[*] Reading encrypt file")
        with open(path, "rb") as file:
            data = file.read()
            file.close()

        print(f"[*] Decrypting {path}")
        decrypted_data = decoder.decrypt(data).decode()
        with open(path, "w") as file:
            file.write(decrypted_data)
            file.close()
        print("[*] Decryption successful.")
        return