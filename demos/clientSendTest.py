import socket
from AES import AESFiledecryption, AESFileencryption, AESStringDecryption, AESStringEncryption
from exempleRSA import Generate_RSA_PBL
import tqdm
import os

from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
from exempleRSA import Encrypt_AES, Decrypt_AES

from xkcdpass import xkcd_password as xp
from xkcdpassExample import gen_xkcd



s = socket.socket()
host = "127.0.0.1"
port = 8080
print(f"[+] Connecting to {host}:{port}")
s.connect((host, port))


BUFFER_SIZE = 4096
filename = 'file.txt'
filesize_enc = os.path.getsize(filename)

progress = tqdm.tqdm(range(filesize_enc), f"Sending {filename}", unit="B", unit_scale=True, unit_divisor=1024)
with open(filename, "rb") as f:
    while True:
        bytes_read = f.read(BUFFER_SIZE)
        if not bytes_read:
            break
        s.sendall(bytes_read)
        progress.update(len(bytes_read))
    f.close()