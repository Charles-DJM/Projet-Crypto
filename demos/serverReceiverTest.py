import os
import csv
import socket
import threading
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from xkcdpass import xkcd_password as xp
from Crypto.Random import get_random_bytes
from xkcdpassExample import gen_xkcd
from AES import AESStringDecryption
from AES import AESStringEncryption

SERVER_HOST = "127.0.0.1"
SERVER_PORT = 8080
SEPARATOR = "<SEPARATOR>"
BUFFER_SIZE = 4096

s = socket.socket()
s.bind((SERVER_HOST, SERVER_PORT))
s.listen(10)
print(f"[*] Listening as {SERVER_HOST}:{SERVER_PORT}")
print("Waiting for the client to connect... ")
client_socket, address = s.accept()
print(f"[+] {address} is connected.")

filename = 'server_file.txt'

with open(filename, "wb") as f:
    while True:
        bytes_read = client_socket.recv(BUFFER_SIZE)
        if not bytes_read:
            break
        f.write(bytes_read)
client_socket.close()
s.close()