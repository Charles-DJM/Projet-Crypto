import socket
from exempleRSA import Generate_RSA_PBL
import tqdm
import os

from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
from exempleRSA import Encrypt_AES, Decrypt_AES

from xkcdpass import xkcd_password as xp
from xkcdpassExample import gen_xkcd

from AES import AESdecryption, AESencryption
SEPARATOR = "<SEPARATOR>"
BUFFER_SIZE = 4096

s = socket.socket()
host = "127.0.0.1"
port = 5001
print(f"[+] Connecting to {host}:{port}")
s.connect((host, port))
print("[+] Connected to ", host)

#recevoir une clef publique rsa

client_socket, address = s.accept()
received = client_socket.recv(BUFFER_SIZE).decode()
#file = open('RSApublicKey.txt','a')
#file.write(received)
#file.close

#****************************************************






#creer une clef aes  /
#la crypté en rsa via la clef publique du serveur/
#l'envoyer au serveur/
#attendre que le serveur confirme sa disponibilité/
#choix de l'utilisateur/
#l'envoyer au serveur/
#si on envois on doit le chiffré en aes/
    #se référer a la boucle ligne 20 dans clientsender.py/
    #préciser la taille du chiffrement au serveur/
    #envois du fichier/
#si on récupère le fichier
    #envoyer une clef xkcdpass au serveur/
    #attendre la réponse du serveur pour la confirmation de la clef xkcdpass/
    #si c ok
        #recevoir la taille et le nom du fichier/
        #boucle de reception de fichier (ref serverreceiver ligne 22)/
        #réception de la clef aes
        #déchiffrement du fichier
    #si c pas bon zob

key = get_random_bytes(16)
cipher_rsa = PKCS1_OAEP.new(received)
enc_session_key = cipher_rsa.encrypt(key)
enc_session_key = str(enc_session_key)
s.send(enc_session_key.encode())
client_socket, address = s.accept()
choix = input('Que voulez vous faire ?\n1-Envoyer un fichier\n2-Récupérer un fichier\n3-quit \n>')
file_out = open("encrypted_data_new.bin", "wb")

if choix=='1':
    s.send(choix.encode())
    filename = input("File to Transfer : \n>")
    
    #chiffrer le fichier 
    AESencryption(filename, key)
    filename = filename + '.enc'
    #envoyer infos fichier
    filesize_enc = os.path.getsize(filename)
    s.send(f"{filename}{SEPARATOR}{filesize_enc}".encode()) 
    
    #envoi fichier au serveur
    progress = tqdm.tqdm(range(filesize_enc), f"Sending {filename}", unit="B", unit_scale=True, unit_divisor=1024)
    with open(filename, "rb") as f:
        while True:
            bytes_read = f.read(BUFFER_SIZE)
            if not bytes_read:
                break
            s.sendall(bytes_read)
            progress.update(len(bytes_read))
    #recevoir la clé xkcd
            passwd = s.recv()
            Decrypt_AES(passwd)
            print(passwd)
if choix=='2':
    s.send(choix.encode())
    passwd = input("Entrez le mot de passe du fichier \n>")
    Encrypt_AES(passwd)
    s.send(passwd.encode())
    srv_response = s.recv()
    srv_response.decode()
    if srv_response == "OK" :
        
        filename, filesize = received.split(SEPARATOR)
        filename = os.path.basename(filename)
        filesize = int(filesize)
        progress = tqdm.tqdm(range(filesize), f"Receiving {filename}", unit="B", unit_scale=True, unit_divisor=1024)
        with open(filename, "wb") as f:
            while True:
                bytes_read = client_socket.recv(filesize)
                if not bytes_read:
                    break
                f.write(bytes_read)
                progress.update(len(bytes_read))
        client_socket.close()
        s.close()
        decrypt_key = s.recv()
        Decrypt_AES(key, decrypt_key)
        AESdecryption(filename, decrypt_key)
        print("Reçu")
    else :
        print("Erreur")
        quit
else : 
    quit



#**************************************************






