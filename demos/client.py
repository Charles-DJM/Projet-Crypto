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

import AES
#from AES import AESStringDecryption, AESdecryption, AESencryption
SEPARATOR = "<SEPARATOR>"
BUFFER_SIZE = 4096

s = socket.socket()
host = "127.0.0.1"
port = 8080
print(f"[+] Connecting to {host}:{port}")
s.connect((host, port))
print("[+] Connected to ", host)

#recevoir une clef publique rsa
received = s.recv(BUFFER_SIZE).decode()

key = get_random_bytes(16)

received = RSA.import_key(received)

cipher_rsa = PKCS1_OAEP.new(received)

enc_session_key = cipher_rsa.encrypt(key)

#enc_session_key = str(enc_session_key)
s.send(enc_session_key)

choix = input('Que voulez vous faire ?\n1-Envoyer un fichier\n2-Récupérer un fichier\n3-quit \n>')


if choix=='1':
    choix = AESStringEncryption(str(choix), key)
    s.send(choix)
    filename = input("File to Transfer : \n>")
    
    #chiffrer le fichier 
    AESFileencryption(filename, key)
    filename = filename + '.enc'
    #envoyer infos fichier
    filesize_enc = os.path.getsize(filename)
    fileInfo = f"{filename}{SEPARATOR}{filesize_enc}"
    fileInfo = AESStringEncryption(fileInfo, key)
    s.send(fileInfo)
    
    #envoi fichier au serveur
    progress = tqdm.tqdm(range(filesize_enc), f"Sending {filename}", unit="B", unit_scale=True, unit_divisor=1024)
    with open(filename, "rb") as f:
        while True:
            print('vier')
            bytes_read = f.read(BUFFER_SIZE)
            print(bytes_read)
            if not bytes_read:
                break
            s.sendall(bytes_read)
            progress.update(len(bytes_read))
    f.close()
    #recevoir la clé xkcd
    xkcdpass = s.recv(BUFFER_SIZE * 2)
    xkcdpass = AESStringDecryption(xkcdpass, key)
    print("Votre mot de passe pour récupérer le fichier est " + str(xkcdpass))
    s.close()
    exit()
if choix=='2':
    choix = AESStringEncryption(str(choix), key)
    s.send(choix)
    passwd = input("Entrez le mot de passe du fichier \n>")
    passwd = AESStringEncryption(passwd, key)
    s.send(passwd)
    
    ack = s.recv(BUFFER_SIZE)
    ack = AESStringDecryption(ack, key)
    if ack != 'OK !':
        s.close
        quit() #oui oui si tu met le mauvais mot de passe tu te fait kik du programe. Charles te conseil de mettre le bon mot de passe et de ne pas etre un idiot ! ;) (c'est exactement ce qu'il pense)

    srv_response = s.recv()
    srv_response = srv_response
    srv_response = AESStringDecryption(srv_response, key)
    if srv_response == "OK" :
        #Recevoir la clé AES de déchiffrage
        decrypt_key = s.recv()
        Decrypt_AES(key, decrypt_key)
        
        fileInfo = s.recv()
        fileInfo = AESStringDecryption(fileInfo, key)
        filename, filesize = fileInfo.split(SEPARATOR)
        filename = os.path.basename(filename)
        filesize = int(filesize)
        progress = tqdm.tqdm(range(filesize), f"Receiving {filename}", unit="B", unit_scale=True, unit_divisor=1024)
        with open(filename, "wb") as f:
            while True:
                bytes_read = s.recv(BUFFER_SIZE)
                if not bytes_read:
                    break
                f.write(bytes_read)
                progress.update(len(bytes_read))
        f.close()
        s.close()
        AESFiledecryption(filename, decrypt_key)
        print("Reçu")
    else :
        print("Erreur")
        quit()
else : 
    quit()



#**************************************************
