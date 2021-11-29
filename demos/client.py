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

received = RSA.import_key(received)

cipher_rsa = PKCS1_OAEP.new(received)

enc_session_key = cipher_rsa.encrypt(key)

#enc_session_key = str(enc_session_key)
s.send(enc_session_key)

choix = input('Que voulez vous faire ?\n1-Envoyer un fichier\n2-Récupérer un fichier\n3-quit \n>')


if choix=='1':
    choix = AESStringEncryption(choix.encode('UTF-8'), key)
    s.send(choix.encode())
    filename = input("File to Transfer : \n>")
    
    #chiffrer le fichier 
    AESFileencryption(filename, key)
    filename = filename + '.enc'
    #envoyer infos fichier
    filesize_enc = os.path.getsize(filename)
    fileInfo = f"{filename}{SEPARATOR}{filesize_enc}"
    fileInfo = AESStringEncryption(fileInfo, key)
    s.send(fileInfo.encode()) 
    
    #envoi fichier au serveur
    progress = tqdm.tqdm(range(filesize_enc), f"Sending {filename}", unit="B", unit_scale=True, unit_divisor=1024)
    with open(filename, "rb") as f:
        while True:
            bytes_read = f.read(BUFFER_SIZE)
            if not bytes_read:
                break
            s.sendall(bytes_read)
            progress.update(len(bytes_read))
    f.close()
    #recevoir la clé xkcd
    xkcdpass = s.recv()
    AESStringDecryption(xkcdpass, key)
    print("Votre mot de passe pour récupérer le fichier est " + xkcdpass.decode())
    s.close()
    exit()
if choix=='2':
    s.send(choix.encode())
    passwd = input("Entrez le mot de passe du fichier \n>")
    AESStringEncryption(passwd.encode('UTF-8'), key)
    s.send(passwd.encode())
    
    ack = s.recv().decode()
    ack = AESStringDecryption(ack, key)
    if ack != 'OK !':
        s.close
        quit() #oui oui si tu met le mauvais mot de passe tu te fait kik du programe. Charles te conseil de mettre le bon mot de passe et de ne pas etre un idiot ! ;) (c'est exactement ce qu'il pense)

    srv_response = s.recv()
    srv_response = srv_response.decode()
    srv_response = AESStringDecryption(srv_response, key)
    if srv_response == "OK" :
        #Recevoir la clé AES de déchiffrage
        decrypt_key = s.recv().decode()
        Decrypt_AES(key, decrypt_key)
        
        fileInfo = s.recv().decode()
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
