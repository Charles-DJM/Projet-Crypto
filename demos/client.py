import socket
from demos.exempleRSA import Generate_RSA_PBL
import tqdm
import os

from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP



SEPARATOR = "<SEPARATOR>"
BUFFER_SIZE = 4096

s = socket.socket()
host = "127.0.0.1"
port = 5001
print(f"[+] Connecting to {host}:{port}")
s.connect((host, port))
print("[+] Connected to ", host)

#recevoir une clef publique rsa

filename = input("File to Transfer : ")
filesize = os.path.getsize(filename)

#creer une clef aes  
#la crypté en rsa via la clef publique du serveur
#l'envoyer au serveur
#attendre que le serveur confirme sa disponibilité
#choix de l'utilisateur
#l'envoyer au serveur
#si on envois on doit le chiffré en aes
    #se référer a la boucle ligne 20 dans clientsender.py
    #préciser la taille du chiffrement au serveur
    #envois du fichier
#si on récupère le fichier
    #envoyer une clef xkcdpass au serveur
    #attendre la réponse du serveur pour loa confirmation de la clef xkcdpass
    #si c ok
        #recevoir la taille et le nom du fichier
        #boucle de reception de fichier (ref serverreceiver ligne 22)
        #réception de la clef aes
        #déchiffrement du fichier
    #si c pas bon zob


s.send(f"{filename}{SEPARATOR}{filesize}".encode())


choix = input('Que voulez vous faire ?\n1-Envoyer un fichier\n2-Récupérer un fichier\n3-quit \n')
if choix=='1':
    print('Envoyer')
if choix=='2':
    print('Recevoir')
else : 
    quit


