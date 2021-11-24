import socket
from exempleRSA import Generate_RSA_PBL
import tqdm
import os

from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
from exempleRSA import Encrypt_AES, Decrypt_AES


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


filename = input("File to Transfer : ")
filesize = os.path.getsize(filename)



#creer une clef aes  /
#la crypté en rsa via la clef publique du serveur/
#l'envoyer au serveur/
#attendre que le serveur confirme sa disponibilité/
#choix de l'utilisateur/
#l'envoyer au serveur/
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

key = get_random_bytes(16)
cipher_rsa = PKCS1_OAEP.new(received)
enc_session_key = cipher_rsa.encrypt(key)
enc_session_key = str(enc_session_key)
s.send(enc_session_key.encode())
client_socket, address = s.accept()
choix = input('Que voulez vous faire ?\n1-Envoyer un fichier\n2-Récupérer un fichier\n3-quit \n')
if choix=='1':
    s.send(choix.encode())
    filename = input("entrer le nom du fichier à envoyer\n")
    filesize = input("entrer la taille du fichier à envoyer\n")



    s.send(f"{filename}{SEPARATOR}{filesize}".encode())
    print('Envoyer')
if choix=='2':
    s.send(choix.encode())
    print('Recevoir')
else : 
    quit



#**************************************************





