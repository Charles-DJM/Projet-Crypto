# Serveur pour le projet crypto
# Connexion > nouveau thread par client
# Communication RSA pour etablir cle AES-128
# Choix utilisateur : envoi (user>server) ou recuperer (server>user) fichier
#   user>server : Reception Fichier > Sauvegarde cle AES dans 1db et fichier dans une autre
#                 Generation xkcdkey pour recuperer fichier
#   server>user : demande xkcdkey > envoi fichier puis cle AES utilise pour chiffrer le fichier
# https://stackoverflow.com/questions/63819977/do-i-understand-correctly-how-to-encrypt-tcp-traffic-via-rsa-aes

import socket
import threading
import os
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

SERVER_HOST = "127.0.0.1"
SERVER_PORT = 8080
SEPARATOR = "<SEPARATOR>"

class ClientThread(threading.Thread):

    RSAKey = RSA.generate(2048)
    RSAprivateKey = RSAKey.export_key()
    RSAPublicKey = RSAKey.public_key().export_key()

    def __init__(self,clientAddress,clientsocket):
        threading.Thread.__init__(self)
        self.csocket = clientsocket
        print ("New connection added: ", clientAddress)

    def run(self):
        print ("Connection from : ", clientAddress)
        self.csocket.send(bytes(self.RSAPublicKey, 'UTF-8'))
        data = self.csocket.recv(2048)
        data = data.decode()

        # Déchiffrer msg avec la clefs privé RSA
        msg = self.RSAprivateKey.decrypt(data)
        msg = msg.decode('utf-8')

        # Sauvegarder la clef AES dans un fichier (logiquement on fait ca en db)
        AESkey = open("aes_key.txt", "a")
        AESkey.write(msg)
        AESkey.close()

        # Maintenant tout doit etre chiffré et déchiffré en AES


        #https://riptutorial.com/python/example/27169/server-side-implementation

        
       
        # Demander au client ce qu'il veut faire : recevoir / envoyer
            # Si envoyer:
                # D'abord recuperer taille du fichier 
                # Récupération du fichier
                # Correspondance entre la clef AES et le fichier
                # Générer une clef avec xkcdpass la correspondance au fichier puis l'envoyer au client  

            # Si recevoir:
                # On attend une clef xkcdpass 
                # Si elle corespond :
                    #  On envoie le fichier avec la correspondance de la clef AES
                # Si ca correspond pas :
                    # Vas niker TA mèreah !


server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind((SERVER_HOST, SERVER_PORT))
print("Server started")
print("Waiting for client request..")
while True:
    server.listen(1)
    clientsock, clientAddress = server.accept()
    newthread = ClientThread(clientAddress, clientsock)
    newthread.start()
    
