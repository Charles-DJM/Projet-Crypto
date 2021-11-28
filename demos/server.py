# Serveur pour le projet crypto
# Connexion > nouveau thread par client
# Communication RSA pour etablir cle AES-128
# Choix utilisateur : envoi (user>server) ou recuperer (server>user) fichier
#   user>server : Reception Fichier > Sauvegarde cle AES dans 1db et fichier dans une autre
#                 Generation xkcdkey pour recuperer fichier
#   server>user : demande xkcdkey > envoi fichier puis cle AES utilise pour chiffrer le fichier
# https://stackoverflow.com/questions/63819977/do-i-understand-correctly-how-to-encrypt-tcp-traffic-via-rsa-aes

import os
import csv
import socket
import threading
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from xkcdpass import xkcd_password as xp
from Crypto.Random import get_random_bytes
from demos.xkcdpassExample import gen_xkcd

SERVER_HOST = "127.0.0.1"
SERVER_PORT = 8080
SEPARATOR = "<SEPARATOR>"
BUFFER_SIZE = 4096

class ClientThread(threading.Thread):

    RSAKey = RSA.generate(2048)
    RSAprivateKey = RSAKey.export_key()
    RSAPublicKey = RSAKey.public_key().export_key()

    def __init__(self,clientAddress,clientsocket, id):
        self.id = id
        threading.Thread.__init__(self)
        self.csocket = clientsocket
        print ("New connection added: ", clientAddress)

    def run(self, clientAddress):
        print ("Connection from : ", clientAddress)
        self.csocket.send(bytes(self.RSAPublicKey, 'UTF-8'))
        data = self.csocket.recv(2048)
        data = data.decode()

        # Déchiffrer msg avec la clefs privé RSA
        msg = self.RSAprivateKey.decrypt(data)
        msg = msg.decode('utf-8')

        # Sauvegarder la clef AES dans un fichier (logiquement on fait ca en db)
        AESkey = open(self.id + "_" + "aes_key.txt", "a")
        AESkey.write(msg)
        AESkey.close()

        # Maintenant tout doit etre chiffré et déchiffré en AES
        # On attend réponse du client 
        respons = self.csocket.recv()
        

        # Le serveur recoit le fichier envoyé par l'utilisateur
        if respons == "1" :
            # D'abord recuperer taille du fichier 
            received = self.csocket.recv(BUFFER_SIZE).decode()
            filename, filesize = received.split(SEPARATOR)
            filesize = int(filesize)

            # Récupération du fichier
            with open(filename, "wb") as f:
                while True:
                    bytes_read = self.csocket.recv(BUFFER_SIZE)
                    if not bytes_read:
                        break
                    f.write(bytes_read)
            f.close()

            # Générer une clef avec xkcdpass la correspondance au fichier 
            xkcdpass = gen_xkcd()

            # Enregistrement de la clé xkcdpass dans un fichier pour établir la correspondance (le mieux c'est en db)
            with open('correspondence.csv', "a", newline= '', encoding='utf-8') as filecsv :
                writer =csv.writer(filecsv)
                writer.writerow([self.id, self.id + "_" + "aes_key.txt", filename, xkcdpass])

            # Envoyer au client la clé
            self.csocket.send(xkcdpass, 'UTF-8')


        # Le serveur envoie un fichier au client 
        if respons == "2" :
            # On attend une clef xkcdpass
            xkcdpass = self.csocket.recv().decode()

            # Vérifier la correspondance entre la clé xkcdpass et le nom du fichier
            with open("Projet-Crypto/demos/correspondence.csv", "r") as file: 
                datafile = file.readlines()
            for line in datafile: 
                id, fileAESkey, filecrypted, xkcdpassword = line.split(",")
                if xkcdpassword + "/n" == xkcdpass :
                    with open( "Projet-Crypto/demos/" + fileAESkey, 'r') as aes :
                        AESkey = aes.readline() 
                        while True:
                            bytes_read = f.read(BUFFER_SIZE)
                            if not bytes_read:
                                break
                            self.csocket.sendall(bytes_read)
                            
                    with open(filecrypted, "rb") as f:
                        while True:
                            bytes_read = f.read(BUFFER_SIZE)
                            if not bytes_read:
                                break
                            self.csocket.sendall(bytes_read)
                else :
                    self.csocket.send('Error')
        
        if respons == "3" :
             


# Si recevoir(client):
    # On attend une clef xkcdpass 
    # Si elle corespond :
        #  On envoie le fichier avec la correspondance de la clef AES
    # Si ca correspond pas :
        # Vas niker TA mèreah !



#https://riptutorial.com/python/example/27169/server-side-implementation


server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind((SERVER_HOST, SERVER_PORT))
print("Server started")
print("Waiting for client request..")
id = 0
while True:
    server.listen(1)
    clientsock, clientAddress = server.accept()
    newthread = ClientThread(clientAddress, clientsock, id)
    id = id + 1
    newthread.start()
    
