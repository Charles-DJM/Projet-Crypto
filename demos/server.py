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

class ClientThread(threading.Thread):

    RSAKey = RSA.generate(2048)
    RSAprivateKey = RSAKey.export_key()
    RSAPublicKey = RSAKey.public_key().export_key()

    def __init__(self,clientAddress,clientsocket, id):
        self.id = id
        threading.Thread.__init__(self)
        self.csocket = clientsocket
        print ("New connection added: ", clientAddress)

    def run(self):
        print ("Connection from : ", clientAddress)
        #self.csocket.send(bytes(self.RSAPublicKey, 'UTF-8'))
        self.csocket.send(self.RSAPublicKey)
        data = self.csocket.recv(4096)
        

        # Déchiffrer msg avec la clefs privé RSA
        pkey = RSA.import_key(self.RSAprivateKey)
        cipherRSA = PKCS1_OAEP.new(pkey)
        AESkey = cipherRSA.decrypt(data)
            
        # Sauvegarder la clef AES dans un fichier (logiquement on fait ca en db)
        AESkeyfile = open(str(self.id) + "_" + "aes_key.txt", "ab")
        test = AESkeyfile.write(AESkey)
        AESkeyfile.close()

        # Maintenant tout doit etre chiffré et déchiffré en AES
        
        # On attend réponse du client chiffré en AES
        responsCrypted = self.csocket.recv(BUFFER_SIZE)

        # Décryptage de la réponse 
        respons = AESStringDecryption(responsCrypted, AESkey)
        

        # Le serveur recoit le fichier envoyé par l'utilisateur
        if respons == "1" :
            # D'abord recuperer taille du fichier (crypté)
            receivedCrypted = self.csocket.recv(BUFFER_SIZE)
            received = AESStringDecryption(receivedCrypted, AESkey)
            filename, filesize = received.split(SEPARATOR)
            filesize = int(filesize)
            filename = filename + 'serv' 

            # Récupération du fichier
            with open(filename, "wb") as f:
                total_bytes_read = 0
                while True:
                    bytes_read = self.csocket.recv(BUFFER_SIZE)
                    total_bytes_read = f.write(bytes_read)
                    print(bytes_read)
                    if not bytes_read or total_bytes_read == filesize:
                        print('flush')
                        f.flush()
                        break

            # Générer une clef avec xkcdpass la correspondance au fichier 
            print('xkcd')
            xkcdpass = gen_xkcd()

            # Enregistrement de la clé xkcdpass dans un fichier pour établir la correspondance (le mieux c'est en db)
            with open('correspondence.csv', "a", newline= '', encoding='utf-8') as filecsv :
                writer =csv.writer(filecsv)
                writer.writerow([str(self.id), str(self.id) + "_" + "aes_key.txt", filename, xkcdpass])

            # Crypatge de la clé en AES
            xkcdpassCrypted = AESStringEncryption(xkcdpass, AESkey)
            # Envoyer au client la clé
            self.csocket.send(xkcdpassCrypted)
            self.csocket.close()

        # Le serveur envoie un fichier au client 
        elif respons == "2" :
            # On attend une clef xkcdpass crypté en AES
            xkcdpassCrypted = self.csocket.recv()

            # Décryptage de xkcdpass avec la clé AES
            xkcdpass = AESStringDecryption(xkcdpassCrypted, AESkey)

            # Vérifier la correspondance entre la clé xkcdpass et le nom du fichier
            with open("Projet-Crypto/demos/correspondence.csv", "r") as file: 
                datafile = file.readlines()
            for line in datafile: 
                id, fileAESkey, fileCryptedName, xkcdpassword = line.split(",")
                if xkcdpassword + "/n" == xkcdpass :
                    self.csocket.send('OK !'.encode('utf-8'))
                    with open( "Projet-Crypto/demos/" + fileAESkey, 'r') as aes :
                        AESkey = aes.readline() 
                        # Envoi de la clé AES
                        while True:
                            bytes_read = f.read(BUFFER_SIZE)
                            if not bytes_read:
                                break
                            self.csocket.sendall(bytes_read)
                        
                        # Envoie des infos du fichier 
                        filesize_enc = os.path.getsize(fileCryptedName)
                        fileInfo = f"{fileCryptedName}{SEPARATOR}{filesize_enc}"
                        fileInfo = AESStringEncryption(fileInfo, AESkey)
                        self.csocket.send(fileInfo) 
                        
                    with open(fileCryptedName, "rb") as f:
                        # Envoi du fichier
                        while True:
                            bytes_read = f.read(BUFFER_SIZE)
                            if not bytes_read:
                                break
                            self.csocket.sendall(bytes_read)
                    self.csocket.close()
                else :
                    self.csocket.send('Error')
                    self.csocket.close()
        
        elif respons == "3" :
            self.csocket.close()

        else :
            error = AESStringEncryption('Erreur de choix', AESkey)
            self.csocket.send(error)
            self.csocket.close()
            


#https://riptutorial.com/python/example/27169/server-side-implementation


server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind((SERVER_HOST, SERVER_PORT))
print("Server started")
print("Waiting for client request..")
id = 0
while True:
    server.listen(99)
    clientsock, clientAddress = server.accept()
    newthread = ClientThread(clientAddress, clientsock, id)
    id = id + 1
    newthread.start()