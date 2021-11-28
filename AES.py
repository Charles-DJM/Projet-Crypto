import os

from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad
from base64 import b64encode, b64decode, decode



def AESencryption(file, key):
    with open(file, 'rb') as enc:
        data = enc.read()
        cipher = AES.new(key, AES.MODE_CFB)
        ciphertext = cipher.encrypt(pad(data, AES.block_size))
        iv = b64encode(cipher.iv).decode('UTF-8')
        ciphertext = b64encode(ciphertext).decode('UTF-8')
        write = iv + ciphertext
    enc.close()
    with open(file + '.enc', 'w') as data:
        data.write(write)
    data.close()


def AESdecryption(file,key):
    with open(file, 'r') as decf:
        try:
            data = decf.read()
            iv = data[:24]
            iv = b64decode(iv)
            ciphertext = data[24:len(data)]
            ciphertext = b64decode(ciphertext)
            cipher = AES.new(key,AES.MODE_CFB,iv)
            decrypted = cipher.decrypt(ciphertext)
            decrypted = unpad(decrypted,AES.block_size)
            new_file = input(f'Entrez le nom du fichier\n>')
            with open(new_file, 'wb') as data:
                data.write(decrypted)
            data.close()
        except(ValueError,KeyError):
            print('Decryption Error')

#key =  input('key')
key = get_random_bytes(16)
#key = key.encode('UTF-8')
key = pad(key, AES.block_size)
filename = input("file to encrypt\n>")
print(filename)
AESencryption(filename, key)
filename = input("file to decrypt\n>")
AESdecryption('file.txt.enc', key)

