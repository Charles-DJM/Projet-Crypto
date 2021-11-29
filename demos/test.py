from re import L
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from xkcdpass import xkcd_password as xp
from Crypto.Random import get_random_bytes
from xkcdpassExample import gen_xkcd
from AES import AESStringDecryption
from AES import AESStringEncryption

key = RSA.generate(2048)
data = get_random_bytes(16)

print(data)
print('\n')

RSAprivateKey = key.export_key()
RSAPublicKey = key.public_key().export_key()



impoezeart = RSA.import_key(RSAPublicKey)

cipher_rsa = PKCS1_OAEP.new(impoezeart)



crypted = cipher_rsa.encrypt(data)


cipher_rsa = PKCS1_OAEP.new(RSA.import_key(RSAprivateKey))
decrypted = cipher_rsa.decrypt(crypted)
print(decrypted)
