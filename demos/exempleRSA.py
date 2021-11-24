# fichier exemple pour RSA
# https://gist.github.com/YannBouyeron/f39893644f89dd676297cc3bc67eaedb
# https://pycryptodome.readthedocs.io/en/latest/src/examples.html#encrypt-data-with-rsa
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP

key = RSA.generate(2048)

def Generate_RSA_PRV():
   private_key = key.export_key()
   file_out = open("private.pem", "wb")
   file_out.write(private_key)
   file_out.close()

def Generate_RSA_PBL():
   public_key = key.publickey().export_key()
   file_out = open("receiver.pem", "wb")
   file_out.write(public_key)
   file_out.close()
	
data = "I met aliens in UFO. Here is the map.".encode("utf-8")
file_out = open("encrypted_data.bin", "wb")

recipient_key = RSA.import_key(open("receiver.pem").read())
session_key = get_random_bytes(16)

# Encrypt the session key with the public RSA key
cipher_rsa = PKCS1_OAEP.new(recipient_key)
enc_session_key = cipher_rsa.encrypt(session_key)

# Decrypt msg with the private RSA key
def Decrypt_Msg_RSA_Private_Key(data, RSAprivateKey):
   msg = RSAprivateKey.decrypt(data)
   msg = msg.decode('utf-8')

# Encrypt the data with the AES session key
def Encrypt_AES():
   cipher_aes = AES.new(session_key, AES.MODE_EAX)
   ciphertext, tag = cipher_aes.encrypt_and_digest(data)
   [ file_out.write(x) for x in (enc_session_key, cipher_aes.nonce, tag, ciphertext) ]
   file_out.close()

file_in = open("encrypted_data.bin", "rb")

private_key = RSA.import_key(open("private.pem").read())

enc_session_key, nonce, tag, ciphertext = \
   [ file_in.read(x) for x in (private_key.size_in_bytes(), 16, 16, -1) ]

# Decrypt the session key with the private RSA key
cipher_rsa = PKCS1_OAEP.new(private_key)
session_key = cipher_rsa.decrypt(enc_session_key)

# Decrypt the data with the AES session key
def Decrypt_AES():
   cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
   data = cipher_aes.decrypt_and_verify(ciphertext, tag)
   print(data.decode("utf-8"))
