from Crypto.PublicKey import RSA
import os

uid = input("Enter UserID: ")
key = RSA.generate(2048)
pubkey = key.publickey().exportKey()
print(pubkey.hex())
passPh = input("\nEnter Passphrase: ")
encrypted_key = key.exportKey(passphrase=passPh, pkcs=8)
with open(os.path.expanduser("~/bcd/"+uid+".pem"), "wb+") as f:
	f.write(encrypted_key)
	print("Private Key written at: ", os.path.expanduser("~/bcd/"+uid+".pem"))
