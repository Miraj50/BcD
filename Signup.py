import psycopg2, secrets, hashlib, os
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5 as pkcs
from Crypto.Hash import SHA256
from flask import session

def Signup(uid, pwd, pubkey, sig=None):
	if sig is None:
		data = uid+','+pwd+','+pubkey+',userenroll'
		session['signup'] = data
		return data
	else:
		orig = SHA256.new(session['signup'].encode())
		if pkcs.new(RSA.importKey(session['pubkey'])).verify(orig, bytes.fromhex(sig)):
			import mc
			try:
				api = mc.getApi()
				txid = mc.publishItem(api, session['username'], 'userenroll', session['signup'], sig)
			except:
				print("MultiChain Error")
				return "D"
			else:
				session.pop('update', None)
				return "S"