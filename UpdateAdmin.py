import psycopg2, secrets, hashlib, os, mc
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5 as pkcs
from Crypto.Hash import SHA256
from flask import session

def UpdatePk(uid, pubkey, sig=None):
	if sig is None:
		data = uid+','+pubkey
		session['updatepk'] = data
		return data
	else:
		orig = SHA256.new(session['updatepk'].encode())
		if pkcs.new(RSA.importKey(session['pubkey'])).verify(orig, bytes.fromhex(sig)):
			try:
				api = mc.getApi()
				txid = mc.publishItem(api, session['username'], 'updatepubkey', session['updatepk'], sig)
			except:
				print("MultiChain Error")
				return "D"
			else:
				session.pop('updatepk', None)
				# cur.execute(stmt, v)
				# conn.commit()
				# conn.close()
				return "S"

def UpdateSQPr(pr, sig=None):
	if sig is None:
		session['updatesqpr'] = pr
		return pr
	else:
		orig = SHA256.new(session['updatesqpr'].encode())
		if pkcs.new(RSA.importKey(session['pubkey'])).verify(orig, bytes.fromhex(sig)):
			try:
				api = mc.getApi()
				txid = mc.publishItem(api, session['username'], 'updatesqlpr', session['updatesqpr'], sig)
			except:
				print("MultiChain Error")
				return "D"
			else:
				session.pop('updatesqpr', None)
				# cur.execute(stmt, v)
				# conn.commit()
				# conn.close()
				return "S"