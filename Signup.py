import psycopg2, secrets, hashlib, os
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5 as pkcs
from Crypto.Hash import SHA256

def Signup(uid, pwd, pubkey, sig=None):
	data = uid+','+pwd+','+pubkey
	if sig is None:
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
				# cur.execute(stmt, v)
				# conn.commit()
				# conn.close()
				return "S"
		# salt = secrets.token_hex(32)
		# phash = hashlib.pbkdf2_hmac('sha256', uid.encode(), pwd.encode(), 100000).hex()
		# stmt = "INSERT INTO icreds (uid, salt, hash, pubkey) VALUES (%s, %s, %s, %s)"
		# v = (uid, salt, phash, pubkey,)
		# query = cur.mogrify(stmt, v)
		# with open(os.path.expanduser("~/bcd/admin.pem"), "r") as f:
		# 	privkey = RSA.importKey(f.read(), passphrase='a')
		# digest = SHA256.new()
		# digest.update(query)
		# sig = pkcs.new(RSA.importKey(privkey.exportKey())).sign(digest).hex()
		# import mc
		# try:
		# 	api = mc.getApi()
		# 	txid = mc.publishItem(api, 'admin', 'userenroll', '', sig)
		# except:
		# 	print("MultiChain Error")
		# 	return "M"
		# else:
		# 	cur.execute(stmt, v)
		# 	conn.commit()
		# 	conn.close()
		# 	return "S"