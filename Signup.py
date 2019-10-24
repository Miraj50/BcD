import psycopg2, secrets, hashlib, os
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5 as pkcs
from Crypto.Hash import SHA256

def Signup(conn, uid, pwd, pubkey):
	cur = conn.cursor()
	cur.execute("SELECT * from icreds WHERE uid=%s", (uid,))
	if cur.fetchone():
		return "M"
	else:
		salt = secrets.token_hex(32)
		phash = hashlib.pbkdf2_hmac('sha256', uid.encode(), pwd.encode(), 100000).hex()
		stmt = "INSERT INTO icreds (uid, salt, hash, pubkey) VALUES (%s, %s, %s, %s)"
		v = (uid, salt, phash, pubkey,)
		query = cur.mogrify(stmt, v)
		with open(os.path.expanduser("~/bcd/admin.pem"), "r") as f:
			privkey = RSA.importKey(f.read(), passphrase='a')
		digest = SHA256.new()
		digest.update(query)
		sig = pkcs.new(RSA.importKey(privkey.exportKey())).sign(digest).hex()
		import mc
		try:
			api = mc.getApi()
			txid = mc.publishItem(api, 'admin', '', sig)
		except:
			print("MultiChain Error")
			return "M"
		else:
			cur.execute(stmt, v)
			conn.commit()
			conn.close()
			return "S"