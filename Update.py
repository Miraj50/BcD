from flask import session
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5 as pkcs
from Crypto.Hash import SHA256

def Update(conn, uid, course, newGrade, sig=None):
	cur = conn.cursor()
	stmt = "UPDATE std SET grade=%s WHERE uid=%s AND course=%s"
	v = (newGrade, uid, course,)
	if sig is None:
		query = cur.mogrify(stmt, v)
		session['update'] = query
		return query
	else:
		orig = SHA256.new(session['update'])
		if pkcs.new(RSA.importKey(session['pubkey'])).verify(orig, bytes.fromhex(sig)):
			import mc
			try:
				api = mc.getApi()
				txid = mc.publishItem(api, session['username'], session['update'].decode('utf-8'), sig)
			except:
				print("MultiChain Error")
				return "D"
			else:
				cur.execute(stmt, v)
				conn.commit()
				session.pop('update', None)
				return "S"
		else:
			return "D"