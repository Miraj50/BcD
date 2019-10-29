from flask import session
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5 as pkcs
from Crypto.Hash import SHA256

def Update(uid, course, newGrade, sig=None):
	# cur = conn.cursor()
	# stmt = "UPDATE std SET grade=%s WHERE uid=%s AND course=%s"
	# v = (newGrade, uid, course,)
	data = uid+','+course+','+newGrade
	if sig is None:
		# query = cur.mogrify(stmt, v)
		session['update'] = data
		return data
	else:
		orig = SHA256.new(session['update'].encode())
		if pkcs.new(RSA.importKey(session['pubkey'])).verify(orig, bytes.fromhex(sig)):
			import mc
			try:
				api = mc.getApi()
				txid = mc.publishItem(api, session['username'], 'gradeupdate', session['update'], sig)
			except:
				print("MultiChain Error")
				return "D"
			else:
				# cur.callproc('gradeUpdate', (session['username'], uid, course, newGrade,))
				# conn.commit()
				session.pop('update', None)
				# if not cur.fetchone()[0]:
				# 	return "D"
				return "S"
		else:
			return "D"