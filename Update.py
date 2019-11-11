from flask import session
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5 as pkcs
from Crypto.Hash import SHA256

def Update(uid, course, newGrade, sig=None):
	data = uid+','+course+','+newGrade+',gradeupdate'
	if sig is None:
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
				session.pop('update', None)
				return "S"
		else:
			return "D"