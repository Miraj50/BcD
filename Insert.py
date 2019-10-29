from flask import session
# import psycopg2.extras
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5 as pkcs
from Crypto.Hash import SHA256

def Insert(data, count, sig=None):
	# cur = conn.cursor()
	# stmt = "INSERT INTO std (uid, course, grade) VALUES %s"
	if sig is None:
		v = [tuple(i.values()) for i in data]
		s = map(list, zip(*v))
		# template = ','.join(['%s'] * len(v))
		# stmt_ = "INSERT INTO std(uid, course, grade) VALUES {}".format(template) 
		# query = cur.mogrify(stmt_, v)
		dt = "||".join([",".join(i) for i in s])
		session['insert'] = dt
		return dt
	else:
		orig = SHA256.new(session['insert'].encode())
		if pkcs.new(RSA.importKey(session['pubkey'])).verify(orig, bytes.fromhex(sig)):
			import mc
			try:
				api = mc.getApi()
				txid = mc.publishItem(api, session['username'], 'gradeinsert', session['insert'], sig)
			except:
				print("MultiChain Error")
				return "D"
			else:
				# t = session['insert'].split('||')
				# std, courses, grades = [i.split(',') for i in t]
				# cur.callproc('gradeInsert', (session['username'], std, courses, grades,))
				# conn.commit()
				session.pop('insert', None)
				# if not cur.fetchone()[0]:
				# 	return "D"
				return "S"
		else:
			return "D"
