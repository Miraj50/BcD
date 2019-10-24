from flask import session
# import psycopg2.extras
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5 as pkcs
from Crypto.Hash import SHA256

def Insert(conn, data, count, sig=None):
	# Do the checks
	cur = conn.cursor()
	stmt = "INSERT INTO std (uid, course, grade) VALUES %s"
	if sig is None:
		v = [tuple(i.values()) for i in data]
		template = ','.join(['%s'] * len(v))
		stmt_ = "INSERT INTO std (uid, course, grade) VALUES {}".format(template) 
		query = cur.mogrify(stmt_, v)
		session['insert'] = query
		return query
	else:
		orig = SHA256.new(session['insert'])
		if pkcs.new(RSA.importKey(session['pubkey'])).verify(orig, bytes.fromhex(sig)):
			import mc
			try:
				api = mc.getApi()
				txid = mc.publishItem(api, session['username'], session['insert'].decode('utf-8'), sig)
			except:
				print("MultiChain Error")
				return "D"
			else:
				# psycopg2.extras.execute_values(cur, stmt, v)
				cur.execute(session['insert'].decode('utf-8'))
				conn.commit()
				session.pop('insert', None)
				return "S"
		else:
			return "D"
