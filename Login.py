from flask import session
import psycopg2, hashlib

def Login(conn, uid, pwd, std):
	cur = conn.cursor()
	cur.execute("SELECT * from icreds WHERE uid=%s", (uid,))
	row = cur.fetchall()
	if len(row) == 1:
		salt = row[0][1]
		phash = row[0][2]
		calc = hashlib.pbkdf2_hmac('sha256', uid.encode(), pwd.encode(), 100000).hex()
		if calc == phash:
			session['logged_in'] = True
			session['username'] = uid
			session['pubkey'] = bytes.fromhex(row[0][3]).decode('utf-8')
			return 'S'
		else:
			return "N"
	else:
		return "N"