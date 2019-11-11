from flask import session, json, jsonify
import requests

def Login(uid, pwd, std):
	url = 'http://localhost:5001/login'
	post_data = {'uid': uid, 'pass': pwd, 'student': std}
	r = {}
	try:
		response = requests.post(url, data=post_data).json()
	except (ConnectionError, requests.exceptions.RequestException) as e:
		r['success'] = 'D'
		return jsonify(r)
	if response['success'] == 'S':
		session['logged_in'] = True
		session['username'] = uid
		session['pubkey'] = bytes.fromhex(response['pubkey']).decode('utf-8')
		r['type'] = response['admin']
	r['success'] = response['success']
	return jsonify(r)


	# conn = psycopg2.connect(database="rraj", user="rraj", password="Hack@hack1", host="127.0.0.1", port="5432")
	# cur = conn.cursor()
	# cur.execute("SELECT * from icreds WHERE uid=%s", (uid,))
	# row = cur.fetchall()
	# conn.close()
	# if len(row) == 1:
	# 	salt = row[0][1]
	# 	phash = row[0][2]
	# 	calc = hashlib.pbkdf2_hmac('sha256', uid.encode(), pwd.encode(), 100000).hex()
	# 	if calc == phash:
	# 		session['logged_in'] = True
	# 		session['username'] = uid
	# 		session['pubkey'] = bytes.fromhex(row[0][3]).decode('utf-8')
	# 		return 'S'
	# 	else:
	# 		return "N"
	# else:
	# 	return "N"