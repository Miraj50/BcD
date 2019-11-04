from flask import session, jsonify
# import psycopg2.extras
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5 as pkcs
from Crypto.Hash import SHA256
import requests, time

def Insert(data, count, sig=None):
	# time.sleep(10)
	if sig is None:
		v = [tuple(i.values()) for i in data]
		s = map(list, zip(*v))
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
				return jsonify({'status':'D'})
			else:
				session.pop('insert', None)
				# if ping == '1':
				# 	url = 'http://localhost:5001/ping'
				# 	try:
				# 		# response = requests.post(url, data={'txid':txid})
				# 		response = requests.post(url, data={'id': session['username']})
				# 	except (ConnectionError, requests.exceptions.RequestException) as e:
				# 		return jsonify({'status':'D'})
				# 	else:
				# 		return jsonify({'status':'PING', 'data':response.text})
				return jsonify({'status':'S'})
		else:
			return jsonify({'status':'D'})
