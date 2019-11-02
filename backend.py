# from twisted.internet import task, reactor
from flask import Flask, request, jsonify
import mc, psycopg2, hashlib
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5 as pkcs
from Crypto.Hash import SHA256
from flask_apscheduler import APScheduler


conn = psycopg2.connect(database="rraj", user="rraj", password="Hack@hack1", host="127.0.0.1", port="5432")
cur = conn.cursor()
api = mc.getApi()
timeout = 3
txRun = 109 #########
stmt = "UPDATE txid SET tx=%s"

scheduler = APScheduler()

class Config(object):
	JOBS = [
		{
			'id': 'job1',
			'func': 'backend:pollAndExecute',
			# 'args': (1, 2),
			'trigger': 'interval',
			'seconds': 5
		}
	]
	SCHEDULER_API_ENABLED = True

def helper(txs, ping='0'):
	for i in txs:
		# Ignore ones with ping
		if i['ping'] == 1:
			cur.execute(stmt, (i['txid'],))
			conn.commit()
			continue
		item = i['data']['json']
		cur.execute("SELECT pubkey from icreds WHERE uid=%s", (item['id'],))
		pubkey = bytes.fromhex(cur.fetchone()[0]).decode('utf-8')
		orig = SHA256.new(item['data'].encode())
		if pkcs.new(RSA.importKey(pubkey)).verify(orig, bytes.fromhex(item['sig'])):
			if item['type'] == 'gradeinsert':
				t = item['data'].split('||')
				std, courses, grades = [j.split(',') for j in t]
				cur.callproc('gradeinsert', (item['id'], std, courses, grades,))
				if not cur.fetchone()[0]:
					#Execution failed, Handle exception
					if ping=='1':
						return 'D'
					with open("logs.txt", 'a') as f:
						f.write(i['txid']+' gradeinsert\n')
				else:
					conn.commit()
					return 'S'
				cur.execute(stmt, (i['txid'],))
				conn.commit()
				print(i['txid'])
			elif item['type'] == 'gradeupdate':
				uid, course, newGrade = item['data'].split(',')
				cur.callproc('gradeupdate', (item['id'], uid, course, newGrade,))
				if not cur.fetchone()[0]:
					with open("logs.txt", 'a') as f:
						f.write(i['txid']+' gradeupdate\n')
					#Execution failed, Handle exception
				cur.execute(stmt, (i['txid'],))
				conn.commit()
				print(i['txid'])
		else:
			with open("logs.txt", 'a') as f:
				f.write(i['txid']+'Signature Mismatch')

def pollAndExecute():
	# Do exception handling in cur.callproc()
	global txRun
	tot = mc.streamInfo(api)
	if tot == txRun:
		return
	else:
		txs = mc.getItems(api, tot-txRun)
		# latestTx = txs[-1]['txid']
		helper(txs, '0')
		# for i in txs:
		# 	####################### Ignore ones with ping
		# 	######################
		# 	item = i['data']['json']
		# 	cur.execute("SELECT pubkey from icreds WHERE uid=%s", (item['id'],))
		# 	pubkey = bytes.fromhex(cur.fetchone()[0]).decode('utf-8')
		# 	orig = SHA256.new(item['data'].encode())
		# 	if pkcs.new(RSA.importKey(pubkey)).verify(orig, bytes.fromhex(item['sig'])):
		# 		if item['type'] == 'gradeinsert':
		# 			t = item['data'].split('||')
		# 			std, courses, grades = [j.split(',') for j in t]
		# 			cur.callproc('gradeinsert', (item['id'], std, courses, grades,))
		# 			if not cur.fetchone()[0]:
		# 				#Execution failed, Handle exception
		# 				with open("logs.txt", 'a') as f:
		# 					f.write(i['txid']+' gradeinsert\n')
		# 			cur.execute(stmt, (latestTx,))
		# 			conn.commit()
		# 			print(latestTx)
		# 		elif item['type'] == 'gradeupdate':
		# 			uid, course, newGrade = item['data'].split(',')
		# 			cur.callproc('gradeupdate', (item['id'], uid, course, newGrade,))
		# 			if not cur.fetchone()[0]:
		# 				with open("logs.txt", 'a') as f:
		# 					f.write(i['txid']+' gradeupdate\n')
		# 				#Execution failed, Handle exception
		# 			cur.execute(stmt, (latestTx,))
		# 			conn.commit()
		# 			print(latestTx)
		# 	else:
		# 		with open("logs.txt", 'a') as f:
		# 			f.write(i['txid']+'Signature Mismatch')
		txRun = txRun + len(txs)

# task.LoopingCall(pollAndExecute).start(timeout)
# reactor.run()


def job1(a, b):
	print(str(a) + ' ' + str(b))

app = Flask(__name__)

@app.route('/login', methods=['POST'])
def login():
	uid = request.form['uid']
	pwd = request.form['pass']
	std = request.form['student']
	cur.execute("SELECT * from icreds WHERE uid=%s", (uid,))
	row = cur.fetchall()
	response = {}
	if len(row) == 1:
		salt = row[0][1]
		phash = row[0][2]
		calc = hashlib.pbkdf2_hmac('sha256', uid.encode(), pwd.encode(), 100000).hex()
		if calc == phash:
			# session['logged_in'] = True
			# session['username'] = uid
			response['pubkey'] = row[0][3]
			response['success'] = 'S'
		else:
			response['success'] = 'N'
	else:
		response['success'] = 'N'
	return jsonify(response)

@app.route('/ping', methods=['POST'])
def ping():
	scheduler.pause()
	txid = request.form['txid']
	tx = mc.getItemByTxid(api, txid)
	r = helper([tx], '1')
	scheduler.resume()
	# print("PING", r)
	if r == 'S':
		return 'PING'
	else:
		return 'D'
# @app.route('/logout', methods=['GET', 'POST'])
# def logout():
# 	scheduler.resume()
# 	import Logout
# 	return Logout.Logout()

if __name__ == '__main__':
	app.config.from_object(Config())
	scheduler.init_app(app)
	scheduler.start()
	app.run(port=5001)