# from twisted.internet import task, reactor
from flask import Flask, request, jsonify, session
import mc, psycopg2, hashlib
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5 as pkcs
from Crypto.Hash import SHA256
from collections import defaultdict
import atexit, threading, os, secrets
# from flask_apscheduler import APScheduler
# from apscheduler.schedulers.background import BackgroundScheduler


conn = psycopg2.connect(database="rraj", user="rraj", password="Hack@hack1", host="127.0.0.1", port="5432")
cur = conn.cursor()
api = mc.getApi()
# timeout = 8
txRun = mc.streamInfo(api)
stmt = "UPDATE txid SET tx=%s"


POOL_TIME = 5
log = defaultdict(list)

dataLock = threading.Lock()
yourThread = threading.Thread()

def interrupt():
    global yourThread
    yourThread.cancel()

# scheduler = APScheduler()
# scheduler = BackgroundScheduler()

# class Config(object):
# 	JOBS = [
# 		{
# 			'id': 'pollAndExecute',
# 			'func': 'backend:pollAndExecute',
# 			# 'args': (1, 2),
# 			'trigger': 'interval',
# 			'seconds': 8
# 		}
# 	]
# 	SCHEDULER_API_ENABLED = True

def pollAndExecute():
	# Do exception handling in cur.callproc()
	global txRun
	global log
	global yourThread

	tot = mc.streamInfo(api)
	# print(log['ss'], txRun, "tot=", tot)
	if tot == txRun:
		yourThread = threading.Timer(POOL_TIME, pollAndExecute)
		yourThread.start() 
		return
	else:
		# print("Should not reach here", tot-txRun)
		txs = mc.getItems(api, tot-txRun)
		# latestTx = txs[-1]['txid']
		# helper(txs, '0')
		for i in txs:
			item = i['data']['json']
			cur.execute("SELECT pubkey from icreds WHERE uid=%s", (item['id'],))
			pubkey = bytes.fromhex(cur.fetchone()[0]).decode('utf-8')
			orig = SHA256.new(item['data'].encode())
			if len(item['data'])<100:
				abridge = item['data']
			else:
				abridge = item['data'][:100]+"....."+item['data'][-10:]
			if pkcs.new(RSA.importKey(pubkey)).verify(orig, bytes.fromhex(item['sig'])):
				if item['type'] == 'gradeinsert':
					t = item['data'].split('||')
					std, courses, grades = [j.split(',') for j in t]
					cur.callproc('gradeinsert', (item['id'], std, courses, grades,))
					if not cur.fetchone()[0]:
						#Execution failed, Handle exception
						# with dataLock:
						log[item['id']].append(abridge+"  (Insert)  FAILURE")
						with open("logs.txt", 'a') as f:
							f.write(i['txid']+' gradeinsert\n')
					else:
						# with dataLock:
						log[item['id']].append(abridge+"  (Insert)  SUCCESS")
					txRun = txRun + 1 
					# print('inside poll', log['ss'])
					cur.execute(stmt, (i['txid'],))
					conn.commit()
					print('INSERT', i['txid'])
				elif item['type'] == 'gradeupdate':
					uid, course, newGrade = item['data'].split(',')
					cur.callproc('gradeupdate', (item['id'], uid, course, newGrade,))
					if not cur.fetchone()[0]:
						# with dataLock:
						log[item['id']].append(abridge+"  (Update)  FAILURE")
						with open("logs.txt", 'a') as f:
							f.write(i['txid']+' gradeupdate\n')
						#Execution failed, Handle exception
					else:
						# with dataLock:
						log[item['id']].append(abridge+"  (Update)  SUCCESS")
					txRun = txRun + 1

					# print('inside pollu', log['ss'])
					cur.execute(stmt, (i['txid'],))
					conn.commit()
					print('UPDATE', i['txid'])
				elif item['type'] == 'userenroll':
					t = item['data'].split(',')
					salt = secrets.token_hex(32)
					phash = hashlib.pbkdf2_hmac('sha256', salt.encode(), t[1].encode(), 100000).hex()
					# print(t, salt, phash)
					cur.callproc('userenroll', (t[0], salt, phash, t[2],))
					if not cur.fetchone()[0]:
						# with dataLock:
						log[item['id']].append(abridge+"  (Enroll)  FAILURE")
						with open("logs.txt", 'a') as f:
							f.write(i['txid']+' userenroll\n')
					else:
						# with dataLock:
						log[item['id']].append(abridge+"  (Enroll)  SUCCESS")
					txRun = txRun + 1 
					cur.execute(stmt, (i['txid'],))
					conn.commit()
					print('ENROLL', i['txid'])

				elif item['type'] == 'updatepubkey':
					t = item['data'].split(',')
					cur.callproc(item['type'], (t[0], t[1],))
					if not cur.fetchone()[0]:
						# with dataLock:
						log[item['id']].append(abridge+"  (UPK)  FAILURE")
						with open("logs.txt", 'a') as f:
							f.write(i['txid']+' updatepubkey\n')
					else:
						# with dataLock:
						log[item['id']].append(abridge+"  (UPK)  SUCCESS")
					txRun = txRun + 1 
					cur.execute(stmt, (i['txid'],))
					conn.commit()
					print('PUBKEY', i['txid'])

				elif item['type'] == 'updatesqlpr':
					cur.callproc(item['type'], (item['data'],))
					if not cur.fetchone()[0]:
						# with dataLock:
						log[item['id']].append(abridge+"  (SQLF)  UNKNOWN")
						with open("logs.txt", 'a') as f:
							f.write(i['txid']+' updatepubkey\n')
					else:
						# with dataLock:
						log[item['id']].append(abridge+"  (SQLF)  UNKNOWN")
					txRun = txRun + 1 
					cur.execute(stmt, (i['txid'],))
					conn.commit()
					print('SQL Proc', i['txid'])

				elif item['type'] == 'instrcourses':
					t = item['data'].split('||')
					cur.callproc(item['type'], ([t[0] for i in t[1].split(',')], [i.strip() for i in t[1].split(',')],))
					if not cur.fetchone()[0]:
						# with dataLock:
						log[item['id']].append(abridge+"  (I-Course)  FAILURE")
						with open("logs.txt", 'a') as f:
							f.write(i['txid']+' updatepubkey\n')
					else:
						# with dataLock:
						log[item['id']].append(abridge+"  (I-Course)  SUCCESS")
					txRun = txRun + 1 
					cur.execute(stmt, (i['txid'],))
					conn.commit()
					print('INSTR COURSES', i['txid'])
			else:
				with open("logs.txt", 'a') as f:
					f.write(i['txid']+' Signature Mismatch')

	yourThread = threading.Timer(POOL_TIME, pollAndExecute)
	yourThread.start() 
		# txRun = txRun + len(txs)

def startWork():
    global yourThread
    yourThread = threading.Timer(POOL_TIME, pollAndExecute)
    yourThread.start()

def job1():
	print("OOhlala :)")
	# print(scheduler.get_job('123'))
	scheduler.run_job(scheduler.get_job('123'))

# task.LoopingCall(job1).start(timeout)
# reactor.run()


# scheduler.add_job(id='123', func=job1, trigger="interval", seconds=5)
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
		calc = hashlib.pbkdf2_hmac('sha256', salt.encode(), pwd.encode(), 100000).hex()
		if calc == phash:
			session['user'] = uid
			response['pubkey'] = row[0][3]
			response['success'] = 'S'
			if uid == 'admin':
				response['admin'] = '1'
			else:
				response['admin'] = '0'
		else:
			response['success'] = 'N'
	else:
		response['success'] = 'N'
	return jsonify(response)

@app.route('/ping', methods=['POST'])
def ping():
	global log
	global txRun
	global yourThread
	yourThread.cancel()
	# scheduler.pause()
	# txid = request.form['txid']
	# tx = mc.getItemByTxid(api, txid)
	# r = helper([tx], '1')
	pollAndExecute()
	# scheduler.resume()
	user = request.form['id']
	if user in log:
		r = log.pop(request.form['id'])
	else:
		r = []
	# with dataLock:
		# r = log.pop(request.form['id'])
	# print("returning after pop", log['ss'], txRun)
	return "\n\n".join(r)

# @app.route('/logout', methods=['GET', 'POST'])
# def logout():
# 	session.pop('user', None)
# 	return 'S'

if __name__ == '__main__':
	app.secret_key = os.urandom(12)
	# app.config.from_object(Config())
	# scheduler.init_app(app)
	# scheduler.start()
	# atexit.register(lambda: scheduler.shutdown())
	startWork()
	app.run(port=5001)