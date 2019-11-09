from flask import Flask, request, jsonify, session
import mc, psycopg2, hashlib, ast
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5 as pkcs
from Crypto.Hash import SHA256
from collections import defaultdict
import atexit, threading, os, secrets, time
# from flask_apscheduler import APScheduler
from apscheduler.schedulers.background import BackgroundScheduler

conn = psycopg2.connect(database="rraj", user="rraj", password="Hack@hack1", host="127.0.0.1", port="5432")
cur = conn.cursor()
api = mc.getApi()

txRun = mc.streamInfo(api)
stmt = "UPDATE txid SET tx=%s"

POOL_TIME = 5
log = defaultdict(list)

# scheduler = APScheduler()
scheduler = BackgroundScheduler()
check = threading.Event()

def pollAndExecute():
	# Do exception handling in cur.callproc()
	check.clear()
	global txRun, log
	# print(time.time(), x)
	tot = mc.streamInfo(api)
	# print(log['ss'], txRun, "tot=", tot)
	if tot == txRun:
		check.set()
		return
	else:
		txs = mc.getItems(api, tot-txRun)
		# latestTx = txs[-1]['txid']
		# helper(txs, '0')
		for i in txs:
			item = i['data']['json']
			cur.execute("SELECT pubkey from icreds WHERE uid=%s", (item['id'],))
			pubkey = bytes.fromhex(cur.fetchone()[0]).decode('utf-8')
			# print(pubkey)
			orig = SHA256.new(item['data'].encode())
			if len(item['data'])<100:
				abridge = item['data']
			else:
				abridge = item['data'][:100]+"....."+item['data'][-10:]
			if pkcs.new(RSA.importKey(pubkey)).verify(orig, bytes.fromhex(item['sig'])):
				if item['type'] == 'gradeinsert':
					t = item['data'].split('||')
					std, courses, grades = [j.split(',') for j in t]
					try:
						cur.callproc('gradeinsert', (item['id'], std, courses, grades,))
						res = cur.fetchone()[0]
						err = res[1:]
					except psycopg2.Error as e:
						err = e.diag.message_primary
						log[item['id']].append(abridge+"  (Update)  \u2718 "+err)
						conn.rollback()
					else:
						if res[0] == '0':
							log[item['id']].append(abridge+"  (Insert)  \u2718 "+err)
							with open("logs.txt", 'a') as f:
								f.write(i['txid']+' gradeinsert\n')
						else:
							log[item['id']].append(abridge+"  (Insert)  \u2714")
						# txRun = txRun + 1
						
					finally:
						cur.execute(stmt, (i['txid'],))
						conn.commit()
						print('INSERT', i['txid'])
						txRun = txRun + 1
				elif item['type'] == 'gradeupdate':
					uid, course, newGrade = item['data'].split(',')
					try:
						cur.callproc('gradeupdate', (item['id'], uid, course, newGrade,))
						res = cur.fetchone()[0]
						err = res[1:]
					except psycopg2.Error as e:
						err = e.diag.message_primary
						log[item['id']].append(abridge+"  (Update)  \u2718 "+err)
						conn.rollback()
					else:
						if res[0] == '0':
							log[item['id']].append(abridge+"  (Update)  \u2718 "+err)
							with open("logs.txt", 'a') as f:
								f.write(i['txid']+' gradeupdate\n')
						else:
							log[item['id']].append(abridge+"  (Update)  \u2714")
					finally:
						cur.execute(stmt, (i['txid'],))
						conn.commit()
						print('UPDATE', i['txid'])
						txRun = txRun + 1
				elif item['type'] == 'userenroll':
					t = item['data'].split(',')
					salt = secrets.token_hex(32)
					phash = hashlib.pbkdf2_hmac('sha256', salt.encode(), t[1].encode(), 100000).hex()
					try:
						cur.callproc('userenroll', (t[0], salt, phash, t[2],))
						res = cur.fetchone()[0]
						err = res[1:]
					except psycopg2.Error as e:
						err = e.diag.message_primary
						log[item['id']].append(abridge+"  (Enroll)  \u2718 "+err)
						conn.rollback()
					else:
						if res[0] == '0':
							log[item['id']].append(abridge+"  (Enroll)  \u2718 "+err)
							with open("logs.txt", 'a') as f:
								f.write(i['txid']+' userenroll\n')
						else:
							log[item['id']].append(abridge+"  (Enroll)  \u2714")
						# txRun = txRun + 1
					finally:
						cur.execute(stmt, (i['txid'],))
						conn.commit()
						print('ENROLL', i['txid'])
						txRun = txRun + 1

				elif item['type'] == 'updatepubkey':
					t = item['data'].split(',')
					try:
						cur.callproc(item['type'], (t[0], t[1],))
						res = cur.fetchone()[0]
						err = res[1:]
					except psycopg2.Error as e:
						err = e.diag.message_primary
						log[item['id']].append(abridge+"  (UPK)  \u2718 "+err)
						conn.rollback()
					else:
						if res[0] == '0':
							log[item['id']].append(abridge+"  (UPK)  \u2718 "+err)
							with open("logs.txt", 'a') as f:
								f.write(i['txid']+' updatepubkey\n')
						else:
							log[item['id']].append(abridge+"  (UPK)  \u2714")
						# txRun = txRun + 1
					finally:
						cur.execute(stmt, (i['txid'],))
						conn.commit()
						print('PUBKEY', i['txid'])
						txRun = txRun + 1

				elif item['type'] == 'updatesqlpr':
					try:
						cur.callproc(item['type'], (item['data'],))
						res = cur.fetchone()[0]
						err = res[1:]
					except psycopg2.Error as e:
						err = e.diag.message_primary
						log[item['id']].append(abridge+"  (SQLF)  \u2718 "+err)
						conn.rollback()
					else:
						if res[0] == '0':
							log[item['id']].append(abridge+"  (SQLF) \ufe16 UNKNOWN")
							with open("logs.txt", 'a') as f:
								f.write(i['txid']+' updatepubkey\n')
						else:
							log[item['id']].append(abridge+"  (SQLF) \ufe16 UNKNOWN")
						# txRun = txRun + 1
					finally:
						cur.execute(stmt, (i['txid'],))
						conn.commit()
						print('SQL Proc', i['txid'])
						txRun = txRun + 1

				elif item['type'] == 'instrcourses':
					t = item['data'].split('||')
					try:
						cur.callproc(item['type'], ([t[0] for i in t[1].split(',')], [i.strip() for i in t[1].split(',')],))
						res = cur.fetchone()[0]
						err = res[1:]
					except psycopg2.Error as e:
						err = e.diag.message_primary
						log[item['id']].append(abridge+"  (I-Course)  \u2718 "+err)
						conn.rollback()
					else:
						if res[0] == '0':
							log[item['id']].append(abridge+"  (I-Course)  \u2718 "+err)
							with open("logs.txt", 'a') as f:
								f.write(i['txid']+' updatepubkey\n')
						else:
							log[item['id']].append(abridge+"  (I-Course)  \u2714")
						# txRun = txRun + 1
					finally:
						cur.execute(stmt, (i['txid'],))
						conn.commit()
						print('INSTR COURSES', i['txid'])
						txRun = txRun + 1
				else:
					t = item['data'].split('||')
					funcname = t[0]
					params = t[1].split()
					try:
						if len(params) == 0:
							cur.callproc(item['type'])
						elif len(params) == 1:
							cur.callproc(item['type'], (ast.literal_eval(params[0]),))
						else:
							cur.callproc(item['type'], tuple(map(ast.literal_eval, params)))
						res = cur.fetchone()[0]
						# err = res[1:]
					except psycopg2.Error as e:
						err = e.diag.message_primary
						log[item['id']].append(abridge+"  (Exec-Func)  \u2718 "+err)
						conn.rollback()
					else:
						log[item['id']].append(abridge+"  (Exec-Func)  : "+str(res))
					finally:
						cur.execute(stmt, (i['txid'],))
						conn.commit()
						print('EXEC FUNC', i['txid'])
						txRun = txRun + 1
			else:
				with open("logs.txt", 'a') as f:
					f.write(i['txid']+' Signature Mismatch')
		check.set()
	# print(time.time(), "E")

# def job1():
# 	print("OOhlala :)")
# 	# print(scheduler.get_job('123'))
# 	scheduler.run_job(scheduler.get_job('123'))

# task.LoopingCall(job1).start(timeout)
# reactor.run()
scheduler.add_job(id='123', func=pollAndExecute, trigger="interval", seconds=POOL_TIME)
scheduler.start()

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
	check.wait()
	global log, txRun
	# global txRun
	# global yourThread
	# yourThread.cancel()
	# scheduler.pause()
	# txid = request.form['txid']
	# tx = mc.getItemByTxid(api, txid)
	# r = helper([tx], '1')

	scheduler.remove_job('123')
	pollAndExecute()
	# scheduler.resume()
	user = request.form['id']
	if user in log:
		r = log.pop(request.form['id'])
	else:
		r = []
	scheduler.add_job(id='123', func=pollAndExecute, trigger="interval", seconds=POOL_TIME)

	return "\n\n".join(r)

if __name__ == '__main__':
	app.secret_key = os.urandom(12)
	# scheduler.init_app(app)
	# scheduler.start()
	# atexit.register(lambda: scheduler.shutdown())
	app.run(port=5001)