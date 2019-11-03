from twisted.internet import task, reactor
from flask import Flask, request, jsonify
import mc, psycopg2, hashlib
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5 as pkcs
from Crypto.Hash import SHA256
from flask_apscheduler import APScheduler
from collections import defaultdict
from apscheduler.schedulers.background import BackgroundScheduler
import atexit


conn = psycopg2.connect(database="rraj", user="rraj", password="Hack@hack1", host="127.0.0.1", port="5432")
cur = conn.cursor()
api = mc.getApi()
timeout = 8
txRun = mc.streamInfo(api)
stmt = "UPDATE txid SET tx=%s"

log = defaultdict(list)

import threading
import atexit

POOL_TIME = 5 #Seconds
commonDataStruct = {}
dataLock = threading.Lock()
yourThread = threading.Thread()

def interrupt():
    global yourThread
    yourThread.cancel()

def doStuff():
    global commonDataStruct
    global yourThread
    print("OOhlala", "".join(log[1]))
    with dataLock:
    # Do your stuff with commonDataStruct Here
    	log[1].append("A")
    # if "".join(log[1]) == "AA":
    # 	yourThread.cancel()
    # 	return
    yourThread = threading.Timer(POOL_TIME, doStuff)
    yourThread.start()   

def doStuffStart():
    global yourThread
    yourThread = threading.Timer(POOL_TIME, doStuff)
    yourThread.start()

doStuffStart()
# When you kill Flask (SIGTERM), clear the trigger for the next thread
atexit.register(interrupt)


def job1():
	print("OOhlala :)")

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
			response['pubkey'] = row[0][3]
			response['success'] = 'S'
		else:
			response['success'] = 'N'
	else:
		response['success'] = 'N'
	# doStuffStart()
	yourThread.cancel()
	return jsonify(response)

if __name__ == '__main__':
	app.run(port=5001)