from flask import Flask, session, request
import os, psycopg2, secrets, hashlib
from flask_apscheduler import APScheduler

scheduler = APScheduler()

class Config(object):
	JOBS = [
		{
			'id': 'job1',
			'func': 'app1:job1',
			'args': (1, 2),
			'trigger': 'interval',
			'seconds': 5
		}
	]
	SCHEDULER_API_ENABLED = True


def job1(a, b):
	print(str(a) + ' ' + str(b))

app = Flask(__name__)

@app.route('/login', methods=['POST'])
def login():
	# global conn
	# getDBConn()
	scheduler.pause()
	uid = request.form['uid']
	pwd = request.form['pass']
	std = request.form['student']
	import Login
	return Login.Login(uid, pwd, std)
@app.route('/logout', methods=['GET', 'POST'])
def logout():
	scheduler.resume()
	import Logout
	return Logout.Logout()

if __name__ == '__main__':
	app.secret_key = os.urandom(12)
	app.config.from_object(Config())

	# it is also possible to enable the API directly
	# scheduler.api_enabled = True
	scheduler.init_app(app)
	scheduler.start()

	app.run()

# if __name__ == '__main__':
	# app.secret_key = os.urandom(12)
	# app.run(debug=True)


# POOL_TIME = 3 #Seconds

# # variables that are accessible from anywhere
# commonDataStruct = {}
# # lock to control access to variable
# dataLock = threading.Lock()
# # thread handler
# yourThread = threading.Thread()

# def create_app():
# 	app = Flask(__name__)

# 	def interrupt():
# 		global yourThread
# 		yourThread.cancel()

# 	def doStuff():
# 		global commonDataStruct
# 		global yourThread
# 		print("MBaba")
# 		# with dataLock:
# 		# # Do your stuff with commonDataStruct Here
# 		# 	print("MB")
# 		# Set the next thread to happen
# 		yourThread = threading.Timer(POOL_TIME, doStuff, ())
# 		yourThread.start()   

# 	def doStuffStart():
# 		# Do initialisation stuff here
# 		global yourThread
# 		# Create your thread
# 		yourThread = threading.Timer(POOL_TIME, doStuff, ())
# 		yourThread.start()

# 	@app.route('/login', methods=['POST'])
# 	def login():
# 		# global conn
# 		# getDBConn()
# 		uid = request.form['uid']
# 		pwd = request.form['pass']
# 		std = request.form['student']
# 		import Login
# 		return Login.Login(uid, pwd, std)

# 	# Initiate
# 	doStuffStart()
# 	# When you kill Flask (SIGTERM), clear the trigger for the next thread
# 	atexit.register(interrupt)
# 	return app

# app = create_app() 







# @app.route('/signup', methods=['POST'])
# def signup():
# 	uid = request.form['uid']
# 	pwd = request.form['pass']
# 	pubkey = request.form['pubkey']
# 	import Signup
# 	return Signup.Signup(uid, pwd, pubkey) # Incomplete

# @app.route('/login', methods=['POST'])
# def login():
# 	# global conn
# 	# getDBConn()
# 	uid = request.form['uid']
# 	pwd = request.form['pass']
# 	std = request.form['student']
# 	import Login
# 	return Login.Login(uid, pwd, std)

# @app.route('/view', methods=['POST'])
# def view():
# 	import View
# 	return View.View()

# @app.route('/insert', methods=['POST'])
# def insert():
# 	import Insert
# 	post_data = request.json
# 	if 'sig' in post_data:
# 		return Insert.Insert(None, None, post_data['sig'])
# 	else:
# 		data = post_data['data']
# 		count = post_data['count']
# 		return Insert.Insert(data, count)

# @app.route('/update', methods=['POST'])
# def update():
# 	uid = request.form['uid']
# 	course = request.form['course']
# 	newGrade = request.form['grade']
# 	import Update
# 	if 'sig' in request.form:
# 		return Update.Update(uid, course, newGrade, request.form['sig'])
# 	else:
# 		return Update.Update(uid, course, newGrade)

# @app.route('/logout', methods=['GET', 'POST'])
# def logout():
# 	import Logout
# 	return Logout.Logout()

