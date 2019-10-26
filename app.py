from flask import Flask, session, request
import os, psycopg2, secrets, hashlib

app = Flask(__name__)

conn = None
def getDBConn():
	global conn
	if conn is None or conn.closed != 0:
		conn = psycopg2.connect(database="rraj", user="rraj", password="Hack@hack1", host="127.0.0.1", port="5432")

@app.route('/signup', methods=['POST'])
def signup():
	global conn
	getDBConn()
	uid = request.form['uid']
	pwd = request.form['pass']
	pubkey = request.form['pubkey']
	import Signup
	return Signup.Signup(conn, uid, pwd, pubkey)
	# cur.execute("SELECT * from icreds WHERE uid=%s", (uid,))
	# if cur.fetchone():
	# 	return "M"
	# else:
	# 	salt = secrets.token_hex(32)
	# 	phash = hashlib.pbkdf2_hmac('sha256', uid.encode(), pwd.encode(), 100000).hex()
	# 	cur.execute("INSERT INTO icreds (uid, salt, hash) VALUES (%s, %s, %s)", (uid, salt, phash,))
	# 	conn.commit()
	# 	return "S"

@app.route('/login', methods=['POST'])
def login():
	global conn
	getDBConn()
	uid = request.form['uid']
	pwd = request.form['pass']
	std = request.form['student']
	import Login
	return Login.Login(conn, uid, pwd, std)

@app.route('/view', methods=['POST'])
def view():
	global conn
	import View
	return View.View(conn)

@app.route('/insert', methods=['POST'])
def insert():
	global conn
	import Insert
	post_data = request.json
	if 'sig' in post_data:
		return Insert.Insert(conn, None, None, post_data['sig'])
	else:
		data = post_data['data']
		count = post_data['count']
		return Insert.Insert(conn, data, count)

@app.route('/update', methods=['POST'])
def update():
	global conn
	uid = request.form['uid']
	course = request.form['course']
	newGrade = request.form['grade']
	import Update
	if 'sig' in request.form:
		return Update.Update(conn, uid, course, newGrade, request.form['sig'])
	else:
		return Update.Update(conn, uid, course, newGrade)

@app.route('/logout', methods=['GET', 'POST'])
def logout():
	global conn
	import Logout
	return Logout.Logout(conn)

if __name__ == '__main__':
	app.secret_key = os.urandom(12)
	app.run(debug=True)