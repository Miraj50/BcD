from flask import Flask, session, request
import os, psycopg2, secrets, hashlib

app = Flask(__name__)

# conn = None
# def getDBConn():
# 	global conn
# 	if conn is None or conn.closed != 0:
# 		conn = psycopg2.connect(database="rraj", user="rraj", password="Hack@hack1", host="127.0.0.1", port="5432")

@app.route('/signup', methods=['POST'])
def signup():
	uid = request.form['uid']
	pwd = request.form['pass']
	pubkey = request.form['pubkey']
	import Signup
	return Signup.Signup(uid, pwd, pubkey) # Incomplete

@app.route('/login', methods=['POST'])
def login():
	uid = request.form['uid']
	pwd = request.form['pass']
	std = request.form['student']
	import Login
	return Login.Login(uid, pwd, std)

@app.route('/view', methods=['POST'])
def view():
	import View
	return View.View()

@app.route('/insert', methods=['POST'])
def insert():
	import Insert
	post_data = request.json
	if 'sig' in post_data:
		return Insert.Insert(None, None, post_data['ping'], post_data['sig'])
	else:
		data = post_data['data']
		count = post_data['count']
		return Insert.Insert(data, count)

@app.route('/update', methods=['POST'])
def update():
	uid = request.form['uid']
	course = request.form['course']
	newGrade = request.form['grade']
	import Update
	if 'sig' in request.form:
		return Update.Update(uid, course, newGrade, request.form['sig'])
	else:
		return Update.Update(uid, course, newGrade)

@app.route('/logout', methods=['GET', 'POST'])
def logout():
	import Logout
	return Logout.Logout()

if __name__ == '__main__':
	app.secret_key = os.urandom(12)
	app.run(debug=True)