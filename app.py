from flask import Flask, session, request, jsonify
import os, psycopg2, secrets, hashlib, requests

app = Flask(__name__)

@app.route('/signup', methods=['POST'])
def signup():
	import Signup
	if 'sig' in request.form:
		return Signup.Signup(None, None, None, request.form['sig'])
	else:
		uid = request.form['uid']
		pwd = request.form['pass']
		pubkey = request.form['pubkey']
		return Signup.Signup(uid, pwd, pubkey)

@app.route('/updatepk', methods=['POST'])
def updatepk():
	import UpdateAdmin
	if 'sig' in request.form:
		return UpdateAdmin.UpdatePk(None, None, request.form['sig'])
	else:
		uid = request.form['uid']
		pubkey = request.form['pubkey']
		return UpdateAdmin.UpdatePk(uid, pubkey)

@app.route('/instrcourses', methods=['POST'])
def instrcourses():
	import UpdateAdmin
	if 'sig' in request.form:
		return UpdateAdmin.InstrCourses(None, None, request.form['sig'])
	else:
		uid = request.form['uid']
		courses = request.form['crs']
		return UpdateAdmin.InstrCourses(uid, courses)

@app.route('/execfunc', methods=['POST'])
def execfunc():
	import UpdateAdmin
	if 'sig' in request.form:
		return UpdateAdmin.ExecFunc(None, None, request.form['sig'])
	else:
		func = request.form['func']
		param = request.form['param']
		return UpdateAdmin.ExecFunc(func, param)

@app.route('/updatesqpr', methods=['POST'])
def updatesqpr():
	import UpdateAdmin
	if 'sig' in request.form:
		return UpdateAdmin.UpdateSQPr(None, request.form['sig'])
	else:
		pr = request.form['sqpr']
		return UpdateAdmin.UpdateSQPr(pr)

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

@app.route('/poke', methods=['POST'])
def poke():
	url = 'http://localhost:5001/ping'
	try:
		# response = requests.post(url, data={'txid':txid})
		response = requests.post(url, data={'id': session['username']})
	except (ConnectionError, requests.exceptions.RequestException) as e:
		return jsonify({'status':'D', 'data':''})
	else:
		return jsonify({'status':'PING', 'data':response.text})

@app.route('/idbi', methods=['POST'])
def idbi():
	url1 = 'http://localhost:5001/idbi'
	url2 = 'http://10.129.125.52:5007/idbi'
	ret = None
	try:
		data1 = {'data': ['God']}
		data2 = {'data': ['God']}
		r1 = requests.post(url1, json=data1).json()
		r2 = requests.post(url2, json=data2).json()
		if r1['children'][0] == r2['children'][0]:
			ret = ":)"
		else:
			while True:
				# print("Hola",r1['children'], r2['children'])
				diff1, diff2 = [], []
				if r1['leaf']=='1' or r2['leaf']==1:
					break 
				for i,j in zip(r1['children'], r2['children']):
					if i!=j:
						diff1.append(i)
						diff2.append(j)
				data1['data'] = diff1
				data2['data'] = diff2
				r1 = requests.post(url1, json=data1).json()
				r2 = requests.post(url2, json=data2).json()
	except (ConnectionError, requests.exceptions.RequestException) as e:
		return jsonify({'status':'D', 'data':''})
	else:
		if ret!=':)':
			print(r1['children'])
			print(r2['children'])
			l1 = ", ".join(list(set(r1['children']) - set(r2['children'])))
			l2 = ", ".join(list(set(r2['children']) - set(r1['children'])))
			print(l1,l2)
			ret = l1+"\n\n"+l2
		return jsonify({'status':'VERIFY', 'data':ret})

@app.route('/insert', methods=['POST'])
def insert():
	import Insert
	post_data = request.json
	if 'sig' in post_data:
		return Insert.Insert(None, None, post_data['sig'])
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
	# app.secret_key = "OOkay"
	app.run(debug=True)