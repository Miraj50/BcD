from flask import Flask, request, jsonify, session
import mc, psycopg2, hashlib, ast, math
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5 as pkcs
from Crypto.Hash import SHA256
from collections import defaultdict
import threading, os, secrets, time
import select, socket, requests
from anytree import Node, RenderTree, LevelOrderIter
from itertools import product

conn = psycopg2.connect(database="rraj", user="rraj", password="Hack@hack1", host="127.0.0.1", port="5432")
cur = conn.cursor()
api = mc.getApi()

txRun = mc.streamInfo(api)
stmt = "UPDATE txid SET tx=%s"

POOL_TIME = 5
log = defaultdict(list)

makeTree = 1 ########################################################################################

def pollAndExecute():
	global txRun, log
	# print(time.time(), x)
	tot = mc.streamInfo(api)
	if tot == txRun:
		return
	else:
		makeTree = 1
		txs = mc.getItems(api, tot-txRun)
		# latestTx = txs[-1]['txid']
		for i in txs:
			item = i['data']['json']
			cur.execute("SELECT pubkey from icreds WHERE uid=%s", (item['id'],))
			pubkey = bytes.fromhex(cur.fetchone()[0]).decode('utf-8')
			# print(pubkey)
			orig = SHA256.new(item['data'].encode())
			if len(item['data'])<100:
				abridge = item['data']
			else:
				abridge = item['data'][:90]+"....."+item['data'][-20:]
			if pkcs.new(RSA.importKey(pubkey)).verify(orig, bytes.fromhex(item['sig'])):
				if item['type'] == 'gradeinsert':
					t = item['data'].split('||')
					std, courses, grades, [func] = [j.split(',') for j in t]
					try:
						cur.callproc(func, (item['id'], std, courses, grades,))
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
						txRun = txRun + 1
						print('INSERT', i['txid'])
				elif item['type'] == 'gradeupdate':
					uid, course, newGrade, func = item['data'].split(',')
					try:
						cur.callproc(func, (item['id'], uid, course, newGrade,))
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
						txRun = txRun + 1
						print('UPDATE', i['txid'])
				elif item['type'] == 'userenroll':
					t = item['data'].split(',')
					salt = secrets.token_hex(32)
					phash = hashlib.pbkdf2_hmac('sha256', salt.encode(), t[1].encode(), 100000).hex()
					try:
						cur.callproc(t[3], (t[0], salt, phash, t[2],))
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
						txRun = txRun + 1
						print('ENROLL', i['txid'])

				elif item['type'] == 'updatepubkey':
					t = item['data'].split(',')
					try:
						cur.callproc(t[2], (t[0], t[1],))
						res = cur.fetchone()[0]
						err = res[1:]
					except psycopg2.Error as e:
						err = e.diag.message_primary
						log[item['id']].append(abridge+"  (UpK)  \u2718 "+err)
						conn.rollback()
					else:
						if res[0] == '0':
							log[item['id']].append(abridge+"  (UpK)  \u2718 "+err)
							with open("logs.txt", 'a') as f:
								f.write(i['txid']+' updatepubkey\n')
						else:
							log[item['id']].append(abridge+"  (UpK)  \u2714")
						# txRun = txRun + 1
					finally:
						cur.execute(stmt, (i['txid'],))
						conn.commit()
						txRun = txRun + 1
						print('PUBKEY', i['txid'])

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
							log[item['id']].append(abridge+"  (SQLF) \u2718 "+err)
							with open("logs.txt", 'a') as f:
								f.write(i['txid']+' updatesqlpr\n')
						else:
							log[item['id']].append(abridge+"  (SQLF) \u2714")
						# txRun = txRun + 1
					finally:
						cur.execute(stmt, (i['txid'],))
						conn.commit()
						txRun = txRun + 1
						print('SQL Proc', i['txid'])

				elif item['type'] == 'instrcourses':
					t = item['data'].split('||')
					try:
						cur.callproc(t[2], ([t[0] for i in t[1].split(',')], [i.strip() for i in t[1].split(',')],))
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
								f.write(i['txid']+' instrcourses\n')
						else:
							log[item['id']].append(abridge+"  (I-Course)  \u2714")
						# txRun = txRun + 1
					finally:
						cur.execute(stmt, (i['txid'],))
						conn.commit()
						txRun = txRun + 1
						print('INSTR COURSES', i['txid'])
				else: # Execute SQL functions
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
						txRun = txRun + 1
						print('EXEC FUNC', i['txid'])
			else:
				with open("logs.txt", 'a') as f:
					f.write(i['txid']+' Signature Mismatch')
		# check.set()
	# print(time.time(), "E")

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setblocking(0)
server_address = ('localhost', 5002)
# print('starting up on %s port %s' % server_address)
server.bind(server_address)
# Listen for incoming connections
server.listen(2)
inputs = [server] # Sockets from which we expect to read
outputs = [] # Sockets to which we expect to write

def work():
	global log
	while inputs:
		# print(time.time(), 'Waiting for the next event')
		readable, writable, exceptional = select.select(inputs, outputs, inputs, POOL_TIME)
		if not (readable or writable or exceptional):
			pollAndExecute()
			continue
		for s in readable:
			if s is server:
				# A "readable" server socket is ready to accept a connection
				connection, client_address = s.accept()
				# print('new connection from', client_address)
				connection.setblocking(0)
				pollAndExecute()
				inputs.append(connection)
			else:
				data = s.recv(1024)
				if s not in outputs:
					outputs.append(s)
		# Handle outputs
		for s in writable:
			r = ("HTTP/1.1 200 OK\n"
				+"Content-Type: text/html\n"
				+"\n").encode()
			s.send(r)
			inputs.remove(s)
			outputs.remove(s)
			s.close()

pollThread = threading.Thread(target=work)

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
	# print("threads = ", threading.active_count())
	global log
	response = requests.post('http://localhost:5002')
	user = request.form['id']
	if user in log:
		r = log.pop(request.form['id'])
	else:
		r = []
	return "\n\n".join(r)

h1_bits = 0
def base_k(x, k):
	t = []
	while x!=0:
		t.append(x%k)
		x = x//k
	return "".join(map(str, t))[:h1_bits]

mtree = None
h1 = defaultdict(list)
leaves = {}

@app.route('/idbi', methods=['POST'])
def idbi():
	global makeTree, mtree, h1_bits, h1, leaves
	if makeTree == 1: #Change it to 1
		print("making Merkle tREE")
		stmt = "SELECT * FROM std"
		cur.execute(stmt)
		tuples = cur.fetchall()
		k = 3 # No. of children of a node in a Merkle Tree. Change as per your choice
		ntuples = len(tuples)
		if ntuples<k:
			n = 1
		else:
			n = math.floor(math.log(ntuples, k))
		h1_bits = n
		digest_size = 4
		for i in tuples:
			dgst = hashlib.blake2b((i[0]+" "+i[1]).encode(), digest_size=digest_size).hexdigest()
			dgst_int = int(dgst, 16)
			h1[base_k(dgst_int, k)].append(" ".join(i))
		print(h1)
		st = "".join(map(str, range(k)))
		mtree = {'root': Node('root')}
		node_ids = ["".join(seq) for i in range(1, n+1) for seq in product(st, repeat=i)]
		for i in node_ids:
			if len(i)==1:
				mtree[i] = Node(i, parent=mtree['root'])
			else:
				mtree[i] = Node(i, parent=mtree[i[:-1]])
		for i in reversed(node_ids): # Find hash values for leaves
			if len(i) == n:
				leaf_hash = hashlib.sha1("".join(sorted([hashlib.sha1(j.encode()).hexdigest() for j in h1[i]])).encode()).hexdigest()
				mtree[i].hash = leaf_hash
				leaves[leaf_hash] = i
			else:
				break
		for i in range(len(node_ids), 0, -k):
			node = node_ids[i-1]
			if len(node) != 1:
				nodeid = node_ids[i-1][:-1]
			else:
				nodeid = 'root'
			mtree[nodeid].hash = hashlib.sha1("".join(sorted([mtree[j].hash for j in node_ids[i-k:i]])).encode()).hexdigest()
		makeTree = 0
		# print(RenderTree(mtree['root']))
	postdata = request.json
	children = []
	for nodeitem in postdata['data']:
		if nodeitem in ['GOD', 'god', 'God']:
			children = [mtree['root'].hash]
		else:
			children += [node.hash for node in LevelOrderIter(mtree['root']) if node.parent!=None and node.parent.hash==nodeitem]
	if children == []:
		# print([j for i in postdata["data"] for j in h1[leaves[i]]])
		return jsonify({"children": [j for i in postdata["data"] for j in h1[leaves[i]]], "leaf": "1"})

	return jsonify({'children': children, "leaf": "0"})

if __name__ == '__main__':
	app.secret_key = os.urandom(12)
	# pollThread.start()
	app.run(port=5001)