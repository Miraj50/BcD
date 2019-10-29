from twisted.internet import task, reactor
import mc, psycopg2

conn = psycopg2.connect(database="rraj", user="rraj", password="Hack@hack1", host="127.0.0.1", port="5432")
cur = conn.cursor()
api = mc.getApi()
timeout = 3
txRun = 83 #########
stmt = "UPDATE txid SET tx=%s"

def pollAndExecute():
	# Do exception handling in cur.callproc()
	global txRun
	tot = mc.streamInfo(api)
	if tot == txRun:
		return
	else:
		txs = mc.getItems(api, tot-txRun)
		latestTx = txs[-1]['txid']
		for i in txs:
			item = i['data']['json']
			if item['type'] == 'gradeinsert':
				t = item['data'].split('||')
				std, courses, grades = [j.split(',') for j in t]
				cur.callproc('gradeinsert', (item['id'], std, courses, grades,))
				if not cur.fetchone()[0]:
					#Execution failed, Handle exception
					with open("logs.txt", 'a') as f:
						f.write(i['txid']+' gradeinsert\n')
				cur.execute(stmt, (latestTx,))
				conn.commit()
				print(latestTx)
			elif item['type'] == 'gradeupdate':
				uid, course, newGrade = item['data'].split(',')
				cur.callproc('gradeupdate', (item['id'], uid, course, newGrade,))
				if not cur.fetchone()[0]:
					with open("logs.txt", 'a') as f:
						f.write(i['txid']+' gradeupdate\n')
					#Execution failed, Handle exception
				cur.execute(stmt, (latestTx,))
				conn.commit()
				print(latestTx)
		txRun = txRun + len(txs)

task.LoopingCall(pollAndExecute).start(timeout)
reactor.run()