from flask import session
import psycopg2.extras

def Insert(conn, data, count):
	# Do the checks
	cur = conn.cursor()
	v = [tuple(i.values()) for i in data]
	stmt = "INSERT INTO std (uid, course, grade) VALUES %s"
	template = ','.join(['%s'] * len(v))
	stmt_ = "INSERT INTO std (uid, course, grade) VALUES {}".format(template) 
	query = cur.mogrify(stmt_, v).decode('utf-8')
	import mc
	try:
		api = mc.getApi()
		txid = mc.publishItem(api, session['username'], query)
	except:
		print("MultiChain Error")
		return "UFO"
	else:
		psycopg2.extras.execute_values(cur, stmt, v)
		conn.commit()
		return "S"