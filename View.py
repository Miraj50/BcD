from flask import session

def View(conn):
	cur = conn.cursor()
	stmt = "SELECT instr.id id, std.uid uid, std.course course, std.grade grade from instr, std WHERE instr.course=std.course AND instr.id=%s ORDER BY std.course asc"
	v = (session['username'],)
	cur.execute(stmt, v)
	ret = ""
	while True:
		row = cur.fetchone()
		if row == None:
			break
		# ret = ret+"%".join(row[1:])+"&"
		ret = ret+row[1]+"%%"+row[2]+"%"+row[3]+"&"
	return ret
