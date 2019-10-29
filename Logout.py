from flask import session

def Logout():
	# conn.close()
	session.pop('logged_in', None)
	session.pop('username', None)
	return 'S'