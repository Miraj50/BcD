from flask import session
import requests

def Logout():
	# conn.close()
	# response = requests.post('http://localhost:5001/logout')
	session.pop('logged_in', None)
	session.pop('username', None)
	return 'S'
	# return response.text