from flask import Flask, request
import threading, os, time
from apscheduler.schedulers.background import BackgroundScheduler
from collections import defaultdict

import select
import socket
import sys
import queue

def poll(a):
	print(time.time(), a)
	time.sleep(1)



# server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# server.setblocking(0)


# server_address = ('localhost', 5001)
# print('starting up on %s port %s' % server_address)
# server.bind(server_address)

# Listen for incoming connections
# server.listen(1)
# Sockets from which we expect to read
inputs = [ server ]

# Sockets to which we expect to write
outputs = [ ]
message_queues = {}


def oohlala():

	while inputs:
		print(time.time(), "inside oohlala")
		# Wait for at least one of the sockets to be ready for processing
		print('\nwaiting for the next event')
		readable, writable, exceptional = select.select(inputs, outputs, inputs, 5)
		if not (readable or writable or exceptional):
			poll('||')
			continue
		for s in readable:
			# if s is server:
				# A "readable" server socket is ready to accept a connection
			# connection, client_address = s.accept()
			# print('new connection from', client_address)
			# connection.setblocking(0)
			poll('@@')
			readable.pop()
			# connection.close()
				# inputs.append(connection)

				# Give the connection a queue for data we want to send
				# message_queues[connection] = queue.Queue()
			# else:
			# 	data = s.recv(1024)
			# 	if data:
			# 		# A readable client socket has data
			# 		print('received "%s" from %s' % (data, s.getpeername()))
			# 		message_queues[s].put(data)
			# 		# Add output channel for response
			# 		if s not in outputs:
			# 			outputs.append(s)
			# 	else:
			# 		# Interpret empty result as closed connection
			# 		print('closing', client_address, 'after reading no data')
			# 		# Stop listening for input on the connection
			# 		if s in outputs:
			# 			outputs.remove(s)
			# 		inputs.remove(s)
			# 		s.close()

			# 		# Remove message queue
			# 		del message_queues[s]
		# Handle outputs
		# for s in writable:
		# 	try:
		# 		next_msg = message_queues[s].get_nowait()
		# 	except queue.Empty:
		# 		# No messages waiting so stop checking for writability.
		# 		print('output queue for', s.getpeername(), 'is empty')
		# 		outputs.remove(s)
		# 	else:
		# 		print('sending "%s" to %s' % (next_msg, s.getpeername()))
		# 		s.send(next_msg)
pollThread = threading.Thread(target=oohlala)



# POOL_TIME = 5
# log = defaultdict(list)
# i=1
# myThread = None
# r = threading.Event()
# r.set()

def startWork():
	global myThread
	myThread = threading.Timer(POOL_TIME, poll)
	myThread.start()

# scheduler = BackgroundScheduler()
# scheduler.add_job(id='123', func=poll, args=['|'], trigger="interval", seconds=POOL_TIME)
# scheduler.start()

app = Flask(__name__)

@app.route('/ping', methods=['POST'])
def ping():
	# global log
	inputs.append(request.form['id'])
	print(inputs)
	# r.wait()
	# scheduler.remove_job('123')
	# poll("@")
	print(log[1])
	# scheduler.add_job(id='123', func=poll, args=['|'], trigger="interval", seconds=POOL_TIME)


	return "Hello"

@app.route('/mb', methods=['POST'])
def mb():
	return "MeraBaba Testing 101"

if __name__ == '__main__':
	# app.secret_key = os.urandom(12)
	# startWork()
	pollThread.start()
	app.run(port=5001)