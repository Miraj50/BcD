from flask import Flask, request
import threading, os, time
from apscheduler.schedulers.background import BackgroundScheduler
from collections import defaultdict


POOL_TIME = 5
log = defaultdict(list)
i=1
# myThread = threading.Thread()
myThread = None
r = threading.Event()
# r.set()
def poll(a):
	global log,i
	r.clear()
	print(time.time(), a)
	# time.sleep(2)
	log[1].append(i)
	i = i+1
	# time.sleep(1)
	# myThread = threading.Timer(POOL_TIME, poll)
	# myThread.start()
	r.set()

def startWork():
	global myThread
	myThread = threading.Timer(POOL_TIME, poll)
	myThread.start()
	# while True:
	# 	r.wait()
	# 	r.clear()
	# 	myThread = threading.Timer(POOL_TIME, poll)
	# 	myThread.start()

scheduler = BackgroundScheduler()
scheduler.add_job(id='123', func=poll, args=['|'], trigger="interval", seconds=POOL_TIME)
scheduler.start()
# class Me(threading.Thread):
# 	def __init__(self):
# 		threading.Thread.__init__(self)
# 		self.can_run = threading.Event()
# 		self.thing_done = threading.Event()
# 		self.thing_done.set()
# 		self.can_run.set()    

# 	def run(self):
# 		while True:
# 			self.can_run.wait()
# 			try:
# 				self.thing_done.clear()
# 				print('do the thing')
# 			finally:
# 				self.thing_done.set()

# 	def pause(self):
# 		self.can_run.clear()
# 		self.thing_done.wait()

# 	def resume(self):
# 		self.can_run.set()

# t = Me()
# t.run()

app = Flask(__name__)

@app.route('/ping', methods=['POST'])
def ping():
	global log
	r.wait()
	# myThread.cancel()
	scheduler.remove_job('123')
	poll("@")
	print(log[1])
	scheduler.add_job(id='123', func=poll, args=['|'], trigger="interval", seconds=POOL_TIME)


	return "Hello"

if __name__ == '__main__':
	# app.secret_key = os.urandom(12)
	# startWork()
	app.run(port=5001)