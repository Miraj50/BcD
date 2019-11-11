#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This project demonstrates detection of insider attacks on databases using Blockchain
# Copyright (C) 2018  Rishabh Raj
# This code is licensed under GNU GPLv3 license. See LICENSE for details

import tkinter as tk
import tkinter.messagebox as msgbox
from tkinter import scrolledtext, simpledialog
import tkinter.ttk as ttk
import requests, os, hashlib
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5 as pkcs
from Crypto.Hash import SHA256
from flask import json

class BcD(tk.Tk):
	def __init__(self):
		super().__init__()
		self.sess = None
		self.uname = ""
		self.student = None
		self.eG = None
		self.vG = None
		# self.reload_button = 0
		self.footer = tk.Label(self, text='The world is coming to an end... SAVE YOUR BUFFERS !', font='Verdana 9', bg='black', fg='springGreen', relief='raised')
		self.footer.grid(row=0, column=0, columnspan=2, sticky="nsew")
		self.option_add('*Dialog.msg.font', 'Helvetica 10')
		self.Start()

	def Start(self):
		
		self.title("BcD")
		self.grid_columnconfigure(0, weight=1)
		self.grid_columnconfigure(1, weight=1)

		login = tk.Frame(self)
		login.grid(row=1, column=0, columnspan=2, pady=(5,5))
		# ttk.Separator(self, orient="horizontal").grid(row=2, column=0, columnspan=2, sticky='nsew')
		# signup = tk.Frame(self)
		# signup.grid(row=3, column=0, columnspan=2, pady=(5,5))

		#login
		loginText = tk.Label(login, text='Login', font='Fixedsys 16 bold', fg='darkblue')
		loginText.grid(row=0, column=0, columnspan=2, pady=(10,10))
		name = tk.Label(login, text='Username', font='Verdana 11')
		pword = tk.Label(login, text='Password', font='Verdana 11')
		name.grid(row=1, column=0, padx=(30,5), pady=(5,5), sticky="e")
		pword.grid(row=2, column=0, padx=(30,5), pady=(5,5), sticky="e")

		nameBox = tk.Entry(login)
		pwordBox = tk.Entry(login, show='*')
		nameBox.grid(row=1, column=1, padx=(0,30), pady=(5,5), sticky="w")
		nameBox.focus()
		pwordBox.grid(row=2, column=1, padx=(0,30), pady=(5,5), sticky="w")
		# stud = tk.IntVar()
		# stud.set(0)
		# checkStud = tk.Checkbutton(login, text='Login as Student', font='Fixedsys 8', variable=stud, onvalue=1, offvalue=0)
		# checkStud.grid(row=3, column=1, padx=(0,30), sticky="w")
		loginButton = tk.Button(login, text='Login', bg='blue', fg='white', activebackground='blue3', activeforeground='white', command=lambda: self.CheckLogin(nameBox.get(), pwordBox.get()))
		loginButton.grid(row=3, column=0, columnspan=2, pady=(5,10))
		loginButton.bind('<Return>', lambda e: self.CheckLogin(nameBox.get(), pwordBox.get()))
		# loginButton.bind('<Return>', lambda e: self.CheckLogin(nameBox.get(), pwordBox.get(), stud.get()))

		self.geometry("327x216")
		self.update_idletasks()
		h = self.winfo_reqheight()
		hs = self.winfo_screenheight()
		w = self.winfo_reqwidth()
		ws = self.winfo_screenwidth()
		x = (ws/2) - (w/2)
		self.geometry("+%d+%d" % (x, hs-h*2.5))

	def checkEmpty(self, uid, pword, pubkey):
		if len(uid) == 0:
			self.footer.config(text='Username field is Empty !', bg='red2', fg='white', relief='raised')
			return 0
		if len(pword) == 0:
			self.footer.config(text='Password field is Empty !', bg='red2', fg='white', relief='raised')
			return 0
		if len(pubkey) == 0:
			self.footer.config(text='Public Key field is Empty !', bg='red2', fg='white', relief='raised')
			return 0
		return 1

	def SignUp(self, uid, pword, pubkey):
		if not self.checkEmpty(uid, pword, pubkey):
			return
		pass_h = hashlib.sha256(pword.encode()).hexdigest()

		url = 'http://localhost:5000/signup'
		post_data = {'uid': uid, 'pass': pass_h, 'pubkey':pubkey}
		try:
			self.footer.config(text='Signing Up...', bg='black', fg='springGreen', relief='raised')
			self.footer.update_idletasks()
			response = self.sess.post(url, data=post_data)
			text = response.text
			if len(text)<100:
				abridge = text
			else:
				abridge = text[:100]+"....."+text[-10:]
			passPh = simpledialog.askstring("PassPhrase", abridge+"\nEnter PassPhrase:", show='*')
			if passPh is None:
				return
			with open(os.path.expanduser("~/bcd/"+self.uname+".pem"), "r") as f:
				try:
					privkey = RSA.importKey(f.read(), passphrase=passPh)
				except:
					self.footer.config(text='Incorrect Passphrase !', bg='red2', fg='white', relief='raised')
					return

			digest = SHA256.new()
			digest.update(text.encode())
			sig = pkcs.new(RSA.importKey(privkey.exportKey())).sign(digest).hex()

			post_data = {'sig':sig}
			response = self.sess.post(url, data=post_data)
			text = response.text

		except (ConnectionError, requests.exceptions.RequestException) as e:
			self.footer.config(text='Some Error has Occurred !', bg='red2', fg='white', relief='raised')
			return

		if text == "S":
			self.footer.config(text='User Enrollment in Process', bg='black', fg='springGreen', relief='raised')
		elif text == "M":
			self.footer.config(text='Username already taken !', bg='red2', fg='white', relief='raised')
		else:
			self.footer.config(text='Some Error has Occurred !', bg='red2', fg='white', relief='raised')

	def CheckLogin(self, uid, pword, stud=0):
		if not self.checkEmpty(uid, pword, pubkey='None'):
			return

		self.sess = requests.Session()

		pass_h = hashlib.sha256(pword.encode()).hexdigest()
		# pass_h = pword
		url = 'http://localhost:5000/login'
		post_data = {'uid': uid, 'pass': pass_h, 'student': stud}
		
		try:
			self.footer.config(text='Checking Login Information...', bg='black', fg='springGreen', relief='raised')
			self.footer.update_idletasks()
			response = self.sess.post(url, data=post_data)
			r = response.json()
			text = r['success']
		except (ConnectionError, requests.exceptions.RequestException) as e:
			self.footer.config(text='Some Error has Occurred !', bg='red2', fg='white', relief='raised')
			return

		if text == "S":
			self.uname = uid
			self.student = stud
			if r['type'] == "1":
				self.Admin()
			else:
				self.Home(stud)
		elif text == "U":
			self.footer.config(text='Please SignUp !', bg='red2', fg='white', relief='raised')
		elif text == "D":
			self.footer.config(text='Some Error has Occurred !', bg='red2', fg='white', relief='raised')
		else:
			self.footer.config(text='Incorrect Username or Password !', bg='red2', fg='white', relief='raised')

	def UpdatePK(self, uid, pubkey):
		# pkey = pubkey.encode().hex()
		url = 'http://localhost:5000/updatepk'
		post_data = {'uid': uid, 'pubkey':pubkey}
		try:
			# self.footer.config(text='Signing Up...', bg='black', fg='springGreen', relief='raised')
			# self.footer.update_idletasks()
			response = self.sess.post(url, data=post_data)
			text = response.text
			if len(text)<100:
				abridge = text
			else:
				abridge = text[:100]+"....."+text[-10:]
			passPh = simpledialog.askstring("PassPhrase", abridge+"\nEnter PassPhrase:", show='*')
			if passPh is None:
				return
			with open(os.path.expanduser("~/bcd/"+self.uname+".pem"), "r") as f:
				try:
					privkey = RSA.importKey(f.read(), passphrase=passPh)
				except:
					self.footer.config(text='Incorrect Passphrase !', bg='red2', fg='white', relief='raised')
					return

			digest = SHA256.new()
			digest.update(text.encode())
			sig = pkcs.new(RSA.importKey(privkey.exportKey())).sign(digest).hex()

			post_data = {'sig':sig}
			response = self.sess.post(url, data=post_data)
			text = response.text

		except (ConnectionError, requests.exceptions.RequestException) as e:
			self.footer.config(text='Some Error has Occurred !', bg='red2', fg='white', relief='raised')
			return
		if text == 'S':
			self.footer.config(text='Public Key Being Updated', bg='black', fg='springGreen', relief='raised')
		else:
			self.footer.config(text='Some Error has Occurred !', bg='red2', fg='white', relief='raised')

	def UpdateSQPr(self, pr):
		url = 'http://localhost:5000/updatesqpr'
		post_data = {'sqpr':pr}
		try:
			# self.footer.config(text='Signing Up...', bg='black', fg='springGreen', relief='raised')
			# self.footer.update_idletasks()
			response = self.sess.post(url, data=post_data)
			text = response.text

			passPh = simpledialog.askstring("PassPhrase", text+"\nEnter PassPhrase:", show='*')
			if passPh is None:
				return
			with open(os.path.expanduser("~/bcd/"+self.uname+".pem"), "r") as f:
				try:
					privkey = RSA.importKey(f.read(), passphrase=passPh)
				except:
					self.footer.config(text='Incorrect Passphrase !', bg='red2', fg='white', relief='raised')
					return

			digest = SHA256.new()
			digest.update(text.encode())
			sig = pkcs.new(RSA.importKey(privkey.exportKey())).sign(digest).hex()

			post_data = {'sig':sig}
			response = self.sess.post(url, data=post_data)
			text = response.text

		except (ConnectionError, requests.exceptions.RequestException) as e:
			self.footer.config(text='Some Error has Occurred !', bg='red2', fg='white', relief='raised')
			return
		if text == 'S':
			self.footer.config(text='SQL Procedure Sent', bg='black', fg='springGreen', relief='raised')
		else:
			self.footer.config(text='Some Error has Occurred !', bg='red2', fg='white', relief='raised')

	def InstrCourses(self, uid, courses):
		url = 'http://localhost:5000/instrcourses'
		post_data = {'uid': uid, 'crs':courses}
		try:
			response = self.sess.post(url, data=post_data)
			text = response.text

			passPh = simpledialog.askstring("PassPhrase", text+"\nEnter PassPhrase:", show='*')
			if passPh is None:
				return
			with open(os.path.expanduser("~/bcd/"+self.uname+".pem"), "r") as f:
				try:
					privkey = RSA.importKey(f.read(), passphrase=passPh)
				except:
					self.footer.config(text='Incorrect Passphrase !', bg='red2', fg='white', relief='raised')
					return

			digest = SHA256.new()
			digest.update(text.encode())
			sig = pkcs.new(RSA.importKey(privkey.exportKey())).sign(digest).hex()

			post_data = {'sig':sig}
			response = self.sess.post(url, data=post_data)
			text = response.text

		except (ConnectionError, requests.exceptions.RequestException) as e:
			self.footer.config(text='Some Error has Occurred !', bg='red2', fg='white', relief='raised')
			return
		if text == 'S':
			self.footer.config(text='Adding Course(s) for Instructor', bg='black', fg='springGreen', relief='raised')
		else:
			self.footer.config(text='Some Error has Occurred !', bg='red2', fg='white', relief='raised')

	def ExecFunc(self, func, p):
		url = 'http://localhost:5000/execfunc'
		if func == '':
			return
		post_data = {'func': func, 'param':p}
		try:
			response = self.sess.post(url, data=post_data)
			text = response.text

			passPh = simpledialog.askstring("PassPhrase", text+"\nEnter PassPhrase:", show='*')
			if passPh is None:
				return
			with open(os.path.expanduser("~/bcd/"+self.uname+".pem"), "r") as f:
				try:
					privkey = RSA.importKey(f.read(), passphrase=passPh)
				except:
					self.footer.config(text='Incorrect Passphrase !', bg='red2', fg='white', relief='raised')
					return

			digest = SHA256.new()
			digest.update(text.encode())
			sig = pkcs.new(RSA.importKey(privkey.exportKey())).sign(digest).hex()

			post_data = {'sig':sig}
			response = self.sess.post(url, data=post_data)
			text = response.text

		except (ConnectionError, requests.exceptions.RequestException) as e:
			self.footer.config(text='Some Error has Occurred !', bg='red2', fg='white', relief='raised')
			return
		if text == 'S':
			self.footer.config(text='Request sent to Execute Function', bg='black', fg='springGreen', relief='raised')
		else:
			self.footer.config(text='Some Error has Occurred !', bg='red2', fg='white', relief='raised')

	def clear(self, *args):
		for i in args:
			i.delete(0, "end")

	def Admin(self):
		self.clear_widgets()
		self.geometry("")
		self.attributes('-zoomed', True)
		self.title('Administrator')

		self.footer.config(text='Logged in as Admin', bg='black', fg='springGreen', relief='raised')
		topF = tk.Frame(self)
		topF.grid(row=1, column=0, padx=(10,0), pady=(5,5), sticky="ew")
		top = tk.Label(topF, text='Signed in : ')
		top.pack(side='left', expand=False)
		u = tk.Label(topF, text=self.uname, font='Helvetica 10 bold', bg='lightblue')
		u.pack(side='left', expand=False)
		tk.Button(topF, text='POKE', bg='firebrick2', fg='white', activebackground='tomato', activeforeground='white', command=self.poke).pack(side='left', padx=100)

		logoutButton = tk.Button(self, text='LogOut', bg='brown4', fg='white', activebackground='brown', activeforeground='white', command=self.Logout)
		logoutButton.grid(row=1, column=1, padx=(0,10), pady=(5,5), sticky="e")

		ttk.Separator(self, orient="horizontal").grid(row=2, column=0, columnspan=2, sticky='nsew')
		outofname = tk.Frame(self)
		outofname.grid(row=3, column=0, columnspan=2, sticky="ew")
		outofname.grid_columnconfigure(0, weight=1)
		outofname.grid_columnconfigure(1, weight=1)

		userEnrl = tk.Frame(outofname)
		userEnrl.grid(row=0, column=0, columnspan=2, sticky='nsew')
		userEnrl.grid_columnconfigure(5, weight=1)

		enrollUser = tk.Label(userEnrl, text='Enroll User', font='Fixedsys 14 bold', fg='darkblue')
		enrollUser.grid(row=0, column=0, columnspan=6, pady=(10,10), sticky='ew')
		uid = tk.Label(userEnrl, text='UserID:', font='Fixedsys', fg='gray20')
		pword = tk.Label(userEnrl, text='Choose Password:', font='Fixedsys', fg='gray20')
		uid.grid(row=1, column=0, padx=5, pady=(5,5), sticky="e")
		pword.grid(row=1, column=2, padx=(20,5), pady=(5,5), sticky="e")

		uidBox = tk.Entry(userEnrl)
		uidBox.grid(row=1, column=1, padx=0, pady=(5,5), sticky="e")
		pwordBox = tk.Entry(userEnrl, show='*')
		pwordBox.grid(row=1, column=3, padx=(0,20), pady=(5,5), sticky="e")

		tk.Label(userEnrl, text='Public Key:\n(Hex Encoded)', font='Fixedsys 11', fg='gray20').grid(row=1, column=4, padx=(5,0))
		pkBox = tk.Entry(userEnrl)
		pkBox.grid(row=1, column=5, padx=5, pady=(5,5), sticky="ew")
		tk.Button(userEnrl, text='Enroll', bg='blue3', fg='white', activebackground='blue', activeforeground='white', command=lambda:self.SignUp(uidBox.get().strip(), pwordBox.get().strip(), pkBox.get().strip())).grid(row=2, column=4, pady=(5,0), sticky="e")
		tk.Button(userEnrl, text='Clear', bg='green', fg='white', activebackground='forestgreen', activeforeground='white', command=lambda: self.clear(uidBox, pwordBox, pkBox)).grid(row=2, column=5, pady=(5,0), sticky="w")

		ttk.Separator(outofname, orient="horizontal").grid(row=1, column=0, columnspan=2, pady=5, sticky='nsew')

		updtpk = tk.Frame(outofname)
		updtpk.grid(row=2, column=0, columnspan=2, sticky='nsew')
		updtpk.grid_columnconfigure(3, weight=1)
		updtkey = tk.Label(updtpk, text='Update Public Key', font='Fixedsys 14 bold', fg='darkblue')
		updtkey.grid(row=0, column=0, columnspan=4, pady=(10,10), sticky='ew')
		tk.Label(updtpk, text='UserID:', font='Fixedsys', fg='gray20').grid(row=1, column=0, padx=5, pady=(5,5), sticky="e")
		updtid = tk.Entry(updtpk)
		updtid.grid(row=1, column=1, padx=(0,5), pady=(5,5), sticky="e")
		tk.Label(updtpk, text='New Public Key:\n(Hex Encoded)', font='Fixedsys 11', fg='gray15').grid(row=1, column=2, padx=(20,5), pady=(5,5), sticky="e")
		npkey = tk.Entry(updtpk)
		npkey.grid(row=1, column=3, padx=(0,5), pady=(5,5), sticky="ew")
		tk.Button(updtpk, text='Submit', bg='blue3', fg='white', activebackground='blue', activeforeground='white', command=lambda:self.UpdatePK(updtid.get().strip(), npkey.get().strip())).grid(row=2, column=2, sticky="e")
		tk.Button(updtpk, text='Clear', bg='green', fg='white', activebackground='forestgreen', activeforeground='white', command=lambda: self.clear(updtid, npkey)).grid(row=2, column=3, sticky="w")

		ttk.Separator(outofname, orient="horizontal").grid(row=3, column=0, columnspan=2, pady=5, sticky='nsew')

		sqlprcd = tk.Frame(outofname)
		sqlprcd.grid(row=4, column=0, rowspan=3, sticky='nsew')
		sqlprcd.grid_columnconfigure(0, weight=1)
		sqlprcd.grid_columnconfigure(1, weight=1)
		tk.Label(sqlprcd, text='Update/New SQL Function', font='Fixedsys 14 bold', fg='darkblue').grid(row=0, column=0, columnspan=2, pady=(10,10))
		enterPrcd = scrolledtext.ScrolledText(sqlprcd, font='Verdana 10', wrap='word', spacing2=0, spacing3=0, width=50, height=12)
		enterPrcd.grid(row=1, column=0, columnspan=2)
		tk.Button(sqlprcd, text='Submit', bg='blue3', fg='white', activebackground='blue', activeforeground='white', command=lambda:self.UpdateSQPr(enterPrcd.get("1.0", 'end-1c').strip())).grid(row=2, column=0, pady=(5,0), sticky="e")
		tk.Button(sqlprcd, text='Clear', bg='green', fg='white', activebackground='forestgreen', activeforeground='white', command=lambda: enterPrcd.delete(1.0, "end")).grid(row=2, column=1, pady=(5,0), sticky="w")

		instrc = tk.Frame(outofname)
		instrc.grid(row=4, column=1, sticky='nsew')
		# instrc.grid_columnconfigure(1, weight=1)
		tk.Label(instrc, text='Instructor-Course', font='Fixedsys 14 bold', fg='darkblue').grid(row=0, column=0, columnspan=4, pady=(10,10))
		tk.Label(instrc, text='UserID:', font='Fixedsys', fg='gray20').grid(row=1, column=0, padx=5, pady=(5,5), sticky="e")
		instrid = tk.Entry(instrc)
		instrid.grid(row=1, column=1, padx=(0,5), pady=(5,5), sticky="e")
		tk.Label(instrc, text='Courses:', font='Fixedsys 11', fg='gray15').grid(row=1, column=2, padx=(5,5), pady=(5,5), sticky="e")
		courses = tk.Entry(instrc)
		courses.grid(row=1, column=3, padx=(0,5), pady=(5,5), sticky="ew")
		tk.Button(instrc, text='Submit', bg='blue3', fg='white', activebackground='blue', activeforeground='white', command=lambda:self.InstrCourses(instrid.get().strip(), courses.get().strip())).grid(row=2, column=1, pady=(5,0), sticky="e")
		tk.Button(instrc, text='Clear', bg='green', fg='white', activebackground='forestgreen', activeforeground='white', command=lambda:self.clear(instrid, courses)).grid(row=2, column=2, pady=(5,0), sticky="w")

		ttk.Separator(outofname, orient="horizontal").grid(row=5, column=1, pady=5, sticky='nsew')

		funcexec = tk.Frame(outofname)
		funcexec.grid(row=6, column=1, sticky='nsew')
		# funcexec.grid_columnconfigure(1, weight=1)
		tk.Label(funcexec, text='Execute SQL Function', font='Fixedsys 14 bold', fg='darkblue').grid(row=0, column=0, columnspan=4, pady=(10,10))
		tk.Label(funcexec, text='Function Name:', font='Fixedsys', fg='gray20').grid(row=1, column=0, padx=5, pady=(5,5), sticky="e")
		func = tk.Entry(funcexec)
		func.grid(row=1, column=1, padx=(0,5), pady=(5,5), sticky="e")
		tk.Label(funcexec, text='Parameters:\n(Space separated)', font='Fixedsys 11', fg='gray15').grid(row=1, column=2, padx=(5,5), pady=(5,5), sticky="e")
		param = tk.Entry(funcexec)
		param.grid(row=1, column=3, padx=(0,5), pady=(5,5), sticky="ew")
		tk.Button(funcexec, text='Submit', bg='blue3', fg='white', activebackground='blue', activeforeground='white', command=lambda:self.ExecFunc(func.get(), param.get())).grid(row=2, column=1, pady=(5,0), sticky="e")
		tk.Button(funcexec, text='Clear', bg='green', fg='white', activebackground='forestgreen', activeforeground='white', command=lambda:self.clear(func, param)).grid(row=2, column=2, pady=(5,0), sticky="w")

		# userEnrl = tk.Frame(self)
		# userEnrl.grid(row=3, column=0, columnspan=2, sticky='nsew')
		# userEnrl.grid_columnconfigure(5, weight=1)

		# enrollUser = tk.Label(userEnrl, text='Enroll User', font='Fixedsys 14 bold', fg='darkblue')
		# enrollUser.grid(row=0, column=0, columnspan=6, pady=(10,10), sticky='ew')
		# uid = tk.Label(userEnrl, text='UserID:', font='Fixedsys', fg='gray20')
		# pword = tk.Label(userEnrl, text='Choose Password:', font='Fixedsys', fg='gray20')
		# uid.grid(row=1, column=0, padx=5, pady=(5,5), sticky="e")
		# pword.grid(row=1, column=2, padx=(20,5), pady=(5,5), sticky="e")

		# uidBox = tk.Entry(userEnrl)
		# uidBox.grid(row=1, column=1, padx=0, pady=(5,5), sticky="e")
		# pwordBox = tk.Entry(userEnrl, show='*')
		# pwordBox.grid(row=1, column=3, padx=(0,20), pady=(5,5), sticky="e")

		# tk.Label(userEnrl, text='Public Key:\n(Hex Encoded)', font='Fixedsys 11', fg='gray20').grid(row=1, column=4, padx=(5,0))
		# pkBox = tk.Entry(userEnrl)
		# pkBox.grid(row=1, column=5, padx=5, pady=(5,5), sticky="ew")
		# tk.Button(userEnrl, text='Enroll', bg='blue3', fg='white', activebackground='blue', activeforeground='white', command=lambda:self.SignUp(uidBox.get().strip(), pwordBox.get().strip(), pkBox.get().strip())).grid(row=2, column=4, pady=(5,0), sticky="e")
		# tk.Button(userEnrl, text='Clear', bg='green', fg='white', activebackground='forestgreen', activeforeground='white', command=lambda: self.clear(uidBox, pwordBox, pkBox)).grid(row=2, column=5, pady=(5,0), sticky="w")

		# ttk.Separator(self, orient="horizontal").grid(row=4, column=0, columnspan=2, pady=5, sticky='nsew')

		# updtpk = tk.Frame(self)
		# updtpk.grid(row=5, column=0, columnspan=2, sticky='nsew')
		# updtpk.grid_columnconfigure(3, weight=1)
		# updtkey = tk.Label(updtpk, text='Update Public Key', font='Fixedsys 14 bold', fg='darkblue')
		# updtkey.grid(row=0, column=0, columnspan=4, pady=(10,10), sticky='ew')
		# tk.Label(updtpk, text='UserID:', font='Fixedsys', fg='gray20').grid(row=1, column=0, padx=5, pady=(5,5), sticky="e")
		# updtid = tk.Entry(updtpk)
		# updtid.grid(row=1, column=1, padx=(0,5), pady=(5,5), sticky="e")
		# tk.Label(updtpk, text='New Public Key:\n(Hex Encoded)', font='Fixedsys 11', fg='gray15').grid(row=1, column=2, padx=(20,5), pady=(5,5), sticky="e")
		# npkey = tk.Entry(updtpk)
		# npkey.grid(row=1, column=3, padx=(0,5), pady=(5,5), sticky="ew")
		# tk.Button(updtpk, text='Submit', bg='blue3', fg='white', activebackground='blue', activeforeground='white', command=lambda:self.UpdatePK(updtid.get().strip(), npkey.get().strip())).grid(row=2, column=2, sticky="e")
		# tk.Button(updtpk, text='Clear', bg='green', fg='white', activebackground='forestgreen', activeforeground='white', command=lambda: self.clear(updtid, npkey)).grid(row=2, column=3, sticky="w")

		# ttk.Separator(self, orient="horizontal").grid(row=6, column=0, columnspan=2, pady=5, sticky='nsew')

		# sqlprcd = tk.Frame(self)
		# sqlprcd.grid(row=7, column=0, sticky='nsew')
		# sqlprcd.grid_columnconfigure(0, weight=1)
		# sqlprcd.grid_columnconfigure(1, weight=1)
		# tk.Label(sqlprcd, text='Update/New SQL Function', font='Fixedsys 14 bold', fg='darkblue').grid(row=0, column=0, columnspan=2, pady=(10,10))
		# enterPrcd = scrolledtext.ScrolledText(sqlprcd, font='Verdana 10', wrap='word', spacing2=0, spacing3=0, width=50, height=12)
		# enterPrcd.grid(row=1, column=0, columnspan=2)
		# tk.Button(sqlprcd, text='Submit', bg='blue3', fg='white', activebackground='blue', activeforeground='white', command=lambda:self.UpdateSQPr(enterPrcd.get("1.0", 'end-1c').strip())).grid(row=2, column=0, pady=(5,0), sticky="e")
		# tk.Button(sqlprcd, text='Clear', bg='green', fg='white', activebackground='forestgreen', activeforeground='white', command=lambda: enterPrcd.delete(1.0, "end")).grid(row=2, column=1, pady=(5,0), sticky="w")

		# instrc = tk.Frame(self)
		# instrc.grid(row=7, column=1, sticky='nsew')
		# # instrc.grid_columnconfigure(1, weight=1)
		# tk.Label(instrc, text='Instructor-Course', font='Fixedsys 14 bold', fg='darkblue').grid(row=0, column=0, columnspan=4, pady=(10,10))
		# tk.Label(instrc, text='UserID:', font='Fixedsys', fg='gray20').grid(row=1, column=0, padx=5, pady=(5,5), sticky="e")
		# instrid = tk.Entry(instrc)
		# instrid.grid(row=1, column=1, padx=(0,5), pady=(5,5), sticky="e")
		# tk.Label(instrc, text='Courses:', font='Fixedsys 11', fg='gray15').grid(row=1, column=2, padx=(5,5), pady=(5,5), sticky="e")
		# courses = tk.Entry(instrc)
		# courses.grid(row=1, column=3, padx=(0,5), pady=(5,5), sticky="ew")
		# tk.Button(instrc, text='Submit', bg='blue3', fg='white', activebackground='blue', activeforeground='white', command=lambda:self.InstrCourses(instrid.get().strip(), courses.get().strip())).grid(row=2, column=1, pady=(5,0), sticky="e")
		# tk.Button(instrc, text='Clear', bg='green', fg='white', activebackground='forestgreen', activeforeground='white', command=lambda:self.clear(instrid, courses)).grid(row=2, column=2, pady=(5,0), sticky="w")

	def Home(self, stud=0):
		self.clear_widgets()
		self.attributes('-zoomed', True)
		self.title('Grades')
		self.grid_rowconfigure(4, weight=1)

		self.footer.config(text='Succesfully Logged in', bg='black', fg='springGreen', relief='raised')

		topF = tk.Frame(self)

		top = tk.Label(topF, text='Signed in : ')
		top.pack(side='left', expand=False)
		u = tk.Label(topF, text=self.uname, font='Helvetica 10 bold', bg='lightblue')
		u.pack(side='left', expand=False)

		topF.grid(row=1, column=0, padx=(10,0), pady=(5,5), sticky="w")
		logoutButton = tk.Button(self, text='LogOut', bg='brown4', fg='white', activebackground='brown', activeforeground='white', command=self.Logout)
		logoutButton.grid(row=1, column=1, padx=(0,10), pady=(5,5), sticky="e")

		ttk.Separator(self, orient="horizontal").grid(row=2, column=0, columnspan=2, sticky='nsew')

		viewButF = tk.Frame(self)

		viewButton = tk.Button(viewButF, text='View Grades', bg='blue3', fg='white', activebackground='blue', activeforeground='white', command=lambda: self.viewG(0))
		viewButton.grid(row=0, column=0)

		ref_img = "iVBORw0KGgoAAAANSUhEUgAAABYAAAAWCAMAAADzapwJAAAABGdBTUEAALGPC/xhBQAAAAFzUkdCAK7OHOkAAAIcUExURf///ya6oSe6oTS/pzO+pjG+pim7ojK+pv3+/jW/pyW6oCi7oi+9pTvBqjjAqTa/py28pD/CrDS+pyO5n0bEr/7+/qfj2Sq8ozS+pje/qFLItEfFr1rLuP7//zG+pSq7ooTYyt/18TzBq/z+/Se7oSy8ozjAqD7CqznAqWrQvkfEry69pG3RwCi7oS68pG7RwCa6oDC9pSu8o+f39CK5nya7oSe7ouj39SG5n2TOvCO6nyG4nyq7o/f8+/X8++f39eL28iS6oOv59mLNuyu7oyW5oOr49pPd0EXEruD18nfUxOD18f7//iO5oLHm3UHDraHi18ft5mzQv0bErii6os/w62vQv6Ti16Pi1+v49tXy7dz08N718aLh1/P7+un39ajk2cbt58vu6I/cz6nk2vH6+T3Cq0/HskLDrVTJtFPItJHc0Jbe0Sy8pDC+pXbUxKrk2oLXycLr5IjZy/T7+rnp4fn9/JHcz4PYySW6oeH28rTn3/X8+vb8+7zq4jK9pmbPvX/WyDO+p9Hx62fPvXnVxUzGsT3Bq1/MuW/RwHLSwmPOvIXYyuL18lrKt1nKt5fe0lbJtVfKtlbJto7bznDSwc7w6vz+/oPXyWfOvabj2LXo34fZy8bt5j/Cq+T39E7HsjK+pXzVxlfJtpbd0nHSwn/Wx33Wx6Dh1t708e/6+GPNvCq8otDw65bd0dfy7eX39FvKuNjz7iS6n1GSCawAAAG/SURBVBjTNdFVd9tAEAXgK2ml1UqWjDHHFFOYmZmatCmmTZmZmZmZUmZuk7bpH+zKPpmHmXO+h905dwCgQEXP+sqQ3R4qezEAtQC5UnHmvlPoi8iy3FaV+XSaQ0677o5FqKgQmtRd8tjHYctVnAzVm3ri+JFLT8dHpL6sOBS3/Og9IS3erEUhsABzf/Vs8lE7f2R3iyneBg7uu94b+42On4rRfQxY6dzruwX1gK4per9tFn8ydY6tjfBqgZpw16FWF5MYSXz+jpcj25pWoGypRCpSe/yUUlJ9LY5pbAnWLUaJjVDKKG98CM2FRYhp1AMmu3zBZQsdea/yYqKUUAZG/b6z2FzPLCYVzlVhRZIZSmj3FRThvJD3cwHebB5Uuq/2cL7jtP6gfkepg0jlxfC2vvsyjs6vGco3vNj0qrE3GtAWYeBNyp0exTeXJur90ZiK51HZqAUG/xm/wj8w/Phy84fXwDPBbNnEM2l/KGaV4AzPiaf19omYLt/RYQUbHxLMVOTG/g0bT10wFDO5fSof+OgDN2WKZqtuaCDv3TtXz5/n8GBCaOPryTUnjF1r85o78brJ5R67fUnxmk6olv4HiD1RWB2GYT8AAAAASUVORK5CYII="
		ref = tk.PhotoImage(data=ref_img)
		refreshG = tk.Button(self.winfo_children()[4], image=ref, activebackground='cyan4', command=lambda: self.viewG(1))
		refreshG.image = ref
		refreshG.grid(row=0, column=1)

		enterButF = tk.Frame(self)
		pokeBut = tk.Button(enterButF, text='POKE', bg='firebrick2', fg='white', activebackground='tomato', activeforeground='white', command=self.poke)

		if stud == 0: # an instructor
			enterButton = tk.Button(enterButF, text='Enter Grades', bg='blue3', fg='white', activebackground='blue', activeforeground='white', command=self.enterG)
			# enterButton.grid(row=2, column=0, padx=(40,5), pady=(5,2), sticky="e")
			enterButton.grid(row=0, column=0, padx=(40,5), sticky="e")
			enterButF.grid(row=2, column=0, padx=(40,5), pady=(5,2), sticky="e")
			pokeBut.grid(row=0, column=1, padx=(2,5), sticky="e")
			viewButF.grid(row=2, column=1, padx=(5,40), pady=(5,2), sticky="w")
		else: # a student
			viewButF.grid(row=2, column=0, columnspan=2, pady=(5,2))

		ttk.Separator(self, orient="horizontal").grid(row=3, column=0, columnspan=2, sticky='nsew')

	def enterG(self):
		self.geometry("")

		if self.vG is not None:
			self.vG.grid_forget()

		if self.eG is None:
			self.eG = tk.Frame(self)
			self.eG.grid_columnconfigure(0, weight=1) # Along with sticky=ewns will resize to full window

			enterGrades = scrolledtext.ScrolledText(self.eG, font='Verdana 11', wrap='word', spacing2=0, spacing3=7, width=50, height=12)
			enterGrades.pack(expand=True, fill="both")
			# self.eG.winfo_children()[0].winfo_children()[1].tag_configure("error", background="gray80", foreground="red")

			subFr = tk.Frame(self.eG)
			enterGBut = tk.Button(subFr, text='Submit Grades', bg='green', fg='white', activebackground='forestgreen', activeforeground='white', command=lambda: self.submitG(enterGrades.get("1.0", 'end-1c')))
			enterGBut.pack(side='left', expand=True, fill='x')
			subFr.pack(side='left', expand=True, fill='x')
			self.eG.grid(row=4, column=0, columnspan=2, pady=(1,3), sticky="ns")
		else:
			self.eG.grid(row=4, column=0, columnspan=2, pady=(1,3), sticky="ns")

	def getGrades(self):
		url = 'http://localhost:5000/view'
		try:
			self.footer.config(text='Retrieving Grades...', bg='black', fg='springGreen', relief='raised')
			self.footer.update_idletasks()
			response = self.sess.post(url)
			text = response.text
		except (ConnectionError, requests.exceptions.RequestException) as e:
			self.footer.config(text='Some Error has Occurred !', bg='red2', fg='white', relief='raised')
			return

		if text == "UFO":
			self.footer.config(text='!!!  BREACH DETECTED  !!!', bg='gold', fg='red3', borderwidth=2, relief='sunken')
			self.footer.update_idletasks()
			return None
		if text == "D":
			self.footer.config(text='Some Error has Occurred !', bg='red2', fg='white', relief='raised')
			return None
		return text

	def viewG(self, flag):

		self.geometry("")

		if self.eG is not None:
			self.eG.grid_forget()

		if flag == 0 or (flag == 1 and self.vG is None):
			if self.vG is None:

				text = self.getGrades()
				if text is None:
					return

				self.footer.config(text='Grades Retrieved Successfully', bg='black', fg='springGreen', relief='raised')
				self.vG = tk.Frame(self)
				viewList = ttk.Treeview(self.vG, height=15)
				viewList['show'] = 'headings'
				viewList['columns'] = ('Roll', 'Name', 'Course', 'Grade')
				viewList.heading("#1", text='Roll No.', anchor='w')
				viewList.column("#1", stretch="no", width=100)
				viewList.heading("#2", text='Name', anchor='w')
				viewList.column("#2", stretch="no", width=160 )
				viewList.heading("#3", text='Course', anchor='w')
				viewList.column("#3", stretch="no", width=100)
				viewList.heading("#4", text='Grade', anchor='w')
				viewList.column("#4", stretch="no", width=100)

				for row in text.split('&'):
					viewList.insert("", "end", values=row.split('%'))

				viewList.pack(side="left", expand=True, fill="both")

				yscroll = tk.Scrollbar(self.vG, command=viewList.yview, orient="vertical")
				yscroll.pack(side="right", fill="y")

				viewList.configure(yscrollcommand=yscroll.set)
				if self.student == 0:
					viewList.bind("<Double-Button-1>", self.updateG)

				self.vG.grid(row=4, column=0, columnspan=2, pady=(1,7), sticky="ns")
			else:
				self.vG.grid(row=4, column=0, columnspan=2, pady=(1,7), sticky="ns")
		elif flag == 1:
			text = self.getGrades()
			if text is None:
				return
			viewList = self.vG.winfo_children()[0]
			viewList.delete(*viewList.get_children())
			for row in text.split('&'):
				viewList.insert("", "end", values=row.split('%'))
			self.footer.config(text='Grades Retrieved Successfully', bg='black', fg='springGreen', relief='raised')
			self.vG.grid(row=4, column=0, columnspan=2, pady=(1,7), sticky="ns")

	def poke(self):
		url = 'http://localhost:5000/poke'
		response = self.sess.post(url)
		# print(response, response.json()['status'])
		r = response.json()['data']
		if r == '':
			msgbox.showinfo("Response", "No new Transactions")
		else:
			msgbox.showinfo("Response", r)

	def submitG(self, grades):
		
		post_data = {'data':[]}
		gradeList = grades.split('\n')
		num = 0

		for row in gradeList:
			temp = row.split()

			if len(temp) != 3 or len(temp[0]) > 128 or len(temp[1]) >5 or len(temp[2]) != 2:
				self.footer.config(text='Please Follow the required Format !', bg='red2', fg='white', relief='raised')
				return
			else:
				post_data['data'].append({'uid':temp[0], 'course':temp[1], 'grade':temp[2]})
				num = num+1

		post_data['count'] = num
		# post_data['ping'] = ping

		url = 'http://localhost:5000/insert'
		try:
			self.footer.config(text='Submitting Grades...', bg='black', fg='springGreen', relief='raised')
			self.footer.update_idletasks()
			response = self.sess.post(url, json=post_data)
			self.update_idletasks()
			text = response.text

			passPh = simpledialog.askstring("PassPhrase", text+"\nEnter PassPhrase:", show='*')
			if passPh is None:
				return
			with open(os.path.expanduser("~/bcd/"+self.uname+".pem"), "r") as f:
				try:
					privkey = RSA.importKey(f.read(), passphrase=passPh)
				except:
					self.footer.config(text='Incorrect Passphrase !', bg='red2', fg='white', relief='raised')
					return

			digest = SHA256.new()
			digest.update(text.encode())
			sig = pkcs.new(RSA.importKey(privkey.exportKey())).sign(digest).hex()

			post_data = {'sig':sig}
			response = self.sess.post(url, json=post_data).json()
			text = response['status']

		except (ConnectionError, requests.exceptions.RequestException) as e:
			self.footer.config(text='Some Error has Occurred !', bg='red2', fg='white')
			return

		if text == "UFO":
			self.footer.config(text='!!!  BREACH DETECTED  !!!', bg='gold', fg='red3', borderwidth=2, relief='sunken')
		elif text == "N":
			self.footer.config(text='Please Follow the required Format !', bg='red2', fg='white', relief='raised')
		elif text[0] == "D":
			self.footer.config(text='Grades could not be Submitted !', bg='red2', fg='white', relief='raised')
		elif text == "S":
			self.footer.config(text='Grades Sent', bg='black', fg='springGreen', relief='raised')
			self.eG.winfo_children()[0].winfo_children()[1].delete(1.0, "end")
			# Put reload button (only once)
			# if self.reload_button == 0:
				# ref_img = "iVBORw0KGgoAAAANSUhEUgAAABYAAAAWCAMAAADzapwJAAAABGdBTUEAALGPC/xhBQAAAAFzUkdCAK7OHOkAAAIcUExURf///ya6oSe6oTS/pzO+pjG+pim7ojK+pv3+/jW/pyW6oCi7oi+9pTvBqjjAqTa/py28pD/CrDS+pyO5n0bEr/7+/qfj2Sq8ozS+pje/qFLItEfFr1rLuP7//zG+pSq7ooTYyt/18TzBq/z+/Se7oSy8ozjAqD7CqznAqWrQvkfEry69pG3RwCi7oS68pG7RwCa6oDC9pSu8o+f39CK5nya7oSe7ouj39SG5n2TOvCO6nyG4nyq7o/f8+/X8++f39eL28iS6oOv59mLNuyu7oyW5oOr49pPd0EXEruD18nfUxOD18f7//iO5oLHm3UHDraHi18ft5mzQv0bErii6os/w62vQv6Ti16Pi1+v49tXy7dz08N718aLh1/P7+un39ajk2cbt58vu6I/cz6nk2vH6+T3Cq0/HskLDrVTJtFPItJHc0Jbe0Sy8pDC+pXbUxKrk2oLXycLr5IjZy/T7+rnp4fn9/JHcz4PYySW6oeH28rTn3/X8+vb8+7zq4jK9pmbPvX/WyDO+p9Hx62fPvXnVxUzGsT3Bq1/MuW/RwHLSwmPOvIXYyuL18lrKt1nKt5fe0lbJtVfKtlbJto7bznDSwc7w6vz+/oPXyWfOvabj2LXo34fZy8bt5j/Cq+T39E7HsjK+pXzVxlfJtpbd0nHSwn/Wx33Wx6Dh1t708e/6+GPNvCq8otDw65bd0dfy7eX39FvKuNjz7iS6n1GSCawAAAG/SURBVBjTNdFVd9tAEAXgK2ml1UqWjDHHFFOYmZmatCmmTZmZmZmZUmZuk7bpH+zKPpmHmXO+h905dwCgQEXP+sqQ3R4qezEAtQC5UnHmvlPoi8iy3FaV+XSaQ0677o5FqKgQmtRd8tjHYctVnAzVm3ri+JFLT8dHpL6sOBS3/Og9IS3erEUhsABzf/Vs8lE7f2R3iyneBg7uu94b+42On4rRfQxY6dzruwX1gK4per9tFn8ydY6tjfBqgZpw16FWF5MYSXz+jpcj25pWoGypRCpSe/yUUlJ9LY5pbAnWLUaJjVDKKG98CM2FRYhp1AMmu3zBZQsdea/yYqKUUAZG/b6z2FzPLCYVzlVhRZIZSmj3FRThvJD3cwHebB5Uuq/2cL7jtP6gfkepg0jlxfC2vvsyjs6vGco3vNj0qrE3GtAWYeBNyp0exTeXJur90ZiK51HZqAUG/xm/wj8w/Phy84fXwDPBbNnEM2l/KGaV4AzPiaf19omYLt/RYQUbHxLMVOTG/g0bT10wFDO5fSof+OgDN2WKZqtuaCDv3TtXz5/n8GBCaOPryTUnjF1r85o78brJ5R67fUnxmk6olv4HiD1RWB2GYT8AAAAASUVORK5CYII="
				# ref = tk.PhotoImage(data=ref_img)
				# refreshG = tk.Button(self.winfo_children()[4], image=ref, activebackground='cyan4', command=lambda: self.viewG(1))
				# refreshG.image = ref
				# refreshG.grid(row=0, column=1)
			# self.reload_button = 1
		# elif text == "PING":
		# 	# self.footer.config(text='SUCCESS', bg='black', fg='springGreen', relief='raised')
		# 	# self.footer.update_idletasks()
		# 	self.eG.winfo_children()[0].winfo_children()[1].delete(1.0, "end")
		# 	msgbox.showinfo("RESPONSE", response['data'])

	def updateG(self, event):
		w = event.widget
		idx = w.selection()[0]
		item = w.item(w.selection())['values']

		uG = simpledialog.askstring('Update grade', 'Enter New Grade', parent=self, initialvalue=item[3])
		if uG is None or uG==item[3]:
			return

		post_data = {'uid':item[0], 'course':item[2], 'grade':uG}

		url = 'http://localhost:5000/update'
		try:
			self.footer.config(text='Updating Grade...', bg='black', fg='springGreen')
			self.footer.update_idletasks()
			response = self.sess.post(url, data=post_data)
			text = response.text

			passPh = simpledialog.askstring("PassPhrase", text+"\nEnter PassPhrase:", show='*')
			if passPh is None:
				return
			with open(os.path.expanduser("~/bcd/"+self.uname+".pem"), "r") as f:
				try:
					privkey = RSA.importKey(f.read(), passphrase=passPh)
				except:
					self.footer.config(text='Incorrect Passphrase !', bg='red2', fg='white', relief='raised')
					return

			digest = SHA256.new()
			digest.update(text.encode())
			sig = pkcs.new(RSA.importKey(privkey.exportKey())).sign(digest).hex()

			post_data = {'uid':item[0], 'course':item[2], 'grade':uG, 'sig':sig}
			response = self.sess.post(url, data=post_data)
			text = response.text

		except (ConnectionError, requests.exceptions.RequestException) as e:
			self.footer.config(text='Some Error has Occurred !', bg='red2', fg='white', relief='raised')
			return

		if text == "D":
			self.footer.config(text='Some Error has Occurred !', bg='red2', fg='white', relief='raised')
		elif text == "S":
			self.footer.config(text='Updated Grade Sent', bg='black', fg='springGreen', relief='raised')
			self.vG.winfo_children()[0].item(idx, values=(item[0], item[1], item[2], item[3]+'\u2b95'+uG))
		# elif text == "UFO":
		# 	self.footer.config(text='!!!  BREACH DETECTED  !!!', bg='gold', fg='red3', borderwidth=2, relief='sunken')

	def Logout(self):
		url = 'http://localhost:5000/logout'
		try:
			response = self.sess.post(url)
		except (ConnectionError, requests.exceptions.RequestException) as e:
			self.footer.config(text='Some Error has Occurred !', bg='red2', fg='white', relief='raised')
		else:
			self.attributes('-zoomed', False)
			self.clear_widgets()
			self.uname = ""
			self.student = None
			self.sess = None
			self.eG = None
			self.vG = None
			self.reload_button = 0
			self.footer.config(text='Successfully Logged Out', bg='black', fg='springGreen', relief='raised')
			self.Start()

	def clear_widgets(self):
		for widget in self.winfo_children():
			if widget != self.footer:
				widget.destroy()

def quit():
	# app.destroy()
	if app.uname != "":
		app.Logout()
	else:
		app.destroy()

app = BcD()
app.protocol("WM_DELETE_WINDOW", quit)
app.mainloop()