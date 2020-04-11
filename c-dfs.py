import socket, threading, os, struct,selectors#,atexit
from pathlib import Path
from tkinter import *
import queue # thread-safe

Q = queue.Queue()
sel = selectors.DefaultSelector()

serv_fd = None
CLIENT_PORT = 9999
MAX_MSG = 4096
last_cmd = ''
last_print = ''

class CleanExit:
  pass

class TextEditor:
	#@staticmethod
	def quit_app(self, event=None):
		os.remove(self.fname)
		self.root.destroy()


	def save_file(self, event=None):
		fil_path = self.fname
		content = self.text_area.get('1.0', END + '-1c')
		if(content[-1:] != '\n'):
			content += '\n'
		self.fd.sendall(('updt '+fil_path+';'+content+'Āā').encode())
		self.quit_app(self)


	def __init__(self, root, fname,fd):
		self.fname = fname
		self.root = root
		self.fd = fd
		self.text_to_write = ""
		root.title("Text Editor")
		root.geometry("600x550")
		frame = Frame(root, width=600, height=550)
		scrollbar = Scrollbar(frame)
		self.text_area = Text(frame, width=600, height=550,
				        yscrollcommand=scrollbar.set,
				        padx=10, pady=10)
		scrollbar.config(command=self.text_area.yview)
		scrollbar.pack(side="right", fill="y")
		self.text_area.pack(side="left", fill="both", expand=True)
		frame.pack()
		the_menu = Menu(root)
		file_menu = Menu(the_menu, tearoff=0)
		file_menu.add_command(label="Save", command=self.save_file)
		file_menu.add_separator()
		file_menu.add_command(label="Quit (Unsaved)", command=self.quit_app)
		the_menu.add_cascade(label="Option", menu=file_menu)
		root.config(menu=the_menu)
		self.text_area.delete(1.0, END)
		with open(fname) as _file:
			self.text_area.insert(1.0, _file.read())
		root.update_idletasks()


def recCliMsg(fd):
	sel.register(fd, selectors.EVENT_READ)
	global last_cmd
	global last_print
	cmd = ''
	while True:
		print('<cmd>: ',end='',flush=True)
		events = sel.select()
		for key, mask in events:
			#print(key)
			#print(key.fd)
			#print(fd)
			if key.fd==fd.fileno():
				try:
					data = fd.recv(MAX_MSG).decode()
				except ConnectionResetError:
					data = ''
				if(len(data)>0):
					if(data[1:4]=='wr%'):#1 cause cmdParse sends \n
						tpath=data[3:data.find(';')]
						while(data[-2:]!='Āā'):
							data +=fd.recv(MAX_MSG).decode()
						try:
							with open(tpath, 'x') as f:
								f.write(data[data.find(';')+1:-2])
							print('\nFile Opened')
							if(os.fork()==0):
								root = Tk()
								text_editor = TextEditor(root, tpath, fd)
								root.mainloop()
								sel.close()
								Q.put('quit')
								return
								#os.execvp('gedit',['gedit', tpath])
						except Exception as e:
							print('\nUpdate File First')
							continue
					elif(data[1:4]=='con'):
						#print('Connecting To '+data[4:])
						sel.unregister(fd)
						last_cmd = cmd
						Q.put('discon')#data[4:])
						return
					else:
						print(data) 
				else:
					print('\nConnection Closed.')
					sel.unregister(fd)
					last_cmd = ''
					Q.put('close')
					#ipq.put(CleanExit)
					return
			elif key.fd ==0:
				last_cmd = cmd
				cmd = input()
				if cmd == "close" or cmd == 'exit':
					sel.close()
					Q.put('quit')
					return
				elif cmd[:5] == 'updt ':
					fil_path ='%'+cmd[5:].replace('/','%')
					exp=False
					try:
						content = Path(fil_path).read_text()
						os.remove(fil_path)
					except Exception as e:
						exp = True 
						print(e)
					if(exp==True):
						continue
					fd.sendall(('updt '+fil_path+';'+content+'Āā').encode())
				else:
					fd.sendall(cmd.encode())


def MakeSock():
	global serv_fd
	serv_fd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	serv_fd.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	serv_fd.settimeout(4)
	serv_fd.bind(('', CLIENT_PORT))
	serv_fd.listen(0)


def main():
	print(r'''
	       .--.                   .---.
	   .---|__|           .-.     |~~~|
	.--|===|--|_          |_|     |~~~|--.
	|  |===|  |'\     .---!~|  .--|   |--|
	|%%| D |  |.'\    |===| |--|%%|   |  |
	|%%| F |  |\.'\   |   | |__|  |   |  |
	|  | S |  | \  \  |===| |==|  |   |  |
	|  |   |__|  \.'\ |   |_|__|  |~~~|__|
	|  |===|--|   \.'\|===|~|--|%%|~~~|--|
	^--^---'--^    `-'`---^-^--^--^---'--'
	Connected To
		     Peek-achu
			       File System
''')
	sel.register(0, selectors.EVENT_READ) #input
	global serv_fd
	#-----------------------------------------------------------
	multicast_group = ('224.4.255.255', 50000)
	mult_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	mult_sock.settimeout(0.2)
	ttl = struct.pack('b', 1)
	mult_sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, ttl)
	mult_sock.sendto(b'cli', multicast_group)
	#-----------------------------------------------------------
	MakeSock()
	while(True):
		while(True):
			if(last_cmd == ''):
				print('Connecting To System...')
			try:
				conn, addr = serv_fd.accept()
			except socket.timeout:
				mult_sock.sendto(b'cli', multicast_group)
			else:
				serv_fd.shutdown(socket.SHUT_RDWR)
				serv_fd.close()
				break
				#print('Out of accept')
		if(last_cmd != ''):
			conn.sendall(last_cmd.encode())
		t1 = threading.Thread(target=recCliMsg, kwargs={'fd':conn})
		t1.daemon = True
		t1.start()
		data = Q.get()
		#print(data)
		conn.close()
		t1.join()
		if(data == 'quit'):
			mult_sock.close()
			sys.exit()
		elif(data == 'close'):
			MakeSock()
			mult_sock.sendto(b'cli', multicast_group)
		elif(data == 'discon'):
			MakeSock()
			continue

if __name__ == "__main__":
	main()

