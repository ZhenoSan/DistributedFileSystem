import os,socket,threading,sys,ast, queue
from pathlib import Path
#import pickle

MAX_MSG = 1024
START_PORT = 7777
MAX_SERVS = 3

Q = queue.Queue()

localfilelist = []

class bcolors:
    HEADER = '\033[95m'#PURPLE
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'#YELLOW
    FAIL = '\033[91m'#RED
    ENDC = '\033[0m'#WHITE
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


serverlist={}
clientlist=[]

class serverContents:
	def __init__(self,fd, filelist, replicalist):
		self.fd = fd
		self.filelist = filelist
		self.replicalist = replicalist


def globalListGenerator():
	globalfilelist=[]
	for ports in serverlist:
		if(serverlist[ports].filelist!=None):
			globalfilelist.append(serverlist[ports].filelist)
	return globalfilelist

def generateList():
	del localfilelist[:]
	for root, dirs, files in os.walk('root'):
		level = root.replace('root', '').count(os.sep)
		localfilelist.append(str(level)+os.path.basename(root))
		for f in files:
			localfilelist.append(str(level+1)+f)


'''def fileExists(name):
	T = globalListGenerator()
	T.append(localfilelist)
	while True:
		for filelist in (T):#izip_longest
			for fil in filelist:
				if name in fil[1:]:
					return True
		return False'''

def fileExists(name):
	T = globalListGenerator()
	T.append(localfilelist)
	old_level = 1
	level = 1
	ind =0
	names_split = name.split('/')
	for filelist in (T):
		for fil in filelist:
			if(int(fil[:1]) ==0):
				continue
			if ((names_split[ind] == fil[1:]) and int(fil[:1])==level):
				if ind == len(names_split)-1:
					return True
				else:
					ind+=1
					old_level = level
					level+=1
					continue
			elif(int(fil[:1])<level and old_level !=level):
				old_level = level
				ind-=1
	return False


def fileExistsLoc(name):
	old_level = 1
	level = 1
	ind =0
	names_split = name.split('/')
	for fil in localfilelist:
		if(int(fil[:1]) ==0):
			continue
		if ((names_split[ind] == fil[1:]) and int(fil[:1])==level):
			if ind == len(names_split)-1:
				return True
			else:
				ind+=1
				old_level = level
				level+=1
				continue
		elif(int(fil[:1])<level and old_level !=level):
			old_level = level
			ind-=1
	return False


def fileLocator(name):#return address of server with file
	globalfilelist=[]
	gfl=[]
	for ports in serverlist:
		if(serverlist[ports].filelist!=None):
			globalfilelist.append(serverlist[ports].filelist)
			gfl.append(ports)
	T = globalfilelist
	old_level = 1
	level = 1
	ind =0
	names_split = name.split('/')
	for x,filelist in enumerate(T):
		for fil in filelist:
			if(int(fil[:1]) ==0):
				continue
			if ((names_split[ind] == fil[1:]) and int(fil[:1])==level):
				if ind == len(names_split)-1:
					return gfl[x]
				else:
					ind+=1
					old_level = level
					level+=1
					continue
			elif(int(fil[:1])<level and old_level !=level):
				old_level = level
				ind-=1
	return -1


def broadcast(msg):
	for port in serverlist:
		if serverlist[port].fd!=None:
			try:
				serverlist[port].fd.sendall(msg)
			except:
				continue

#def pathParse(path_str, file_list):
	
def cmdParse(cmd):
	#filelist = os.listdir("root")
	ret_msg = ''
	if cmd == 'dir':
		T = globalListGenerator()
		T.append(localfilelist)
		ret_msg = '-'*10 +'File Directory' + '-'*10 +'\n'
		ret_msg+=localfilelist[0][1:]
		for filelists in (T):
			for line in filelists:
				if(line[1:]==localfilelist[0][1:]):
					continue
				ret_msg += '\n'+'    '*int(line[0:1])+line[1:]
	elif cmd[0:5] == 'exis ':
		if (fileExists(cmd[5:])):	
			ret_msg = 'File Present'
		else:
			ret_msg = 'File Absent'
	elif cmd == 'cons':
		ret_msg ='_'*40
		for servers in serverlist:
			if serverlist[servers].fd!=None:
				ret_msg +='\n'+repr(serverlist[servers].fd) + ' ' +str(servers)
		ret_msg +='_'*40
	elif cmd[0:5] == "open ":
		path = cmd[5:]
		exe_str = cmd[-(len(path)-(path.rfind('.'))):]
		extensions = ['.txt','.c','.py']
		if not(any(x in exe_str for x in extensions)):
			ret_msg ='File Cannot Be Opened'
		elif not(fileExists(path)):
			ret_msg ='File Does Not Exists'
		elif (fileExistsLoc(path)):
			if(os.fork()==0):
				ret_msg = 'File Opened'
				os.execvp('gedit',['gedit', './root/'+path])
		else:
			port = fileLocator(path)
			serverlist[port].fd.sendall(('give'+path).encode())
			ret_msg = 'File Opened'
			if path.rfind('/') !=-1:
				tpath = '%'+path.replace('/', '%')#path[path.rfind('/')+1:]
			else:
				tpath = '%'+path
			with open(tpath, 'x') as f:
				f.write(Q.get())
			ret_msg = 'File Opened'	
			if(os.fork()==0):
				os.execvp('gedit',['gedit', tpath])
	elif cmd[0:5] == 'writ ':
		fil_path = cmd[5:]
		tpath = '%' + fil_path.replace('/','%')
		exe_str = cmd[-(len(fil_path)-(fil_path.rfind('.'))):]
		extensions = ['.txt','.c','.py']
		ret_msg = 'wr'+tpath+';'
		if not(any(x in exe_str for x in extensions)):
			ret_msg ='File Cannot Be Opened'
		elif not(fileExists(fil_path)):
			ret_msg ='File Does Not Exists'
		elif (fileExistsLoc(fil_path)):	
			ret_msg+= Path("root/"+fil_path).read_text() +'%'
		else:
			port = fileLocator(fil_path)
			serverlist[port].fd.sendall(('give'+fil_path).encode())
			ret_msg+= Q.get()+'%'
	elif cmd[0:5] == 'updt ':
		fil_path = cmd[5:cmd.find(';')].replace('%','/')
		fil_path = fil_path[1:]
		if (not fileExists(fil_path)):
			ret_msg='File Does not Exists'
		elif (fileExistsLoc(fil_path)):
			cmd=cmd[:-1]
			with open('root/'+fil_path,'w') as f:
				f.write(cmd[cmd.find(';')+1:])
			ret_msg = 'Written To File'
		else:
			serverlist[fileLocator(path[1:])].fd.sendall((cmd).encode())
			ret_msg = 'Written To File'
	elif cmd[0:6] == 'touch ':
		if (fileExists(cmd[6:])):
			ret_msg='File Already Exists'
		else:
			file1 = open("root/"+cmd[6:],'w+')
			generateList()
			file1.close()
			broadcast(('dir_up'+repr(localfilelist)).encode())
			ret_msg ='File Created'
	elif cmd[0:4] == 'del ':
		if not(fileExists(cmd[4:])):
			ret_msg ='File Does Not Exists'
		else:
			ret_msg ='File Deleted'
			if (fileExistsLoc(cmd[4:])):
				os.remove("root/"+cmd[4:])
				generateList()
				broadcast(('dir_up'+repr(localfilelist)).encode())
			else:
				serverlist[fileLocator(cmd[4:])].fd.sendall((cmd).encode())
	elif cmd[0:5] == 'read ':
		path = cmd[5:]
		exe_str = cmd[-(len(path)-(path.rfind('.'))):]
		extensions = ['.txt','.c','.py']
		if not(any(x in exe_str for x in extensions)):
			ret_msg ='File not readable'
		elif not(fileExists(path)):
			ret_msg ='File Does Not Exists'
		elif (fileExistsLoc(path)):
			#print(ret_msg) QUERY 1
			ret_msg =('_'*40+'\n' +Path("root/"+path).read_text()+'_'*40)
		else:
			port = fileLocator(path)
			serverlist[port].fd.sendall(('give'+path).encode())
			ret_msg ='_'*40+'\n' + Q.get()+'\n'+'_'*40
	elif cmd[0:5] == 'apen ':
		text = cmd.split(' ',2)
		exe_str = cmd[(text[1]).rfind('.'):]
		extensions = ['.txt','.c','.py']
		if not(any(x in exe_str for x in extensions)):
			ret_msg ='File not readable'
		elif not(fileExists(text[1])):
			ret_msg ='File Does Not Exists'
		elif (fileExistsLoc(text[1])):
			with open("root/"+text[1], 'a') as f:
				f.write(text[2])
				ret_msg = 'appended to file'
		else:
			port = fileLocator(text[1])
			serverlist[port].fd.sendall(('apen'+';' + text[1]+ ';'+str(text[2])).encode())
			ret_msg = 'appended to file'
	elif ('help'in cmd or 'cmd' in cmd):
		ret_msg ='_'*30 + "\nList Of Possible Commands:\n" + '-'*30+"\ndir View File Directory ..\ncons View Connections ..\ntouch [file_name] ..\ndel [file_name] ..\nexis [file_name] ..\nread [file_name] ..\napen [file_name] [text] ..\nopen [file_name] ..\nclose Close Program ..\n"+'-'*30
	else:
		ret_msg ='Invalid Command. Use help.'
	return ('\n' + ret_msg)


def recServMsg(fd):
	while(True):
		data = fd.recv(MAX_MSG).decode()
		port = 0
		for ports in serverlist:
			if serverlist[ports].fd == fd:
				port = ports
				break
		if len(data) >0:
			print('\nMsg Recieved from Server: ', port,' : ',data, '\n<cmd>: ', end='',flush=True)
			if data[0:6] == 'dir_up':
				serverlist[port].filelist = ast.literal_eval(data[6:])
			elif data[0:4] == 'give':
				if(data[4:6]=='fd'):
					file_content = Path("root/"+data[7:]).read_text()
					fd.sendall(('fil_msg'+'fd'+data[6:7]+str(len(file_content))+';'+file_content).encode())	
				else:
					file_content = Path("root/"+data[4:]).read_text()
					fd.sendall(('fil_msg'+str(len(file_content))+';'+file_content).encode())
			elif if(data[:5] == 'updt '):
				while(data[-1:]!='%'):
					data +=fd.recv(MAX_MSG).decode()
				reply = cmdParse(data)
				fd.sendall(reply.encode())
			elif data[0:4] == 'apen':
				text = data.split(';',2)
				with open("root/"+text[1], 'a') as f:
					f.write(str(text[2]))
			elif data[0:3] == 'del':
				print(cmdParse(data))
			elif data[0:7] == 'fil_msg':
				st_ind = 7
				file_data = data.split(';')
				file_size = int(file_data[0][st_ind:])
				data = None
				file_temp_data_size = MAX_MSG-st_ind-file_size
				if file_size > file_temp_data_size:
					data = fd.recv(file_size-file_temp_data_size).decode()
				if(data !=None):
					Q.put(file_data[1]+data)
				else:
					Q.put(file_data[1])
				#print(result + '\n<cmd>: ', end='',flush=True)
			else:
				pass
		else:
			print('\nTerminating Connection:', port,fd.getpeername(),'\n<cmd>: ', end='',flush=True) 
			fd.close()
			serverlist[port].fd = None
			serverlist[port].filelist = None
			break


def recCliMsg(fd):
	while(True):
		data = (fd.recv(MAX_MSG)).decode()
		if len(data) >0:
			print('\nMsg Recieved from Client: ', repr(fd.getpeername()),' : ',data, '\n<cmd>: ', end='',flush=True)
			if(data[:5] == 'updt '):
				while(data[-1:]!='%'):
					data +=fd.recv(MAX_MSG).decode()
			reply = cmdParse(data)
			#print(reply) QUERY 2
			fd.sendall(reply.encode())
		else:
			print('\nTerminating Connection with Client:', fd.getpeername(),'\n<cmd>: ', end='',flush=True) 
			clientlist.remove(fd)
			fd.close()
			break

def sockListen(sock):
	#print('Thread SockBind')
	sock.listen()
	while(True):
		conn, addr = sock.accept()
		#print('Conn Accept Loop')
		if(sock.getsockname()[1]>=START_PORT):
			server_port=int(conn.recv(MAX_MSG).decode());	
			serverlist[server_port].fd= conn
			if len(localfilelist)>1:
				conn.sendall(repr(localfilelist).encode())
			serverlist[server_port].filelist = ast.literal_eval(conn.recv(MAX_MSG).decode())
			#print('\nMsg:'+repr(serverlist[server_port].filelist))
			print('\nIncoming Server Connection:', server_port, addr,'\n<cmd>: ', end='',flush=True)
			threading.Thread(target=recServMsg, kwargs={'fd':conn}).start()
		else:
			clientlist.append(conn)
			#print(clientlist)
			print('\nIncoming Client Connection:', addr,'\n<cmd>: ', end='',flush=True)
			threading.Thread(target=recCliMsg, kwargs={'fd':conn}).start()


def main():
	for x in range(MAX_SERVS):
		serverlist[START_PORT+x]=serverContents(None, None, None)
	print('Available ports: ',list(serverlist.keys()))
	generateList()
	serv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	inc=0
	while True:
		try:
			#arg = int(input('Select Server Port: '))
			arg = START_PORT+inc
			if arg not in serverlist.keys():
				raise ValueError
			serv.bind(('127.0.0.1', arg))
			break
		except ValueError:
			print('Error: Incorrect Port Number')
		except OSError:
			print('Port Already In Use')
		finally:
			inc+=1
	serverlist[arg].fd=serv
	t = threading.Thread(target=sockListen, kwargs={"sock": serv})
	t.daemon = True
	t.start()
	onlineServs = []
	offlineServers=[]
	i=0
	for servers in serverlist:
			if servers == int(arg):
				continue
			onlineServs.append(socket.socket(socket.AF_INET, socket.SOCK_STREAM))
			try:
				onlineServs[i].connect(('127.0.0.1', servers))
				serverlist[servers].fd = onlineServs[i]
				print('Connected to Server: ', servers)
				onlineServs[i].sendall(str(arg).encode())
				serverlist[servers].filelist = ast.literal_eval((onlineServs[i].recv(MAX_MSG).decode()))
				#print('\nMsg:'+repr(serverlist[servers].filelist))
				if len(localfilelist)>1:
					onlineServs[i].sendall(repr(localfilelist).encode())
				t = threading.Thread(target=recServMsg, kwargs={'fd':onlineServs[i]})
				t.daemon = True
				t.start()
			except ConnectionRefusedError:
				offlineServers.append(servers)
			i+=1
	print('Offline Servers: ', offlineServers)
	cli = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	while(True):
		try:
			cli.bind(('127.0.0.1', START_PORT-int(input('no:'))))
			break
		except OSError:
			print('try another')
	ct = threading.Thread(target = sockListen, kwargs={'sock':cli})
	ct.daemon = True
	ct.start()
	while(True):
		cmd=input('<cmd>: ')
		if(cmd=='close' or cmd == 'exit'):
			sys.exit()
		print(cmdParse(cmd))

		
if __name__ == "__main__":
	main()
	
	

