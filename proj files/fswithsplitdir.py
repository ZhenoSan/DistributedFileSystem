import os,socket,threading,sys,ast, queue
from pathlib import Path
#import pickle
'''
To do:
1) Replicated Files in Dir
2) Updating Replicated Files
3) Deleting Replicated Files
4) Connecting using hostname

'''
MAX_MSG = 1024
START_PORT = 7777
MAX_SERVS = 3

SERVER_ID = 7777

fileDirectoryRoot = 'root'
replicDir = 'replica'

DFSOnline = 0

Q = queue.Queue()

localfilelist = []
localreplicalist = []

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
	def __init__(self):
		self.fd = None
		self.filelist = None
		self.replicalist = []
		self.count = 99999


def globalListGenerator():
	globalfilelist=[]
	for ports in serverlist:
		if(serverlist[ports].filelist!=None):
			globalfilelist.append(serverlist[ports].filelist)
	return globalfilelist

def generateList():
	del localfilelist[:]
	for root, dirs, files in os.walk(fileDirectoryRoot):
		level = root.replace(fileDirectoryRoot, '').count(os.sep)
		localfilelist.append(str(level)+os.path.basename(root))
		for f in files:
			localfilelist.append(str(level+1)+f)
	serverlist[SERVER_ID].filelist = localfilelist

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


def costCreationFunc(cost, ign_port):
	if(ign_port ==0):
		port=SERVER_ID
	#	defport = False
	#else:
	#	defport = True
	for sport in (serverlist):
		if ign_port == sport:
				continue		
		#if(defport):
		#	port = sport
		#	cost =len(serverlist[port].filelist)
		#	defport=False
		if serverlist[sport].fd!=None:
			if len(serverlist[sport].filelist) < cost:
				cost = len(serverlist[sport].filelist)
				port = sport
				#defport=False
	return port
'''
def costCreationFunc(cost, port,ign_port):
	for sport in serverlist:
		if serverlist[sport].filelist!=None:
			if len(serverlist[sport].filelist) < cost:
				cost = len(serverlist[sport].filelist)
				port = sport
	return port
'''
#def pathParse(path_str, file_list):
def cmdParse(cmd):
	#filelist = os.listdir("root")
	ret_msg = ''
	if cmd == 'peek'or cmd == 'dir':
		T = globalListGenerator()
		#T.append(localfilelist)
		ret_msg = '-'*10 +'File Directory' + '-'*10 +'\n'
		ret_msg+=localfilelist[0][1:]+'/'
		last_lvl = 0
		curr_lvl = 0
		for filelists in (T):
			for index,line in enumerate(filelists):
				if(line[1:]==localfilelist[0][1:]):
					continue
				last_lvl = curr_lvl
				curr_lvl = int(line[:1])
				file_name = line[1:]
				if(index<len(filelists)-1):
					nxt_lvl = int(filelists[index+1][:1])
				else:
					nxt_lvl = 11
				if(last_lvl<curr_lvl and nxt_lvl==curr_lvl):
					ret_msg += '\n'+'    '*curr_lvl+'┌'+file_name
				elif(nxt_lvl>curr_lvl):
					if(nxt_lvl ==11):
						ret_msg += '\n'+'    '*curr_lvl+'└'+file_name
					else:
						ret_msg += '\n'+'    '*curr_lvl+'└'+bcolors.BOLD+file_name+'/'+bcolors.ENDC
				else:
					ret_msg += '\n'+'    '*curr_lvl+'├'+file_name
	elif cmd[:5] == 'exis ':
		if (fileExists(cmd[5:])):	
			ret_msg = 'File Present'
		else:
			ret_msg = 'File Absent'
	elif cmd == 'repl':
		for serports in serverlist:
			ret_msg += repr(serverlist[serports].replicalist)
	elif cmd == 'cons':
		ret_msg ='_'*40
		for servers in serverlist:
			if serverlist[servers].fd!=None:
				ret_msg +='\n'+repr(serverlist[servers].fd) + ' ' +str(servers)
		ret_msg +='_'*40
	elif cmd[:5] == "open ":
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
				os.execvp('gedit',['gedit', './'+fileDirectoryRoot+'/'+path])
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
	elif cmd[:5] == 'writ ':
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
			try:	
				ret_msg+= (Path("root/"+fil_path).read_text() +'&%')
			except Exception as e:
				ret_msg = e
		else:
			port = fileLocator(fil_path)
			serverlist[port].fd.sendall(('give'+fil_path).encode())
			ret_msg+= (Q.get()+'&%')
	elif cmd[:5] == 'updt ':
		fil_path = cmd[5:cmd.find(';')].replace('%','/')
		fil_path = fil_path[1:]
		if (not fileExists(fil_path)):
			ret_msg='File Does not Exists'
		elif (fileExistsLoc(fil_path)):
			cmd=cmd[:-2]
			try:
				with open(fileDirectoryRoot+'/'+fil_path,'w') as f:
					f.write(cmd[cmd.find(';')+1:])
					ret_msg = 'Written To File'
			except Exception as e:
				ret_msg = e
		else:
			serverlist[fileLocator(fil_path)].fd.sendall((cmd).encode())
			ret_msg = 'Written To File'
	elif cmd[:5] == 'make ':
		if (fileExists(cmd[5:])):
			ret_msg='File Already Exists'
		else:
			cost = len(localfilelist)
			port = SERVER_ID
			if(cmd.rfind('/')!=-1):
				if (fileExistsLoc(cmd[5:cmd.rfind('/')])):
					cost=0
				elif fileLocator(cmd[5:cmd.rfind('/')])!=-1:
					cost=0
					port = fileLocator(cmd[5:cmd.rfind('/')])
			if cost !=0:
				port = costCreationFunc(cost,0)
			if(port==SERVER_ID):
				file1 = open(fileDirectoryRoot+"/"+cmd[5:],'w+')
				file1.close()
				generateList()
				broadcast(('dir_up'+repr(localfilelist)).encode())
				ret_msg ='File Created'
				if(DFSOnline!=0):
					replic_serv = costCreationFunc(9999,SERVER_ID)
					serverlist[replic_serv].fd.sendall(('!@rep%'+cmd[5:].replace('/','%')).encode())
			else:
				serverlist[port].fd.sendall((cmd).encode())
				ret_msg ='File Created'
	elif cmd[:5] == 'remv ':
		if not(fileExists(cmd[5:])):
			ret_msg ='File Does Not Exists'
		else:
			ret_msg ='File Deleted'
			if (fileExistsLoc(cmd[5:])):
				os.remove(fileDirectoryRoot+"/"+cmd[5:])
				generateList()
				broadcast(('dir_up'+repr(localfilelist)).encode())
			else:
				serverlist[fileLocator(cmd[5:])].fd.sendall((cmd).encode())
	elif cmd[:5] == 'read ':
		path = cmd[5:]
		exe_str = cmd[-(len(path)-(path.rfind('.'))):]
		extensions = ['.txt','.c','.py']
		if not(any(x in exe_str for x in extensions)):
			ret_msg ='File not readable'
		elif not(fileExists(path)):
			ret_msg ='File Does Not Exists'
		elif (fileExistsLoc(path)):
			#print(ret_msg) QUERY 1
			try:
				ret_msg =('_'*40+'\n' +Path(fileDirectoryRoot+"/"+path).read_text()+'_'*40)
			except Exception as e:
				ret_msg = e
		else:
			port = fileLocator(path)
			serverlist[port].fd.sendall(('give'+path).encode())
			ret_msg ='_'*40+'\n' + Q.get()+'\n'+'_'*40
	elif cmd[:5] == 'apen ':
		text = cmd.split(' ',2)
		exe_str = cmd[(text[1]).rfind('.'):]
		extensions = ['.txt','.c','.py']
		if not(any(x in exe_str for x in extensions)):
			ret_msg ='File not readable'
		elif not(fileExists(text[1])):
			ret_msg ='File Does Not Exists'
		elif (fileExistsLoc(text[1])):
			try:
				with open("root/"+text[1], 'a+') as f:
					f.write(text[2])
					ret_msg = 'appended to file'
			except Exception as e:
				ret_msg = e
		else:
			port = fileLocator(text[1])
			serverlist[port].fd.sendall(('apen'+';' + text[1]+ ';'+str(text[2])).encode())
			ret_msg = 'appended to file'
	elif ('help'in cmd or 'cmd' in cmd):
		ret_msg ='_'*30 + "\nList Of Possible Commands:\n" + '-'*30+"\npeek View File Directory ..\ncons View Connections ..\nmake [file] ..\nremv [file] ..\nexis [file] ..\nread [file] ..\napen [file] [text] ..\nwrit [file] ..\nupdt [file] ..\nexit Close Program ..\n"+'-'*30
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
			all_data = data.split('!@')
			for data in all_data:
				if(len(data)<1):
					continue
				print('\nMsg Recieved from Server: ', port,' : ',data, '\n<cmd>: ', end='',flush=True)
				if data[:6] == 'dir_up':
					serverlist[port].filelist = ast.literal_eval(data[6:])
				elif data[:6] == 'rep_up':
					serverlist[port].replicalist = ast.literal_eval(data[6:])
				elif data[:4] == 'rep%':
					file1 = open(replicDir+"/"+data[3:],'w+')
					file1.close()
					serverlist[SERVER_ID].replicalist.append(data.replace('%','/'))
					broadcast(('rep_up'+repr(serverlist[SERVER_ID].replicalist)).encode())
				elif data[:4] == 'give':
					try:
						file_content = Path("root/"+data[4:]).read_text()
						fd.sendall(('fil_msg'+';'+file_content+'&%').encode())
					except Exception as e:
						fd.sendall(e.encode())
				elif(data[:5] == 'updt '):
					while(data[-2:]!='&%'):
						data +=fd.recv(MAX_MSG).decode()
					reply = cmdParse(data)
					fd.sendall(reply.encode())
				elif data[:4] == 'apen':
					text = data.split(';',2)
					try:
						with open(fileDirectoryRoot+"/"+text[1], 'a') as f:
							f.write(str(text[2]))
					except Exception as e:
						print(e)
				elif data[:5] == 'remv ':
					print(cmdParse(data))
				elif data[:5] == 'make ':
					print(cmdParse(data))
				elif data[:7] == 'fil_msg':
					file_data = data.split(';')
					while(file_data[1][-2:]!='&%'):
						file_data[1] += fd.recv(MAX_MSG).decode()
					Q.put(file_data[1][:-2])
					#print(result + '\n<cmd>: ', end='',flush=True)
			else:
				pass
		else:
			print('\nTerminating Connection:', port,fd.getpeername(),'\n<cmd>: ', end='',flush=True) 
			fd.close()
			serverlist[port].fd = None
			serverlist[port].filelist = None
			global DFSOnline
			DFSOnline-=1
			break


def recCliMsg(fd):
	while(True):
		data = (fd.recv(MAX_MSG)).decode()
		if len(data) >0:
			print('\nMsg Recieved from Client: ', repr(fd.getpeername()),' : ',data, '\n<cmd>: ', end='',flush=True)
			if(data[:5] == 'updt '):
				while(data[-2:]!='&%'):
					data +=fd.recv(MAX_MSG).decode()
			reply = cmdParse(data)
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
			global DFSOnline
			DFSOnline+=1
			threading.Thread(target=recServMsg, kwargs={'fd':conn}).start()
		else:
			clientlist.append(conn)
			#print(clientlist)
			print('\nIncoming Client Connection:', addr,'\n<cmd>: ', end='',flush=True)
			threading.Thread(target=recCliMsg, kwargs={'fd':conn}).start()


def main():
	for x in range(MAX_SERVS):
		serverlist[START_PORT+x]=serverContents()
	print('Available ports: ',list(serverlist.keys()))
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
	global SERVER_ID, localreplicalist, DFSOnline
	SERVER_ID = arg
	generateList()
	localreplicalist = os.listdir(replicDir)
	for ind, files in enumerate(localreplicalist):
		localreplicalist[ind] = files[1:].replace('%','/')
	serverlist[SERVER_ID].replicalist = localreplicalist
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
				DFSOnline+=1
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
	
	

