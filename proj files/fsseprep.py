import os,socket,threading,sys,ast, queue, shutil, xattr
from pathlib import Path
#
'''
To do:
2) Updating Replicated Files
3) Deleting Replicated Files
4) Connecting using hostname
5) Smart client and file transfer with data server direct
6) Making directory and file
7) Removing from list

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
			for files in serverlist[ports].filelist:
				globalfilelist.append(files[0])
	return globalfilelist


def globalReplicGenerator():
	globalrepllist=[]
	for ports in serverlist:
		if(serverlist[ports].replicalist!=[]):
			for files in serverlist[ports].replicalist:
				globalrepllist.append(files[0])
	return globalrepllist


def generateList():
	del localfilelist[:]
	for root, dirs, files in os.walk(fileDirectoryRoot):
		#localfilelist.append(os.path.relpath(root,fileDirectoryRoot))
		prefx = os.path.relpath(root,fileDirectoryRoot)
		if (prefx != '.'):
			prefx = '/'+prefx
		else:
			prefx = ''
		for f in files:
			try:
				att = (xattr.get(fileDirectoryRoot+prefx+'/'+f,'user.comment')).decode()
			except OSError:
				att = 0
			localfilelist.append([prefx+'/'+f, str(att)])
		for d in dirs:
			localfilelist.append([prefx+'/'+d+'/',str(-1)])
	serverlist[SERVER_ID].filelist = localfilelist
	for files in localfilelist:
		print(files)


def generateRepList():
	global localreplicalist
	localreplicalist = os.listdir(replicDir)
	for ind, files in enumerate(localreplicalist):
		try:
			att = (xattr.get(replicDir+'/'+files,'user.comment')).decode()
		except OSError:
				att = 0
		localreplicalist[ind] = [files.replace('%','/'), str(att)]
	serverlist[SERVER_ID].replicalist = localreplicalist


def fileExists(name):
	T = globalListGenerator()
	if('/' not in name[:1]):
		name = '/'+name
	for fil in T:
		if fil == name: 
			return True
	return False


def fileExistsLoc(name):
	if('/' not in name[:1]):
		name = '/'+name
	for fil in localfilelist:
		if fil[0] == name: 
				return True
	return False


def locFileLocator(name):
	if('/' not in name[:1]):
		name = '/'+name
	for ind, files in enumerate(localfilelist):
		if files[0]==name:
			return ind


def globFileLocator(serv, name):
	if('/' not in name[:1]):
		name = '/'+name
	for ind, files in enumerate(serverlist[serv].filelist):
		if files[0]==name:
			return ind


def fileLocator(name):#return address of server with file
	if('/' not in name[:1]):
		name = '/'+name
	globalfilelist=[]
	gfl=[]
	for ports in serverlist:
		if(serverlist[ports].filelist!=None):
			globalfilelist.append(serverlist[ports].filelist)
			gfl.append(ports)
	T = globalfilelist
	for x,filelist in enumerate(T):
		for fil in filelist:
			if fil[0] == name: 
				return gfl[x]
	return -1


def broadcast(msg):
	for port in serverlist:
		if serverlist[port].fd!=None and port != SERVER_ID:
			try:
				serverlist[port].fd.sendall(msg)
			except:
				continue


def costCreationFunc(cost, ign_port):
	if(ign_port ==0):
		port=SERVER_ID
	for sport in (serverlist):
		if ign_port == sport:
				continue		
		if serverlist[sport].fd!=None:
			if len(serverlist[sport].filelist) < cost:
				cost = len(serverlist[sport].filelist)
				port = sport
	return port


def updateFile(fname, rep, content):
	if(rep):
		for files in localfilelist:
			if fname == files[0]:
				pass
	else:
		localreplicalist = []


def syncFiles():
	pass

def cmdParse(cmd):
	#filelist = os.listdir("root")
	ret_msg = ''
	if cmd == 'peek'or cmd == 'dir':
		T = globalListGenerator()
		T.extend(globalReplicGenerator())
		T = set(T)
		ret_msg = '-'*10 +'File Directory' + '-'*10 +'\n'
		ret_msg +=fileDirectoryRoot+'/\n' 
		filelists = sorted(T)
		for ind, files in enumerate(filelists):
			lvl = files[:-1].count('/')
			name = files[:-1].rfind('/')
			prev_lvl =filelists[ind-1][:-1].count('/')
			ret_msg += '    '*lvl
			if(ind == len(filelists)-1):
				ret_msg += '└'+files[name:]+'\n'
				continue
			else:
				nxt_lvl = filelists[ind+1][:-1].count('/')
			if(lvl>prev_lvl and nxt_lvl == lvl):
				ret_msg += '┌'
			elif( lvl == nxt_lvl):
				ret_msg +=  '├'
			else:
				ret_msg += '└'
			ret_msg += files[name:]+'\n'
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
				ret_msg+= (Path(fileDirectoryRoot+"/"+fil_path).read_text() +'Āā')
			except Exception as e:
				ret_msg = str(e)
		else:
			port = fileLocator(fil_path)
			serverlist[port].fd.sendall(('give'+fil_path).encode())
			ret_msg+= (Q.get()+'Āā')
	elif cmd[:5] == 'updt ':
		fil_path = cmd[5:cmd.find(';')].replace('%','/')
		fil_path = fil_path[1:]
		if (not fileExists(fil_path)):
			ret_msg='File Does not Exists'
		elif (fileExistsLoc(fil_path)):
			cmd=cmd[:-2]
			try:
				name = fileDirectoryRoot+'/'+fil_path
				with open(name,'w') as f:
					f.write(cmd[cmd.find(';')+1:])
					ret_msg = 'Written To File'
				att =int( localfilelist[locFileLocator('/'+fil_path)][1])+1
				xattr.set(name, 'user.comment', str(att))
				broadcast(('ver_up'+str(att)+';/'+fil_path+'Ĕ').encode())
			except Exception as e:
				ret_msg = str(e)
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
				flag = True
				ret_msg ='File Created'
				try:
					file1 = open(fileDirectoryRoot+"/"+cmd[5:],'w+')
					file1.close()
				except IsADirectoryError:
					os.makedirs(fileDirectoryRoot+"/"+cmd[5:cmd.rfind('/')])
					flag = False
					ret_msg = 'Directory Created'
				except FileNotFoundError:
					os.makedirs(fileDirectoryRoot+"/"+cmd[5:cmd.rfind('/')])
					file1 = open(fileDirectoryRoot+"/"+cmd[5:],'w+')
					file1.close()
				broadcast(('dir_ap'+"/"+cmd[5:]).encode())
				if(flag):
					localfilelist.append(["/"+cmd[5:],str(0)])
					xattr.set(fileDirectoryRoot+"/"+cmd[5:],"user.comment", str(0))
					if(DFSOnline!=0):
						replic_serv = costCreationFunc(9999,SERVER_ID)
						serverlist[replic_serv].fd.sendall(('Ĕrep%'+cmd[5:].replace('/','%')).encode())
				else:
					localfilelist.append(["/"+cmd[5:],str(-1)])
			else:
				serverlist[port].fd.sendall((cmd).encode())
				ret_msg ='File Created'
	elif cmd[:5] == 'remv ':
		if not(fileExists(cmd[5:])):
			ret_msg ='File Does Not Exists'
		else:
			ret_msg ='File Deleted'
			if (fileExistsLoc(cmd[5:])):
				name = cmd[5:]
				if('/' not in name[:1]):
						name = '/'+name
				if(cmd[-1:]!='/'):
					os.remove(fileDirectoryRoot+name)
				else:
					try:
						os.rmdir(fileDirectoryRoot+"/"+cmd[5:-1])
						ret_msg = "Directory Deleted"
					except OSError:
						ret_msg = "To Delete Non-empty Directories, use rmdr"
				del localfilelist[locFileLocator(name)]
				broadcast(('dir_dl'+name).encode())
			else:
				serverlist[fileLocator(cmd[5:])].fd.sendall((cmd).encode())
	elif cmd[:5] == 'rmdr ':
		if not(fileExists(cmd[5:])):
			ret_msg ='Directory Does Not Exists'
		else:
			ret_msg ='Directory Deleted'
			if (fileExistsLoc(cmd[5:])):
				shutil.rmtree((fileDirectoryRoot+"/"+cmd[5:]))
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
			try:
				ret_msg =('_'*40+'\n' +Path(fileDirectoryRoot+"/"+path).read_text()+'_'*40)
			except Exception as e:
				ret_msg = str(e)
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
					f.write(text[2]+'\n')
					ret_msg = 'appended to file'
			except Exception as e:
				ret_msg = str(e)
		else:
			port = fileLocator(text[1])
			serverlist[port].fd.sendall((cmd).encode())
			ret_msg = 'appended to file'
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
	elif ('help'in cmd or 'cmd' in cmd):
		ret_msg ='_'*30 + "\nList Of Possible Commands:\n" + '-'*30+"\npeek View File Directory ..\ncons View Connections ..\nmake [file] ..\nremv [file] ..\nexis [file] ..\nread [file] ..\nwrit [file] ..\nupdt [file] ..\nexit Close Program ..\n"+'-'*30 #\napen [file] [text] ..
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
			all_data = data.split('Ĕ')
			for data in all_data:
				if(len(data)<1):
					continue
				print('\nMsg Recieved from Server: ', port,' : ',data, '\n<cmd>: ', end='',flush=True)
				if data[:6] == 'dir_up':
					serverlist[port].filelist = ast.literal_eval(data[6:])
				elif data[:6] == 'dir_ap':
					serverlist[port].filelist.append([data[6:], str(0)])
				elif data[:6] == 'dir_dl':
					for files in serverlist[port].filelist:
						if data[6:] == files[0]:
							serverlist[port].filelist.remove(files)
							break
				elif data[:6] == 'rep_ap':
					serverlist[port].replicalist.append([data[6:], str(0)])
				elif data[:6] == 'ver_up':
					data = data.split(';')
					serverlist[port].filelist[globFileLocator(port, data[1])][1] = data[0][6:]
				elif data[:4] == 'rep%':
					file1 = open(replicDir+"/"+data[3:],'w+')
					file1.close()
					xattr.set(replicDir+"/"+data[3:],"user.comment", str(0))
					serverlist[SERVER_ID].replicalist.append([data[3:].replace('%','/'), str(0)])
					broadcast((('rep_ap'+data[3:]).replace('%','/')).encode())
				elif data[:4] == 'give':
					try:
						file_content = Path("root/"+data[4:]).read_text()
						fd.sendall(('fil_msg'+';'+file_content+'Āā').encode())
					except Exception as e:
						fd.sendall(e.encode())
				elif(data[:5] == 'updt '):
					while(data[-2:]!='Āā'):
						data +=fd.recv(MAX_MSG).decode()
					reply = cmdParse(data)
					fd.sendall(reply.encode())
				elif data[:7] == 'fil_msg':
					file_data = data.split(';')
					while(file_data[1][-2:]!='Āā'):
						file_data[1] += fd.recv(MAX_MSG).decode()
					Q.put(file_data[1][:-2])
					#print(result + '\n<cmd>: ', end='',flush=True)
				elif data[:4] == 'apen':
					cmdParse(data)
				elif data[:5] == 'remv ':
					print(cmdParse(data))
				elif data[:5] == 'make ':
					print(cmdParse(data))
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
				while(data[-2:]!='Āā'):
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
			conn.sendall((repr(localfilelist)+';'+repr(localreplicalist)+'Āā').encode())
			data = conn.recv(MAX_MSG).decode()
			while(data[-2:]!='Āā'):
					data +=conn.recv(MAX_MSG).decode()
			data = data.split(';')
			serverlist[server_port].filelist = ast.literal_eval(data[0])
			serverlist[server_port].replicalist = ast.literal_eval(data[1][:-2])
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
	generateRepList()
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
			data = onlineServs[i].recv(MAX_MSG).decode()
			while(data[-2:]!='Āā'):
					data +=onlineServs[i].recv(MAX_MSG).decode()
			data = data.split(';')
			serverlist[servers].filelist = ast.literal_eval(data[0])
			serverlist[servers].replicalist = ast.literal_eval(data[1][:-2])
			onlineServs[i].sendall((repr(localfilelist)+';'+repr(localreplicalist)+'Āā').encode())
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
	
	

