import os,socket,threading,sys,ast, queue, shutil, xattr, struct
from pathlib import Path
lock = threading.Lock()
Q = queue.Queue()

'''
To do:
3) Deleting Replicated Files
4) Connecting using hostname
5) Smart client and file transfer with data server direct
6) Making directory and file
7) Removing from list

'''
MAX_MSG = 1024
MAX_SERVS = 3
SERVER_PORT = 10000
CLIENT_PORT = 6969
DFSOnline = 0
RootDir = 'root'
#locname = str(socket.getfqdn())
locname = str(socket.gethostbyname(socket.gethostname()))

localfilelist = []
localreplicalist = []
serverlist={}
clientlist=[]

class bcolors:
    HEADER = '\033[95m'#PURPLE
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'#YELLOW
    FAIL = '\033[91m'#RED
    ENDC = '\033[0m'#WHITE
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


class serverContents:
	def __init__(self):
		self.fd = None
		self.filelist = None
		self.count = 99999


def globalListGenerator(ign_addr):
	globalfilelist=[]
	for server in serverlist:
		if server ==ign_addr:
			continue
		if(serverlist[server].filelist!=None):
			for files in serverlist[server].filelist:
				globalfilelist.append(files[0])
	return globalfilelist


def generateList():
	del localfilelist[:]
	del localreplicalist[:]
	for root, dirs, files in os.walk(RootDir):
		#localfilelist.append(os.path.relpath(root,RootDir))
		prefx = os.path.relpath(root,RootDir)
		if (prefx != '.'):
			prefx = '/'+prefx
		else:
			prefx = ''
		for f in files:
			try:
				att = (xattr.getxattr(RootDir+prefx+'/'+f,'user.comment')).decode()
			except OSError:
				att = 0
			if(f.count('%')>0):
				fname = prefx+f.replace('%','/')
				localfilelist.append([fname, str(att)])
				localreplicalist.append(fname)
			else:
				localfilelist.append([prefx+'/'+f, str(att)])
		for d in dirs:
			localfilelist.append([prefx+'/'+d+'/',str(-1)])
	serverlist[locname].filelist = localfilelist
	for files in localfilelist:
		print(files)


def fileExists(name):
	T = globalListGenerator(-1)
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


def repExistsLoc(name):
	if('/' not in name[:1]):
		name='/'+name
	for file in localreplicalist:
		if name == file:
			return True
	return False


def locFileLocator(name):
	if('/' not in name[:1]):
		name = '/'+name
	for ind, files in enumerate(localfilelist):
		if files[0]==name:
			return ind


def custFileLocator(serv, name):
	if('/' not in name[:1]):
		name = '/'+name
	for ind, files in enumerate(serverlist[serv].filelist):
		if files[0]==name:
			return ind


def fileLocator(name, ign_addr):#return address of server with file
	if('/' not in name[:1]):
		name = '/'+name
	globalfilelist=[]
	gfl=[]
	for server in serverlist:
		if server == ign_addr:
			continue
		if(serverlist[server].filelist!=None):
			globalfilelist.append(serverlist[server].filelist)
			gfl.append(server)
	for x,filelist in enumerate(globalfilelist):
		for fil in filelist:
			if fil[0] == name: 
				return gfl[x]
	return -1


def broadcast(msg):
	for server in serverlist:
		if serverlist[server].fd!=None and server != locname:
			try:
				serverlist[server].fd.sendall(msg)
			except:
				continue


def costCreationFunc(cost, ign_addr):
	if(ign_addr ==0):
		serv=locname
	for server in (serverlist):
		if ign_addr == server:
				continue		
		if serverlist[server].fd!=None:
			if len(serverlist[server].filelist) < cost:
				cost = len(serverlist[server].filelist)
				serv = server
	return serv


def syncFiles(serverid):
	for files in serverlist[serverid].filelist:
		for files2 in localfilelist:
			if files[0] == files2[0]:
				if int(files[1]) < int(files2[1]):
					if(repExistsLoc(files2[0])):
						files2[0] =files2[0].replace('/','%')
					name = RootDir+'/'+files2[0]
					serverlist[serverid].fd.sendall(('fil_up'+files[0]+';'+files2[1]+';'+Path(name).read_text() +'Āā').encode())
					serverlist[serverid].filelist[1] = files2[1]
				break


def cmdParse(cmd):
	#filelist = os.listdir("root")
	ret_msg = ''
	if cmd == 'peek'or cmd == 'dir':
		T = globalListGenerator(-1)
		#T.extend(globalReplicGenerator())
		T = set(T)
		ret_msg = '-'*10 +'File Directory' + '-'*10 +'\n'
		ret_msg +=RootDir+'/\n' 
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
	elif cmd[:5] == 'read ':
		path = cmd[5:]
		exe_str = cmd[-(len(path)-(path.rfind('.'))):]
		extensions = ['.txt','.c','.py']
		if not(any(x in exe_str for x in extensions)):
			ret_msg ='File not readable'
		elif not(fileExists(path)):
			ret_msg ='File Does Not Exists'
		elif (fileExistsLoc(path)):
			if(repExistsLoc(path)):
				path =path.replace('/','%')
				if('%' not in path[:1]):
					path='%'+path
			try:
				ret_msg =('_'*40+'\n' +Path(RootDir+"/"+path).read_text()+'_'*40)
			except Exception as e:
				ret_msg = str(e)
		else:
			servid = fileLocator(path, -1)
			#serverlist[port].fd.sendall(('give'+path).encode())
			#ret_msg ='_'*40+'\n' + Q.get()+'\n'+'_'*40
			ret_msg = 'con'+servid
			#serverlist[servid].fd.sendall('con'#getpeername()[0]
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
			if(repExistsLoc(fil_path)):
				fil_path =fil_path.replace('/','%')
				if('%' not in fil_path[:1]):
					fil_path='%'+fil_path
			try:
				ret_msg+= (Path(RootDir+"/"+fil_path).read_text() +'Āā')
			except Exception as e:
				ret_msg = str(e)
		else:
			servid = fileLocator(fil_path, -1)
			#serverlist[port].fd.sendall(('give'+fil_path).encode())
			#ret_msg+= (Q.get()+'Āā')
			ret_msg = 'con'+servid
			#serverlist[servid].fd.sendall('con'#getpeername()[0]
	elif cmd[:5] == 'updt ':
		fil_path = cmd[5:cmd.find(';')].replace('%','/')
		fil_path = fil_path[1:]
		if (not fileExists(fil_path)):
			ret_msg='File Does not Exists'
		elif (fileExistsLoc(fil_path)):
			name = RootDir+'/'+fil_path
			if(repExistsLoc(fil_path)):
				fil_path =fil_path.replace('/','%')
				if('%' not in fil_path[:1]):
					name = RootDir+'/%'+fil_path				
			try:
				with open(name,'w') as f:
					f.write(cmd[cmd.find(';')+1:])
					ret_msg = 'Written To File'
				att =int( localfilelist[locFileLocator(fil_path)][1])+1
				localfilelist[locFileLocator(fil_path)][1] = str(att)
				xattr.setxattr(name, 'user.comment', str(att))
				#broadcast(('ver_up'+str(att)+';/'+fil_path+'Ĕ').encode())
				serv = fileLocator(fil_path, SERVER_PORT)
				if(serv!=-1):
					if(int(serverlist[serv].filelist[custFileLocator(serv, fil_path)][1]) < att):
						serverlist[serv].fd.sendall(('ver_up'+str(att)+';/'+fil_path+'Ĕ'+cmd+'Āā'+'Ĕ').encode())
			except Exception as e:
				ret_msg = str(e)		
		else:
			serverlist[fileLocator(fil_path,-1)].fd.sendall((cmd+'Āā').encode())
			ret_msg = 'Written To File'
	elif cmd[:5] == 'make ':
		if (fileExists(cmd[5:])):
			ret_msg='File Already Exists'
		else:
			cost = len(localfilelist)
			serv = SERVER_PORT
			if(cmd.rfind('/')!=-1):
				if (fileExistsLoc(cmd[5:cmd.rfind('/')])):
					cost=0
				elif fileExists(cmd[5:cmd.rfind('/')]):
					cost=0
					serv = fileLocator(cmd[5:cmd.rfind('/')],-1)
			if cost !=0:
				serv = costCreationFunc(cost,0)
			if(serv==SERVER_PORT):
				flag = True
				ret_msg ='File Created'
				try:
					file1 = open(RootDir+"/"+cmd[5:],'w+')
					file1.close()
				except IsADirectoryError:
					os.makedirs(RootDir+"/"+cmd[5:cmd.rfind('/')])
					flag = False
					ret_msg = 'Directory Created'
				except FileNotFoundError:
					os.makedirs(RootDir+"/"+cmd[5:cmd.rfind('/')])
					file1 = open(RootDir+"/"+cmd[5:],'w+')
					file1.close()
				broadcast(('dir_ap'+"/"+cmd[5:]+'Ĕ').encode())
				if(flag):
					lock.acquire()
					localfilelist.append(["/"+cmd[5:],str(0)])
					lock.release()
					xattr.setxattr(RootDir+"/"+cmd[5:],"user.comment", str(0))
					if(DFSOnline!=0):
						replic_serv = costCreationFunc(9999,SERVER_PORT)
						serverlist[replic_serv].fd.sendall(('rep%'+cmd[5:].replace('/','%')).encode())
				else:
					lock.acquire()
					localfilelist.append(["/"+cmd[5:],str(-1)])
					lock.release()
			else:
				serverlist[serv].fd.sendall((cmd).encode())
				ret_msg ='File Created'
	elif cmd[:5] == 'remv ':
		fil_path = cmd[5:]
		if not(fileExists(fil_path)):
			ret_msg ='File Does Not Exists'
		else:
			ret_msg ='File Deleted'
			if (fileExistsLoc(fil_path)):
				name = fil_path
				if(repExistsLoc(fil_path)):
					fil_path ='%'+fil_path.replace('/','%')
				if('/' not in fil_path):
						fil_path = '/'+fil_path
				if(cmd[-1:]!='/'):
					os.remove(RootDir+fil_path)
				else:
					try:
						os.rmdir(RootDir+"/"+cmd[5:-1])
						ret_msg = "Directory Deleted"
					except OSError:
						ret_msg = "To Delete Non-empty Directories, use rmdr"
				lock.acquire()		
				del localfilelist[locFileLocator(name)]
				lock.release()
				broadcast(('dir_dl'+name+'Ĕ').encode())
				serv = fileLocator(name, SERVER_PORT)
				if(serv!=-1):
					serverlist[serv].fd.sendall((cmd+'Ĕ').encode())
			else:
				serverlist[fileLocator(fil_path, -1)].fd.sendall((cmd).encode())
	elif cmd[:5] == 'rmdr ':
		if not(fileExists(cmd[5:])):
			ret_msg ='Directory Does Not Exists'
		else:
			ret_msg ='Directory Deleted'
			if (fileExistsLoc(cmd[5:])):
				shutil.rmtree((RootDir+"/"+cmd[5:]))
				lock.acquire()
				generateList()
				lock.release()
				broadcast(('dir_up'+repr(localfilelist)).encode())
			else:
				serverlist[fileLocator(cmd[5:], -1)].fd.sendall((cmd).encode())
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
			serv = fileLocator(text[1], -1)
			serverlist[serv].fd.sendall((cmd).encode())
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
				os.execvp('gedit',['gedit', './'+RootDir+'/'+path])
		else:
			serv = fileLocator(path, -1)
			serverlist[serv].fd.sendall(('give'+path).encode())
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
	elif cmd == 'cons':
		ret_msg ='_'*40
		for servers in serverlist:
			if serverlist[servers].fd!=None:
				ret_msg +='\n'+repr(serverlist[servers].fd) + ' ' +str(servers)
		ret_msg +='_'*40
	elif cmd[:5] == 'exis ':
		if (fileExists(cmd[5:])):	
			ret_msg = 'File Present'
		else:
			ret_msg = 'File Absent'
	#elif cmd == 'repl':
	#	for serports in serverlist:
	#		ret_msg += repr(serverlist[serports].replicalist)
	elif ('help'in cmd or 'cmd' in cmd):
		ret_msg ='_'*30 + "\nList Of Possible Commands:\n" + '-'*30+"\npeek View File Directory ..\ncons View Connections ..\nmake [file] ..\nremv [file] ..\nexis [file] ..\nread [file] ..\nwrit [file] ..\nupdt [file] ..\nexit Close Program ..\n"+'-'*30 #\napen [file] [text] ..
	else:
		ret_msg ='Invalid Command. Use help.'
	return ('\n' + ret_msg)


def recServMsg(fd):
	while(True):
		data = fd.recv(MAX_MSG).decode()
		serv = 0
		for server in serverlist:
			if serverlist[server].fd == fd:
				serv = server
				break
		if len(data) >0:
			print('\nMsg Recieved from Server: ', serv,' : ',data, '\n<cmd>: ', end='',flush=True)
			all_data = data.split('Ĕ')
			for data in all_data:
				if(len(data)<1):
					continue
				if data[:6] == 'dir_up':
					serverlist[serv].filelist = ast.literal_eval(data[6:])
				elif data[:6] == 'dir_ap':
					serverlist[serv].filelist.append([data[6:], str(0)])
				elif data[:6] == 'dir_dl':
					for files in serverlist[serv].filelist:
						if data[6:] == files[0]:
							serverlist[serv].filelist.remove(files)
							break
				elif data[:6] == 'ver_up':
					data = data.split(';')
					serverlist[serv].filelist[custFileLocator(serv, data[1])][1] = data[0][6:]
				elif data[:4] == 'rep%':
					file1 = open(RootDir+"/"+data[3:],'w+')
					file1.close()
					fname = data[3:].replace('%','/')
					xattr.setxattr(RootDir+"/"+data[3:],"user.comment", str(0))
					lock.acquire()
					localfilelist.append([fname, str(0)])
					localreplicalist.append(fname)
					lock.release()
					broadcast(('dir_ap'+fname).encode())
				elif data[:4] == 'give':
					try:
						file_content = Path("root/"+data[4:]).read_text()
						fd.sendall(('fil_msg'+';'+file_content+'Āā').encode())
					except Exception as e:
						fd.sendall(e.args[1].encode())
				elif(data[:5] == 'updt '):
					while(data[-2:]!='Āā'):
						data +=fd.recv(MAX_MSG).decode()
					reply = cmdParse(data[:-2])
					fd.sendall(reply.encode())
				elif(data[:6] == 'fil_up'):
					file_data = data.split(';')
					while(file_data[2][-2:]!='Āā'):
						file_data[2] += fd.recv(MAX_MSG).decode()
					fil_path = file_data[0][6:]
					name = RootDir+"/"+fil_path
					if(repExistsLoc(fil_path)):
						name = RootDir+ '/'+fil_path.replace('/','%')
					with open(name,'w') as f:
						f.write(file_data[2][:-2])
					localfilelist[locFileLocator(fil_path)][1] = file_data[1]
					xattr.setxattr(name, 'user.comment', file_data[1])
				elif data[:7] == 'fil_msg':
					file_data = data.split(';')
					while(file_data[1][-2:]!='Āā'):
						file_data[1] += fd.recv(MAX_MSG).decode()
					Q.put(file_data[1][:-2])
					#print(result + '\n<cmd>: ', end='',flush=True)
				elif data[:3] == 'con':
					client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
					client.connect((data[3:], CLIENT_PORT))
					clientlist.append(client)
					#print(clientlist)
					print('\nIncoming Client Connection:', data[3:],'\n<cmd>: ', end='',flush=True)
					threading.Thread(target=recCliMsg, kwargs={'fd':client}).start()
				elif data[:4] == 'apen':
					cmdParse(data)
				elif data[:5] == 'remv ':
					print(cmdParse(data))
				elif data[:5] == 'make ':
					print(cmdParse(data))
		else:
			print('\nTerminating Connection:', serv,fd.getpeername(),'\n<cmd>: ', end='',flush=True) 
			fd.close()
			serverlist[serv].fd = None
			serverlist[serv].filelist = None
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
				data = data[:-2]
			reply = cmdParse(data)
			if(reply[1:4] == 'con'):	
				fd.sendall(reply[:4].encode())
				serverlist[reply[4:]].fd.sendall(('con'+fd.getpeername()[0]).encode())
			else:
				fd.sendall(reply.encode())
		else:
			print('\nTerminating Connection with Client:', fd.getpeername(),'\n<cmd>: ', end='',flush=True) 
			clientlist.remove(fd)
			fd.close()
			break


def multiCast():#listening on multicast group
	global DFSOnline
	server_address = ('', 50000)
	sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	sock.bind(server_address)
	group = socket.inet_aton('224.4.255.255')
	mreq = struct.pack('4sL', group, socket.INADDR_ANY)
	sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
	print('\nwaiting to receive multicast message')
	while True:
		data, address = sock.recvfrom(4)
		if(data.decode() == 'cli'):
			cli = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			try:
				cli.connect((address[0], CLIENT_PORT))
			except:
				continue
			else:
				clientlist.append(cli)
				#print(clientlist)
				print('\nIncoming Client Connection:', address,'\n<cmd>: ', end='',flush=True)
				threading.Thread(target=recCliMsg, kwargs={'fd':cli}).start()
		elif(data.decode() == 'ser'):
			serv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			serv.connect((address[0],SERVER_PORT))
			data = serv.recv(MAX_MSG).decode()
			serverlist[address[0]] = serverContents()
			while(data[-2:]!='Āā'):
					data +=serv.recv(MAX_MSG).decode()
			serverlist[address[0]].fd= serv
			serv.sendall((repr(localfilelist)+'Āā').encode())#+';'+repr(localreplicalist)
			lock.acquire()
			DFSOnline+=1
			serverlist[address[0]].filelist = ast.literal_eval(data[:-2])
			syncFiles(address[0])
			lock.release()
			print('\nIncoming Server Connection:', address,'\n<cmd>: ', end='',flush=True)
			threading.Thread(target=recServMsg, kwargs={'fd':serv}).start()

def sockListen(sockfd):
	global DFSOnline
	sockfd.listen()
	while(True):
		conn, addr = sockfd.accept()
		serverlist[addr[0]] = serverContents()
		serverlist[addr[0]].fd = conn
		print('Connected to Server: ', addr)
		conn.sendall((repr(localfilelist)+'Āā').encode())
		data = conn.recv(MAX_MSG).decode()
		while(data[-2:]!='Āā'):
				data +=conn.recv(MAX_MSG).decode()
		lock.acquire()
		DFSOnline+=1
		serverlist[addr[0]].filelist = ast.literal_eval(data[:-2])
		syncFiles(addr[0])
		lock.release()
		t = threading.Thread(target=recServMsg, kwargs={'fd':conn})
		#t.daemon = True
		t.start()

def main():
	print(locname)
	serverlist[locname]=serverContents()
	serv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	serv.bind(('', SERVER_PORT))
	generateList()
	serverlist[locname].fd=serv
	t = threading.Thread(target=sockListen, kwargs={"sockfd": serv})
	t.daemon = True
	t.start()
	#-----------------------------------------------------------
	sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	sock.settimeout(0.5)
	ttl = struct.pack('b', 1)
	sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, ttl)
	sent = sock.sendto(b'ser', ('224.4.255.255', 50000))
	#----------------------------------------------------------
	mtc = threading.Thread(target = multiCast)
	mtc.daemon = True
	mtc.start()
	while(True):
		cmd=input('<cmd>: ')
		if(cmd=='close' or cmd == 'exit'):
			sys.exit()
		print(cmdParse(cmd))


if __name__ == "__main__":
	main()
	
	

