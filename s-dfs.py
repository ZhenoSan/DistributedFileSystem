import os,socket,threading,sys,ast, queue, shutil, struct, time, xattr
from pathlib import Path
lock = threading.Lock()
Q = queue.Queue()

'''
fix updt writ read

Assumption: Always send file path with / on network
Stored with / on list
rep stored with / as starting in list
rep saved with starting % on disk

line 559
To do:

3) Deleting Replicated Files

6) Making directory and file
7) Removing from list
8) Del Files Check
9) replicate Dirs
10) total files on server

11) file del while other updating
semantics

on filecreate:
	if file in del_file / list
		set file version to del_file version
		remove file name from del_file / list
#	if no rep made:
#		add to no_rep file / list
#
#on fileDel:
#	if file in no_rep list / file:
#		remove file name from no_rep file
#	else:
#		if rep online:
#			send del to rep
#		else
#			add file and verison to del_file / list
#	del file 
			
#on ServHandshake:
#	if file in del_file:
#		del file
#		remove from del_file / list
		
#on main:
#	read no_rep on to list
#	read del_file on to list
'''

MAX_MSG = 1024
MAX_SERVS = 3
SERVER_PORT = 10000
CLIENT_PORT = 9999
DFSOnline = 0
RootDir = 'root'
#locname = str(socket.getfqdn())
locname = str(socket.gethostbyname(socket.gethostname()))

localfilelist = []
localreplicalist = []
noreplist=[]
dellist=[]
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
		self.tot = 0


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
			serverlist[locname].tot +=1
			try:
				att = (xattr.getxattr(RootDir+prefx+'/'+f,b'user.comment')).decode()
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
	
	for files in localreplicalist:
		for x in range(files.count('/')-1):
			#print(files[:files.rfind('/')+1])
			#print(files.count('/'))
			for ind, fil in enumerate(localfilelist):
				#print(ind)
				if files[:files.rfind('/')+1] == fil:
					#print('found match')
					break
				if(ind ==len(localfilelist)-1):
					#print('adding')
					#print(files[:files.rfind('/')+1])
					localfilelist.append([files[:files.rfind('/')+1],-1])
					break
			files =files[:files.rfind('/')]
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
	for files in localreplicalist:
		if name == files:
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
			if  (serverlist[server].tot) < cost:
				cost = serverlist[server].tot
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
	elif cmd == 'refr':
		generateList()
		print('List Refreshed')
		ret_msg ='Invalid Command. Use help.'
	elif cmd == 'ldir':
		for files in localfilelist:
			print(files)
		ret_msg ='Invalid Command. Use help.'
	elif cmd[:5] == 'read ':
		fil_path = cmd[5:]
		exe_str = cmd[-(len(fil_path)-(fil_path.rfind('.'))):]
		extensions = ['.txt','.c','.py']
		if not(any(x in exe_str for x in extensions)):
			ret_msg ='File not readable'
		elif not(fileExists(fil_path)):
			ret_msg ='File Does Not Exists'
		elif (fileExistsLoc(fil_path)):
			if(repExistsLoc(fil_path)):
				fil_path =fil_path.replace('/','%')
				if('%' not in fil_path[:1]):
					fil_path='%'+fil_path
			try:
				ret_msg =('_'*40+'\n' +Path(RootDir+'/'+fil_path).read_text()+'_'*40)
			except Exception as e:
				ret_msg = str(e)
		else:
			servid = fileLocator(fil_path, -1)
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
				ret_msg+= (Path(RootDir+'/'+fil_path).read_text() +'Āā')
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
				name =fil_path.replace('/','%')
				if('%' not in name[:1]):
					name = RootDir+'/%'+name
			#try:
			with open(name,'w') as f:
				f.write(cmd[cmd.find(';')+1:])
				ret_msg = 'Written To File'
			att =int( localfilelist[locFileLocator(fil_path)][1])+1
			localfilelist[locFileLocator(fil_path)][1] = str(att)
			xattr.setxattr(name, b'user.comment', str(att).encode())
			serv = fileLocator(fil_path, locname)
			if(serv!=-1):
				if(int(serverlist[serv].filelist[custFileLocator(serv, fil_path)][1]) < att):
					serverlist[serv].fd.sendall(('ver_up'+str(att)+';/'+fil_path+'Ĕ'+cmd+'Āā'+'Ĕ').encode())
			broadcast(('ver_up'+str(att)+';/'+fil_path+'Ĕ').encode())
			#except Exception as e:
			#	ret_msg = str(e)		
		else:
			serverlist[fileLocator(fil_path,-1)].fd.sendall((cmd+'Āā').encode())
			ret_msg = 'Written To File'
	elif cmd[:5] == 'make ':
		fil_path = cmd[5:]
		if(fil_path[:1]!='/'):
			fil_path = '/'+fil_path
		if (fileExists(fil_path)):
			ret_msg='File Already Exists'
		else:
			cost = len(localfilelist)
			serv = locname
			pos_sl = fil_path[1:].rfind('/')+1
			if(pos_sl!=-1):
				if (fileExistsLoc(fil_path[:pos_sl])):
					cost=0
				elif fileExists(fil_path[:pos_sl]):
					cost=0
					serv = fileLocator(fil_path[:pos_sl],-1)
			if cost !=0:
				serv = costCreationFunc(cost,0)
			if(serv==locname):
				flag = True
				ret_msg ='File Created'
				try:
					file1 = open(RootDir+fil_path,'w+')
					file1.close()
				except IsADirectoryError:
					os.makedirs(RootDir+fil_path[:pos_sl])
					flag = False
					ret_msg = 'Directory Created'
				except FileNotFoundError:
					os.makedirs(RootDir+fil_path[:pos_sl])
					file1 = open(RootDir+fil_path,'w+')
					file1.close()
				if(flag):
					att = str(0)
					for files in dellist:
						if files[:files.rfind('~')] == fil_path:
							att = files[files.rfind('~'):]
							print(att)
							dellist.remove(files)
							break
					delstr = ""
					for items in dellist:
						delstr += items+'\n'
					with open('dellist.txt','w') as f:
						f.write(delstr)
					lock.acquire()
					serverlist[locname].tot +=1
					localfilelist.append([fil_path,att])
					lock.release()
					xattr.setxattr(RootDir+fil_path,b"user.comment", att.encode())
					if(DFSOnline!=0):
						replic_serv = costCreationFunc(9999,locname)
						serverlist[replic_serv].fd.sendall(('rep%'+fil_path+';'+att+'Ĕ').encode())
					#else:
					#	noreplist.append(fil_path)
					#	with open('noreplist.txt', 'a+') as f:
					#		f.write(fil_path+'\n')
				else:
					lock.acquire()
					localfilelist.append([fil_path,str(-1)])
					lock.release()
				broadcast(('dir_ap'+fil_path+'Ĕ').encode())
			else:
				serverlist[serv].fd.sendall((cmd).encode())
				ret_msg ='File Created'
	elif cmd[:5] == 'remv ':
		fil_path = cmd[5:]
		if(fil_path[:1]!='/'):
			fil_path = '/'+fil_path
		if not(fileExists(fil_path)):
			ret_msg ='File Does Not Exists'
		else:
			ret_msg ='File Deleted'
			'''print(localfilelist)
			print('REM SERVER')
			serv = fileLocator(fil_path, locname)
			if(serv!=-1):
				print(serverlist[serv].filelist)'''
			if (fileExistsLoc(fil_path)):
				name = fil_path
				norep = False
				serv = fileLocator(name, locname)
				if(repExistsLoc(fil_path)):
					lock.acquire()
					localreplicalist.remove(fil_path)
					lock.release()
					name = '/'+fil_path.replace('/','%')
				if(cmd[-1:]!='/'):#If requested delete is not on dir
					if(serv==-1):
						#for files in noreplist:
						#	if files == fil_path:
						#		norep = True
						#		noreplist.remove(files)
						#		norepstr = ""
						#		for items in noreplist:
						#			norepstr += items+'\n'
						#		with open('noreplist.txt','w') as f:
						#			f.write(norepstr)
						#		break
						if(not norep):
							try:
								xatt = (xattr.getxattr(RootDir+fil_path, b'user.comment')).decode()
							except OSError:
								xatt = 0
							text = fil_path+'~'+str(xatt)+'\n'
							dellist.append(text)
							with open('dellist.txt', 'a+') as f:
								f.write(text)
					os.remove(RootDir+name)
					serverlist[locname].tot -=1
				else:
					try:
						os.rmdir(RootDir+fil_path)
						ret_msg = "Directory Deleted"
					except OSError:
						ret_msg = "To Delete Non-empty Directories, use rmdr"
				lock.acquire()		
				del localfilelist[locFileLocator(fil_path)]
				lock.release()
				if(serv!=-1):
					serverlist[serv].fd.sendall((cmd+'Ĕ').encode())
				broadcast(('dir_dl'+fil_path+'Ĕ').encode())
			else:
				serverlist[fileLocator(fil_path, -1)].fd.sendall((cmd).encode())
	elif cmd[:5] == 'rmdr ':
		fil_path = cmd[5:]
		if(fil_path[:1]!='/'):
			fil_path = '/'+fil_path
		if not(fileExists(fil_path)):
			ret_msg ='Directory Does Not Exists'
		else:
			ret_msg ='Directory Deleted'
			if (fileExistsLoc(fil_path)):
				shutil.rmtree((RootDir+fil_path))
				lock.acquire()
				generateList()
				lock.release()
				broadcast(('dir_up'+repr(localfilelist)).encode())
			else:
				serverlist[fileLocator(cmd[5:], -1)].fd.sendall((cmd).encode())
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
		ret_msg ='_'*30 + "\nList Of Possible Commands:\n" + '-'*30+"\npeek View File Directory ..\nmake [file] ..\nremv [file] ..\nexis [file] ..\nread [file] ..\nwrit [file] ..\nupdt [file] ..\nexit Close Program ..\n"+'-'*30 #\napen [file] [text] ..\ncons View Connections ..
	else:
		ret_msg ='Invalid Command. Use help.'
	return ('\n' + ret_msg)

	'''	elif cmd[:5] == 'apen ':
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
				os.execvp('gedit',['gedit', tpath])'''

def recServMsg(fd):
	while(True):
		try:
			data = fd.recv(MAX_MSG).decode()
		except ConnectionResetError:
			data = ''
		else:
			serv = 0
			for server in serverlist:
				if serverlist[server].fd == fd:
					serv = server
					break
		if len(data) >0:
			print('\nMsg Recieved (Server): ', serv,' : ',data, '\n<cmd>: ', end='',flush=True)
			all_data = data.split('Ĕ')
			for data in all_data:
				if(len(data)<1):
					continue
				if data[:6] == 'dir_up':
					lock.acquire()
					serverlist[serv].filelist = ast.literal_eval(data[6:])
					lock.release()
				elif data[:6] == 'dir_ap':
					lock.acquire()
					serverlist[serv].filelist.append([data[6:], str(0)])
					serverlist[serv].tot +=1
					lock.release()
				elif data[:6] == 'dir_dl':
					for files in serverlist[serv].filelist:
						if data[6:] == files[0]:
							lock.acquire()
							serverlist[serv].filelist.remove(files)
							serverlist[serv].tot -=1
							lock.release()
							break
				elif data[:6] == 'dls_up':
					fname = data[6:]
					dellist.remove(fname)
					delstr = ""
					for items in dellist:
						delstr += items+'\n'
					with open('dellist.txt', 'w') as f:
						f.write(delstr)
				elif data[:6] == 'ver_up':
					data = data.split(';')
					serverlist[serv].filelist[custFileLocator(serv, data[1])][1] = data[0][6:]
				elif data[:4] == 'rep%':
					data = data.split(';')
					fil_path = data[0][4:]
					fname = '/'+data[0][4:].replace('/','%')
					file1 = open(RootDir+fname,'w+')
					file1.close()
					xattr.setxattr(RootDir+fname,b"user.comment", (data[1]).encode())
					lock.acquire()
					serverlist[locname].tot +=1
					localfilelist.append([fil_path, data[1]])
					localreplicalist.append(fil_path)
					lock.release()
					broadcast(('dir_ap'+fil_path).encode())
				elif data[:4] == 'give':
					try:
						file_content = Path(RootDir+ data[4:]).read_text()
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
					name = '/'+fil_path
					if(repExistsLoc(fil_path)):
						name = '/'+fil_path.replace('/','%')
						fil_path = fil_path[1:]
					#print(name)
					with open(RootDir+ name,'w') as f:
						f.write(file_data[2][:-2])
					lock.acquire()
					localfilelist[locFileLocator(fil_path)][1] = file_data[1]
					lock.release()
					xattr.setxattr(RootDir + name, b'user.comment', file_data[1].encode())
				elif data[:7] == 'fil_msg':
					file_data = data.split(';')
					while(file_data[1][-2:]!='Āā'):
						file_data[1] += fd.recv(MAX_MSG).decode()
					Q.put(file_data[1][:-2])
					#print(result + '\n<cmd>: ', end='',flush=True)
				elif data[:3] == 'con':
					client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
					count=0
					while(count<3):
						try:
							client.connect((data[3:], CLIENT_PORT))
						except:
							count+=1
							time.sleep(1)
						else:
							break
					clientlist.append(client)
					#print(clientlist)
					print('\nConnecting To Client:', data[3:],'\n<cmd>: ', end='',flush=True)
					threading.Thread(target=recCliMsg, kwargs={'cfd':client}).start()
				elif data[:4] == 'apen':
					cmdParse(data)
				elif data[:5] == 'remv ':
					print(cmdParse(data))
				elif data[:5] == 'make ':
					print(cmdParse(data))
		else:
			print('\nTerminating Connection (Server):', serv,'\n<cmd>: ', end='',flush=True) 
			fd.close()
			lock.acquire()
			serverlist[serv].fd = None
			serverlist[serv].filelist = None
			lock.release()
			global DFSOnline
			DFSOnline-=1
			break


def recCliMsg(cfd):
	while(True):
		try:
			data = (cfd.recv(MAX_MSG)).decode()
		except ConnectionResetError:
			data = ''
		if len(data) >0:
			print('\nMsg Recieved (Client): ', repr(cfd.getpeername()),' : ',data, '\n<cmd>: ', end='',flush=True)
			if(data[:5] == 'updt '):
				while(data[-2:]!='Āā'):
					data +=cfd.recv(MAX_MSG).decode()
				data = data[:-2]
			reply = cmdParse(data)
			if(reply[1:4] == 'con'):	
				cfd.sendall(reply[:4].encode())
				serverlist[reply[4:]].fd.sendall(('con'+cfd.getpeername()[0]).encode())
				print('\nReDirecting Connection (Client):', cfd.getpeername(),'\n<cmd>: ', end='',flush=True) 
				clientlist.remove(cfd)
				cfd.close()
				return
			else:
				cfd.sendall(reply.encode())
		else:
			print('\nTerminating Connection (Client):', cfd.getpeername(),'\n<cmd>: ', end='',flush=True) 
			clientlist.remove(cfd)
			cfd.close()
			return


def multiCast():#listening on multicast group
	global DFSOnline
	server_address = ('', 50000)
	sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	sock.bind(server_address)
	group = socket.inet_aton('224.4.255.255')
	mreq = struct.pack('4sL', group, socket.INADDR_ANY)
	sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
	print('\nwaiting for multicast message','\n<cmd>: ', end='',flush=True)
	while True:
		data, address = sock.recvfrom(4)
		if(data.decode() == 'cli'):
			cli = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			err = cli.connect_ex((address[0], CLIENT_PORT))
			if(err==0):
				clientlist.append(cli)
				#print(clientlist)
				print('\nIncoming Client Connection:', address[0],'\n<cmd>: ', end='',flush=True)
				threading.Thread(target=recCliMsg, kwargs={'cfd':cli}).start()
		elif(data.decode() == 'ser'):
			serv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			serv.connect((address[0],SERVER_PORT))
			data = serv.recv(MAX_MSG).decode()
			serverlist[address[0]] = serverContents()
			while(data[-2:]!='Āā'):
					data +=serv.recv(MAX_MSG).decode()
			data = data.split(';')
			serverlist[address[0]].fd= serv
			serv.sendall((repr(localfilelist)+';'+str(serverlist[locname].tot)+';'+repr(dellist)+'Āā').encode())
			lock.acquire()
			DFSOnline+=1
			serverlist[address[0]].filelist = ast.literal_eval(data[0])
			serverlist[address[0]].tot = int(data[1])#[:-2])
			remotedellist = ast.literal_eval(data[2][:-2])
			for files in localfilelist:
				for dfiles in remotedellist:
					if dfiles[:dfiles.rfind('~')] == files[0]:
						fil_path = files[0]
						if(repExistsLoc(files[0])):
							fil_path = fil_path.replace('/','%')
							localreplicalist.remove(files[0])
						localfilelist.remove(files)
						os.remove(RootDir+'/'+fil_path)
						serv.sendall(('dls_up'+dfiles+'Ĕ'+'dir_dl'+dfiles+'Ĕ').encode())
						break
			syncFiles(address[0])
			lock.release()
			print('\nIncoming Server Connection:', address[0],'\n<cmd>: ', end='',flush=True)
			threading.Thread(target=recServMsg, kwargs={'fd':serv}).start()

def sockListen(sockfd):
	global DFSOnline
	sockfd.listen()
	while(True):
		conn, addr = sockfd.accept()
		serverlist[addr[0]] = serverContents()
		serverlist[addr[0]].fd = conn
		print('Connected to Server: ', addr,'\n<cmd>: ', end='',flush=True)
		conn.sendall((repr(localfilelist)+';'+str(serverlist[locname].tot)+';'+repr(dellist)+'Āā').encode())
		data = conn.recv(MAX_MSG).decode()
		while(data[-2:]!='Āā'):
				data +=conn.recv(MAX_MSG).decode()
		data = data.split(';')
		lock.acquire()
		DFSOnline+=1
		serverlist[addr[0]].filelist = ast.literal_eval(data[0])
		serverlist[addr[0]].tot = int(data[1])#[:-2])
		remotedellist = ast.literal_eval(data[2][:-2])
		for files in localfilelist:
			for dfiles in remotedellist:
				if dfiles[:dfiles.rfind('~')] == files[0]:
					fil_path = files[0]
					if(repExistsLoc(files[0])):
						fil_path = fil_path.replace('/','%')
						localreplicalist.remove(files[0])
					localfilelist.remove(files)
					os.remove(RootDir+'/'+fil_path)
					serv.sendall(('dls_up'+dfiles+'Ĕ'+'dir_dl'+dfiles+'Ĕ').encode())
					break
		syncFiles(addr[0])
		lock.release()
		t = threading.Thread(target=recServMsg, kwargs={'fd':conn})
		#t.daemon = True
		t.start()

def main():
	serverlist[locname]=serverContents()
	serv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	serv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	serv.bind(('', SERVER_PORT))
	generateList()
	global noreplist, dellist
	#Add Auto Create Del Rep List
	try:
		with open('dellist.txt','r') as f:
			dellist = f.read().splitlines()
	except:
		f= open('dellist.txt','w+') 
		f.close()
		dellist = []
	#try:
	#	with open('noreplist.txt','r') as f:
	#		noreplist = f.read().splitlines()
	#except:
	#	noreplist = None
	serverlist[locname].fd=serv
	t = threading.Thread(target=sockListen, kwargs={"sockfd": serv})
	t.daemon = True
	t.start()
	#-----------------------------------------------------------s
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
			serv.shutdown(socket.SHUT_RDWR)
			serv.close()
			sys.exit()
		print(cmdParse(cmd))


if __name__ == "__main__":
	main()
	
	

