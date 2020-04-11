import os,socket,threading,sys,ast
from pathlib import Path
#import pickle

MAX_MSG = 1024
START_PORT = 7777
MAX_SERVS = 3


localfilelist = []

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
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
	
def cmdParse(cmd, fd):
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
	elif cmd[0:4] == 'exis':
		if (fileExists(cmd[5:])):	
			ret_msg = 'File Present'
		else:
			ret_msg = 'File Absent'
	elif cmd == 'cons':
		ret_msg +='_'*40
		for servers in serverlist:
			if serverlist[servers].fd!=None:
				ret_msg +='\n'+repr(serverlist[servers].fd) + ' ' +str(servers)
		ret_msg +='_'*40
	elif cmd[0:5] == 'touch':
		if (not fileExists(cmd[6:])):
			file1 = open("root/"+cmd[6:],'w+')
			generateList()
			file1.close()
			broadcast(('dir_up'+repr(localfilelist)).encode())
			ret_msg +='File Created'
		else:
			ret_msg='File Already Exists'
	elif cmd[0:3] == 'del':
		if (fileExists(cmd[4:])):
			ret_msg +='File Deleted'
			if (fileExistsLoc(cmd[4:])):
				os.remove("root/"+cmd[4:])
				generateList()
				broadcast(('dir_up'+repr(localfilelist)).encode())
				return ret_msg
			serverlist[fileLocator(cmd[4:])].fd.sendall((cmd).encode())
		else:
			ret_msg ='File Does Not Exists'
	elif cmd[0:4] == 'read':
		exe_str = cmd[-(len(cmd[5:])-(cmd[5:].rfind('.'))):]
		extensions = ['.txt','.c','.py']
		if not(any(x in exe_str for x in extensions)):
			ret_msg +='File not readable'
		else:
			if not(fileExists(cmd[5:])):
				ret_msg +='File Does Not Exists'
			else:
				if (fileExistsLoc(cmd[5:])):
					ret_msg +=('\n'+'_'*40+'\n' +Path("root/"+cmd[5:]).read_text()+'\n'+'_'*40)
					return ret_msg
				if(fd!=-1):
					print('SENT TO SERV')
					serverlist[fileLocator(cmd[5:])].fd.sendall(('give'+'fd'+str(fd)+cmd[5:]).encode())
				else:
					serverlist[fileLocator(cmd[5:])].fd.sendall(('give'+cmd[5:]).encode())
				#for ports in serverlist:#izip_longest
					#if serverlist[ports].filelist !=None  and cmd[5:] in str(serverlist[ports].filelist):
						#serverlist[ports].fd.sendall(('give'+cmd[5:]).encode())
						#break
	elif ('help'in cmd or 'cmd' in cmd):
		ret_msg +='_'*30 + "\nList Of Possible Commands:\n" + '-'*30+"\ndir ..\ncons ..\ntouch [file_name] ..\ndel [file_name] ..\nexis [file_name] ..\nread [file_name] ..\nclose Close Program ..\n"+'-'*30
	else:
		ret_msg +='Invalid Command. Use help.'
	return ret_msg


def recServMsg(fd):
	while(True):
		data = fd.recv(MAX_MSG).decode()
		port = 0
		for ports in serverlist:
			if serverlist[ports].fd == fd:
				port = ports
				break
		if len(data) >0:
			if data[0:6] == 'dir_up':
				serverlist[port].filelist = ast.literal_eval(data[6:])
			elif data[0:4] == 'give':
				if(data[4:6]=='fd'):
					file_content = Path("root/"+data[7:]).read_text()
					fd.sendall(('fil_msg'+'fd'+data[6:7]+str(len(file_content))+';'+file_content).encode())	
				else:
					file_content = Path("root/"+data[4:]).read_text()
					fd.sendall(('fil_msg'+str(len(file_content))+';'+file_content).encode())
			elif data[0:3] == 'del':
				print('Rcvd Del')
				print(cmdParse(data), -1)
			elif data[0:7] == 'fil_msg':
				if(data[7:9]=='fd'):
					st_ind = 10
				else:
					st_ind = 7
				file_data = data.split(';')
				file_size = int(file_data[0][st_ind:])
				data = None
				file_temp_data_size = MAX_MSG-st_ind-file_size
				if file_size > file_temp_data_size:
					data = fd.recv(file_size-file_temp_data_size).decode()
				result = '\n'+'_'*40 + '\n'
				if(data !=None):
					result+=file_data[1]+data + '_'*40	
				else:
					result+=file_data[1] + '_'*40
				if st_ind==7:
					print(result + '\n<cmd>: ', end='',flush=True)
				else:
					print(result)
					clientlist[int(file_data[0][9:10])].sendall(result.encode()) 
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
		data = fd.recv(MAX_MSG).decode()
		if len(data) >0:
			print('Msg Recieved from Client: '+repr(fd.getpeername())+' : '+data,'\n<cmd>: ', end='',flush=True)
			fd.sendall(cmdParse(data,clientlist.index(fd)).encode())
		else:
			print('\nTerminating Connection with Client:', fd.getpeername(),'\n<cmd>: ', end='',flush=True) 
			clientlist.remove(fd)
			#del clientlistclientlist.indexof(fd)
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
			print(clientlist)
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
		if(cmd=='close'):
			sys.exit()
		print(cmdParse(cmd,-1))

		
if __name__ == "__main__":
	main()
	
	

