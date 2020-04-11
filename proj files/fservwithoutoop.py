import os,socket,threading,sys
#import pickle

MAX_MSG = 1024
START_PORT = 7777
MAX_SERVS = 3


localfilelist = []
localdirlist = []

globalfilelist = {}
globaldirlist = []

serverports={}

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

class serverContents:
	def __init__(self, port, fd, filelist):
	self.port = port
	self.fd = fd
	self.filelist = filelist


def fileExists(name):
	for fil in localfilelist+list(globalfilelist.items()):#izip_longest
		if name in fil:
			return True
	return False


def cmdParse(cmd):
	#filelist = os.listdir("root")
	if cmd == 'dir':
		print(localdirlist)
		print(localfilelist+list(globalfilelist.items()))
	elif cmd[0:4] == 'exis':
		if (fileExists(cmd[5:])):	
			print('File Present')
		else:
			print('File Absent')
	elif cmd == 'cons':
		print(repr(serverports))
	elif cmd[0:5] == 'touch':
		if (not fileExists(cmd[6:])):
			file1 = open("root/"+cmd[6:],'w+')
			localfilelist[0].append(cmd[6:])
			file1.close()
			for port in serverports:
				try:
					serverports[port].sendall(repr(localfilelist).encode())
				except:
					continue
			print('File Created')
		else:
			print('File Already Exists')
	elif cmd[0:3] == 'del':
		if (fileExists(cmd[4:])):
			os.remove("root/"+cmd[4:])
			localfilelist[0].remove(cmd[4:])
			for port in serverports:
				try:
					serverports[port].sendall(repr(localfilelist).encode())
				except:
					continue
			print('File Deleted')
		else:
			print('File Does Not Exists')
	elif cmd == 'help':
		print('_'*30 + "\nList Of Possible Commands:\n" + '-'*30+"\ndir ..\ncons ..\ntouch [file_name] ..\ndel [file_name] ..\nexis [file_name] ..\nclose Close Program ..\n"+'-'*30)
	else:
		print('Invalid Command. Use help.')
	return


def recServMsg(fd):
	while(True):
		data = fd.recv(MAX_MSG).decode()
		if len(data) >0:
			print('\nMsg: ',data)
		else:
			print('\nTerminating Connection:', list(serverports.keys())[list(serverports.values()).index(fd)],fd.getpeername(),'\nEnter Cmd: ', end='',flush=True) 
			fd.close()
			break


def sockListen(serv):
	#print('Thread SockBind')
	serv.listen()
	while(True):
		#print('Conn Accept Loop')
		conn, addr = serv.accept()
		server_port=int(conn.recv(MAX_MSG).decode());	
		serverports[server_port]= conn
		if len(localfilelist)>0:
			conn.sendall(repr(localfilelist).encode())
		globalfilelist[server_port].append(conn.recv(MAX_MSG).decode())
		print('\nIncoming Connection:', server_port, addr,'\nEnter Cmd: ', end='',flush=True)
		threading.Thread(target=recServMsg, kwargs={'fd':conn}).start()


def sockTalk(fd):
	#print('Thread Socktalk')
	fd.sendall('dir'.encode())
	print('Msg Sent')
	return
	

def main():
	for x in range(MAX_SERVS):
		serverports[START_PORT+x]=None
		globalfilelist[START_PORT+x]=None
	print('Available ports: ',list(serverports.keys()))
	for root, dirs, files in os.walk('root'):
		localfilelist.append(files)
		if(len(dirs)>0): 
			localdirlist.append(dirs)
	serv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	inc=0
	while True:
		try:
			#arg = int(input('Select Server Port: '))
			arg = START_PORT+inc
			if arg not in serverports.keys():
				raise ValueError
			serv.bind(('127.0.0.1', arg))
			break
		except ValueError:
			print('Error: Incorrect Port Number')
		except OSError:
			print('Port Already In Use')
		finally:
			inc+=1
	serverports[arg]=serv
	t = threading.Thread(target=sockListen, kwargs={"serv": serv})
	t.daemon = True
	t.start()
	onlineServs = []
	offlineServers=[]
	i=0
	for servers in serverports:
			if servers == int(arg):
				continue
			onlineServs.append(socket.socket(socket.AF_INET, socket.SOCK_STREAM))
			try:
				onlineServs[i].connect(('127.0.0.1', servers))
				serverports[servers] = onlineServs[i]
				print('Connected to Server: ', servers)
				onlineServs[i].sendall(str(arg).encode())
				globalfilelist[servers].append(onlineServs[i].recv(MAX_MSG).decode())
				if len(localfilelist)>0:
					onlineServs[i].sendall(repr(localfilelist).encode())
				t = threading.Thread(target=recServMsg, kwargs={'fd':onlineServs[i]})
				t.daemon = True
				t.start()
			except ConnectionRefusedError:
				offlineServers.append(servers)
			i+=1
	print('Offline Servers: ', offlineServers)
	while(True):
		cmd=input('Enter Cmd: ')
		if(cmd=='close'):
			sys.exit()
		cmdParse(cmd)

		
if __name__ == "__main__":
	main()
	
	

