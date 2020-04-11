import socket, threading, os
from pathlib import Path

START_PORT = 7777
MAX_MSG = 4096
 
def recCliMsg(fd):
	while True:
		data = fd.recv(MAX_MSG).decode()
		if(len(data)>0):
			if(data[1:4]=='wr%'):#1 cause cmdParse sends \n
				tpath=data[3:data.find(';')]
				while(data[-2:]!='&%'):
					data +=fd.recv(MAX_MSG).decode()
				try:
					with open(tpath, 'x') as f:
						f.write(data[data.find(';')+1:-2])
					print('File Opened'+'\n<cmd>: ', end='',flush=True)
					if(os.fork()==0):
						os.execvp('gedit',['gedit', tpath])
				except:
					print('Update File First'+'\n<cmd>: ', end='',flush=True)
					continue
			else:
				print(data,'\n<cmd>: ', end='',flush=True) 
		else:
			print('Connection Closed.')
			break


def main():
	with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as cli:
		cli.connect(('127.0.0.1', START_PORT-int(input('no:'))))
		t = threading.Thread(target=recCliMsg, kwargs={'fd':cli})
		t.daemon = True
		t.start()
		while True:
			cmd = input('<cmd>: ')
			if cmd == "close" or cmd == 'exit':
				break
			elif cmd[:5] == 'updt ':
				fil_path =cmd[5:]
				exp=False
				try:
					content = Path(fil_path).read_text()
					os.remove(fil_path)
				except Exception as e:
					exp = True 
					print(e)
				if(exp==True):
					continue
				cli.sendall((cmd+';'+content+'&%').encode())
			else:
				cli.sendall(cmd.encode())
			
	    
if __name__ == "__main__":
	main()

