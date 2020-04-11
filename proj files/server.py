import os, socket

PATH = "filesystem/" 
HOST = '127.0.0.1'  # Standard loopback interface address (localhost)
PORT = 65432		# Port to listen on (non-privileged ports are > 1023)

def parseCommand (cmd):
	if cmd == "ls":
		return '  '.join(os.listdir(PATH))
	
	return "Unrecognized Command"

def main():
	with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
		s.bind((HOST, PORT))
		s.listen()
		conn, addr = s.accept()
		with conn:
			print('Connected by', addr)
			while True:
				data = conn.recv(1024)
				print(data)
				if data.decode() == "exit":
					s.close()
					break
				
				conn.sendall( parseCommand(data.decode()).encode() )
	
if __name__ == "__main__":
	main()
