# Peek-achu DFS README.txt file

## How To Run:
open Terminal and type 'python3 dfs-serv.py' to run server program
open Terminal and type 'python3 dfs-cli.py' to run client program

## Help
### Client Side Commands:
1.	peek			View Directory Listing
2.	read	[filename]	Read a File’s contents
3.	writ	[filename]	Edit a File in Text Editor
4.	remv	[file / folder]	Remove a file or a folder
5.	rmdir 	[Directory]	Remove a non-empty folder
6.	updt    [filename]	Manually update a file
7.	make    [file / folder]	Make a file or folder
8.	exit			Close Program
9.	cmds			Display all available commands

### Dependencies
•	The current system only supports a UNIX environment.

•	Before running the program, it is necessary to ensure that the xattr library for python3 has been installed. This library allows for editing extended attributes of a file.

•	The network that the system is running on must allow for multicast of messages.

•	A folder called ‘root’ must be present at the location of the server program file.
