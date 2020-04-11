import xattr

file1 = input("File Name: ")
print(xattr.get(file1, "user.comment"))
xattr.set(file1,"user.comment", str(2))
print(xattr.get(file1, "user.comment"))

#https://en.wikipedia.org/wiki/Clustered_file_system

xattr.set(fileDirectoryRoot+"/"+cmd[5:],"user.comment", str(0))
