import os

fileDirectoryRoot = 'root'
localfilelist=[]
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
			localfilelist.append(prefx+'/'+f)
		for d in dirs:
			localfilelist.append(prefx+'/'+d+'/')
	for items in localfilelist:
		print(items)
	
generateList()
