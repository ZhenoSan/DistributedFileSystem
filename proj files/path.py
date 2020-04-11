import os

strt = 'folder1/folder2/file3'
strt = 'folder1'
newl = strt.split('/')

print(newl)
'''
def list_files(startpath):
    for root, dirs, files in os.walk(startpath):
        level = root.replace(startpath, '').count(os.sep)
        #print(level)
        indent = ' ' * 4 * (level)
        print('{}{}/'.format(indent, os.path.basename(root)))
        subindent = ' ' * 4 * (level + 1)
        for f in files:
            print('{}{}'.format(subindent, f))


def list_file():
	x=0
	localfilelist={}
	for x in range(9):
		localfilelist[x]=[]
	print(localfilelist)
	for root, dirs, files in os.walk('root'):
		level = root.replace('root', '').count(os.sep)
		localfilelist[level].append(os.path.basename(root))
		for f in files:
			localfilelist[level+1].append(f)
	print(repr(localfilelist))

list_files(input('\nPath: '))
list_file()


path = 'root'
indentation=2
tree = []
for root, dirs, files in os.walk(path):
    level = root.replace(path, '').count(os.sep)
    indent = ' '*indentation*(level)
    tree.append(str(level)+os.path.basename(root))
    #tree.append('{}{}/'.format(indent,os.path.basename(root)))    
    for f in files:
        subindent=' ' * indentation * (level+1)
        tree.append(str(level+1)+f)
        #tree.append('{}{}'.format(subindent,f))
            
for line in tree:
	print(line)
	
touch folder1/folder2/file3


0root
	1file1
	1folder1
		2file2
		2folder2
			3file3

0 folder1
1 folder2
3 file3

def fileExists(name):
	T = globalListGenerator()
	T.append(localfilelist)
	level = 1
	names_split = name.split('/')
		for filelist in (T):#izip_longest
			for ind in range(len(names_split))
				for fil in filelist:
					if names[ind] in fil[1:] and fil[:1]==level:
						if ind == len(names_split)-1:
							return True
						else:
							ind+=1
							level+=1
							continue
	return False	
'''
