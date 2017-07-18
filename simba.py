#Title: Python Binary Reconnaissance Tool
#Revision: 1
#Authors: Elijah Sheets & Eric Zhang
#Project Start:7/17/2017
#Last Edit:7/19/2017
#Goal: Through collaboration with a fellow SEAP intern build a Binary Reconnaissance Tool to run specific scans and or analysis.

#imports
import os
import sys
import angr
import r2pipe
import binwalk
import socket

#A function to run Binwalk Signature and Entropy Scan.
def binwalkSigEntropyScan(file):
	
	for module in binwalk.scan(file, 
				   signature=True,  
				   quiet=True):
		print "%s Binwalk Signature Scan:" % module.name
		for result in module.results:
			print "\t%s    0x%.8x    %s" % (result.file.name, 
							result.offset,
							result.description)
	print "\nBinwalk Entropy Scan:"
	binwalk.scan(file, entropy=True)

	print "\n"



#A function to run a Netcat Service Heartbeat.
def netcatHeartBeat():

	ip = raw_input('Input an IP to run a Netcat Service Heartbeat.\n')
	try:
		socket.inet_aton(ip)
	except: socket.error

	port = raw_input('Input a Port on the IP.\n')
	while(not(port.isdigit())):
		port = raw_input('Input a Port on the IP.\n')


	cmd = 'while `nc -nn -vv -z -w3 '  + ip + ' ' + port + ' > /dev/null`; do echo "OK"; sleep 1; done; echo "DOWN"; while (true); do echo "***DOWN***"; sleep 5; done'

	os.system(cmd)
	

#A function to run angr analysis.
def fullAngrScan(file):
	print('\nLoading the Binary...')
	#Using angr to attempt to load the Binary File.
	proj = angr.Project(file, load_options = {'auto_load_libs':False})
	#Running a Control Flow Graph Analysis on the Binary.
	cfg = proj.analyses.CFG()
	print('\nBinary Architecture:') 
	#Print out the Binary Architecture.
	print(proj.arch)
	print('\nFunction List\n')
	#Loop to print out all the function lists on separate lines.
	count = len(cfg.functions.items())
	i = 0
	for i in cfg.functions.items():
		print i	
	print('\nStack Protection:')
	#Show the binary Stack Protection state.
	print(proj.loader.aslr)
	print('\n')

#A function to run angr analysis without CFG, Function list, or Stack protection.
def halfAngrScan(file):
	print('\nLoading the Binary...')
	#Using angr to attempt to load the Binary File.
	proj = angr.Project(file, load_options = {'auto_load_libs':False})
	print('\nBinary Architecture:')
	#Print out the Binary Architecture.
	print(proj.arch)

#A function to run radare2 analysis.
def radare2Scan(filepath):
	#setup
	r2 = r2pipe.open(filepath)
	r2.cmd("aaa")
	r2.cmd("s main")

	print "\x1B[32m" + "\n\n\nR2 Analysis:\n" + "\x1B[0m"

	#print basic fileinfo
	print("\x1B[31m" + "File info: \n" + "\x1B[0m" + r2.cmd('iI~arch,bintype,bits,class,endian,lang,machine,os'))
	bintype = r2.cmd('iI~bintype')
	
	
	#print entrypoints, main, linked libraries
	print "\x1B[31m" + "\nBinary info: " + "\x1B[0m"
	print r2.cmd("ie")
	print r2.cmd('iM')
	print "\n" + r2.cmd('il')
	
	#ask if user wants to see all functions
	uinput = raw_input("\nDo you want to see all functions? (y/n)")
	if uinput == 'y' or uinput == 'Y':
		print r2.cmd('afl')
	
	#ask if user wants to run readelf or objdump
	if 'elf' in bintype:
		uinput = raw_input("\nDo you want to run readelf -a?(y/n)")
		if uinput == 'y' or uinput == 'Y':
			print "\x1B[31m" + "\nReadelf \n" + "\x1B[0m"
			print r2.cmd("!readelf -a " + filepath)

	else:
		uinput = raw_input("\nDo you want to run objdump -h?(y/n)")
		if uinput == 'y' or uinput == 'Y':
			print "\x1B[31m" + "\nObjdump -h\n" + "\x1B[0m"
			print r2.cmd("!objdump -h " + filepath)
	#ask if user wants to run strings
	uinput = raw_input("\nDo you want to call strings? (y/n)")
	if uinput == 'y' or uinput == 'Y':
		print r2.cmd("!strings " + filepath)

#A help function to explain which flags runs which scan.
def help():
	print ("\n \'-a\' : To run angr analysis\n \'-aB\' : To run angr analysis(no CFG, function list, stack protection\n \'-b\' : To run binwalk signature and entropy scan\n \'-n\' : To run netcat service heartbeat\n \'-r\' : To run radare2 analysis\n \'-h\' : To get the help table (this table)\n")

	print ("Synopsis:\n")
	print ("python simba.py [Binary File*] [Flag1] [Flag2*] [Flag...*]\n")
	print ("\'*\' means it is optional.\nIt should be noted that this program will not run if:\n    1. A binary file is given but no scan flags.\n    2. A scan flag is given but no binary file.\n    3. No arguments are passed to the too.l\n    4. A file that does not exist is passed to the tool.\n    5. A flag that is not apart of this tools library is passed to it.\n")





def main():
	file = sys.argv[1]
	#If the first argument is a file, we need to start looking for flags at the second index
	if (os.path.exists(file)):
		j=2
	#If the first argument was not a file we look for flags at the first argument
	else:
		j=1

	#Generate a set of all possible flags for this tool.
	fullargset = set(['-a','-aB','-b','-n','-r','-h'])
	#A set of all the flags that require a binary file to scan.
	binlist = ['-a','-aB','-b','-r']
	#Initialize a set of to contain all the flags passed in the command line.
	argset = set([])

	#Grab all arguments given at command line and put them into the argset.
	while(j < len(sys.argv)):
		argset.add(sys.argv[j])
		j = j+1

	#If statement to determine whether all arguments given are a flag for this program, and exits with an exit message if any argument is not.
	if(not(argset.issubset(fullargset))):
		print('\n\nThe flag \"' + argset.difference(fullargset).pop() + '\" has no use with this tool. \nPlease try the -h flag to see the proper flags for each scan.\n' )
		exit()

	#If no arguments are given to the function this exits the function with a 	message.
	if (len(argset) < 1):
		print('No arguments given')
		exit()

	#If -h flag is anywhere in the argset this forces the help function to be shown.
	if '-h' in argset:
		help()
		exit()

	#Complicated loop. Checks if a file is passed. If it is, it checks the flags and makes sure at least on of the flags requires a binary (from our predetermined list binlist), as long as one of these flags is in the list it runs, otherwise it quits. Also if no file is given it makes sure that only either -n or -h flags are passed.
	inlist = False
	if (os.path.exists(file)):
		#Each element in argset
		for x in argset:
			#If x is not in the binlist inlist with False (If inlist is already true this does nothing, but if its false it stays false).
			if x not in binlist:
				inlist = inlist or False
			#If x is in binlist or inlist with true, this will set inlist to true.
			elif x in binlist:
				inlist = inlist or True
		#We make it through the for loop and inlist is still false, that means a binary was given but no flags for scans.
		if inlist == False:
			print('Sorry, if you give a path, you must also supply a flag for a scan')
			exit()
	#Check that if only one argument is given it MUST be -n
	elif((sys.argv[1] != '-n') or (len(argset) > 1)):
		print('Sorry that is im-proper format. \nTry using the -h flag to fix it')
		exit()

		
		#For loop to run all the scans based on the flags given in order at 	command line.
	for i in range(1, len(sys.argv)):
		#Jump to angr function.
		if(sys.argv[i] == '-a'):
			fullAngrScan(file)
		#Jump to simple angr function.
		elif(sys.argv[i] == '-aB'):
			halfAngrScan(file)
		#Jump to Netcat service heartbeat.
		elif(sys.argv[i] == '-n'):
			netcatHeartBeat()
		#Jump to binwalk signature and entropy scan.
		elif(sys.argv[i] == '-b'):
			binwalkSigEntropyScan(file)
		#Jump to radare2 Scan.
		elif(sys.argv[i] == '-r'):
			radare2Scan(file)
		#If the argument is -h, just continue the for loop.
		elif(sys.argv[i] == '-h'):
			continue
	


		

main()
