#Title: Python Binary Reconnaissance Tool
#Revision: 1
#Authors: Elijah Sheets & Eric Zhang
#Project Start:7/17/2017
#Last Revision:7/18/2017
#Goal: Through collaboration with a fellow NREIP intern build a Binary Reconnaissance 	     Tool to run specific scans and or analysis.

#imports
import os
import sys
import angr
import binwalk
import r2pipe

#A function to run Binwalk Signature and Entropy Scan.
def binwalkSigEntropyScan():
	for module in binwalk.scan(file, 
				   signature=True,  
				   quiet=True):
		print "%s Binwalk Signature Scan:" % module.name
		for result in module.results:
			print "\t%s    0x%.8x    %s" % (result.file.name, 
							result.offset,
							result.description)
	print "Binwalk Entropy Scan:"
	binwalk.scan(file, entropy=True)

#A function to run a Netcat Service Heartbeat.
def netcatHeartBeat(): 
	print ('rawr3')
	

#A function to run angr analysis.
def fullAngrScan():
	print ('rawr1')

#A function to run angr analysis without CFG, Function list, or Stack protection.
def halfAngrScan():
	print ('rawr2')

#A function to run radare2 analysis.
def radare2Scan():
	#setup
	r2 = r2pipe.open(file)
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
	
	#ask if user wants to run readelf
	if 'elf' in bintype:
		uinput = raw_input("\nDo you want to run readelf -a?(y/n)")
		if uinput == 'y' or uinput == 'Y':
			print "\x1B[31m" + "\nReadelf \n" + "\x1B[0m"
			print r2.cmd("!readelf -a " + file)

	#ask if user wants to run strings
	uinput = raw_input("\nDo you want to call strings? (y/n)")
		if uinput == 'y' or uinput == 'Y':
			print r2.cmd("!strings " + file)

#A help function to explain which flags runs which scan.
def help():
	print ("\n \'-a\' : To run angr analysis\n \'-aB\' : To run angr analysis(no CFG, function list, stack protection\n \'-b\' : To run binwalk signature and entropy scan\n \'-n\' : To run netcat service heartbeat\n \'-r\' : To run radare2 analysis\n \'-h\' : To get the help table (this table)\n")






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

	#If the file exists, and the flags given are in the 
	inlist = False
	if (os.path.exists(file)):
		for x in argset:
			if x not in binlist:
				inlist = inlist or False
			elif x in binlist:
				inlist = inlist or True
		if inlist == False:
			exit()
	elif((sys.argv[1] != '-n') or len(argset) > 1):
		print('Sorry that is im-proper format. \nTry using the -h flag to fix it')
		exit()

	#If -h flag is anywhere in the argset this forces the help function to be shown.
	if '-h' in argset:
		help()
		
		#For loop to run all the scans based on the flags given in order at 	command line.
	for i in range(1, len(sys.argv)):
		#Jump to angr function.
		if(sys.argv[i] == '-a'):
			fullAngrScan()
		#Jump to simple angr function.
		elif(sys.argv[i] == '-aB'):
			halfAngrScan()
		#Jump to Netcat service heartbeat.
		elif(sys.argv[i] == '-n'):
			netcatHeartBeat()
		#Jump to binwalk signature and entropy scan.
		elif(sys.argv[i] == '-b'):
			binwalkSigEntropyScan()
		#Jump to radare2 Scan.
		elif(sys.argv[i] == '-r'):
			radare2Scan()
		#If the argument is -h, just continue the for loop.
		elif(sys.argv[i] == '-h'):
			continue
	


		

main()
