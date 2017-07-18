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

#A function to run Binwalk Signature and Entropy Scan.
def binwalkSigEntropyScan():
	print ('rawr4')

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
	print ('rawr5')

#A help function to explain which flags runs which scan.
def help():
	print ("\n \'-a\' : To run angr analysis\n \'-aB\' : To run angr analysis(no CFG, function list, stack protection\n \'-b\' : To run binwalk signature and entropy scan\n \'-n\' : To run netcat service heartbeat\n \'-r\' : To run radare2 analysis\n \'-h\' : To get the help table (this table)\n")






def main():
	file = sys.argv[1]
	if (os.path.exists(file)):
		j=2
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

	if (os.path.exists(file)):
		for x in argset:
			print x 
			if x not in binlist:
				print('You gave a file but no scans to run on it!')
				exit()
	elif((sys.argv[1] != '-n') or len(argset) > 1):
		print('Sorry that is im-proper format. \nTry using the -h flag to fix it')
		exit()

	#If statement to determine whether all arguments given are a flag for this program, and exits with an exit message if any argument is not.
	if(not(argset.issubset(fullargset))):
		print('\n\nThe flag \"' + argset.difference(fullargset).pop() + '\" has no use with this tool. \nPlease try the -h flag to see the proper flags for each scan.\n' )
		exit()

	#If -h flag is anywhere in the argset this forces the help function to be shown.
	if '-h' in argset:
		help()
	
	#If no arguments are given to the function this exits the function with a 	message.
	if (len(argset) < 1):
		print('No arguments given')
		exit()
	else:	
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
