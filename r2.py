import r2pipe
from sys import argv


def r2(self, filepath, option):

	#setup
	r2 = r2pipe.open(filepath)
	r2.cmd("aaa")
	r2.cmd("s main")


	print "\x1B[32m" + "\n\n\nUseful stuff to know:\n" + "\x1B[0m"

	#print basic fileinfo
	print("\x1B[31m" + "File info: \n" + "\x1B[0m" + r2.cmd('iI~arch,bintype,bits,class,endian,lang,machine,os'))
	bintype = r2.cmd('iI~bintype')
	
	
	#print entrypoints, main, linked libraries
	print "\x1B[31m" + "\nBinary info: " + "\x1B[0m"
	print r2.cmd("ie")
	print r2.cmd('iM')
	print "\n" + r2.cmd('il')
	
	
	#print functions
	#callref = r2.cmd("pd~call")
	
	if option == 'all':
		print r2.cmd('afl')
	#	print "\x1B[31m" + "\nFunction calls: \n" + "\x1B[0m" + callref
	else:
		uinput = raw_input("\nDo you want to see all functions? (y/n)")
		if uinput == 'y' or uinput == 'Y':
			print r2.cmd('afl')
	#		print "\x1B[31m" + "\nFunction calls: \n" + "\x1B[0m" + callref
	
	
	
	#print readelf
	if 'elf' in bintype and option != 'all':
		uinput = raw_input("\nDo you want to run readelf -a?(y/n)")
		if uinput == 'y' or uinput == 'Y':
			print "\x1B[31m" + "\nReadelf \n" + "\x1B[0m"
			print r2.cmd("!readelf -a " + filepath)
	elif 'elf' in bintype and option == 'all':
		print "\x1B[31m" + "\nReadelf \n" + "\x1B[0m"
		print r2.cmd("!readelf -a " + filepath)
	
	
	#print strings
	if option == 'all':
		print "\x1B[31m" + "\nStrings: \n" + "\x1B[0m"
		print r2.cmd("!strings " + filepath)
	else:
		uinput = raw_input("\nDo you want to call strings? (y/n)")
		if uinput == 'y' or uinput == 'Y':
			print r2.cmd("!strings " + filepath)

def r2(self, filepath):
	#setup
	r2 = r2pipe.open(filepath)
	r2.cmd("aaa")
	r2.cmd("s main")

	print "\x1B[32m" + "\n\n\nUseful stuff to know:\n" + "\x1B[0m"

	#print basic fileinfo
	print("\x1B[31m" + "File info: \n" + "\x1B[0m" + r2.cmd('iI~arch,bintype,bits,class,endian,lang,machine,os'))
	bintype = r2.cmd('iI~bintype')
	
	
	#print entrypoints, main, linked libraries
	print "\x1B[31m" + "\nBinary info: " + "\x1B[0m"
	print r2.cmd("ie")
	print r2.cmd('iM')
	print "\n" + r2.cmd('il')

	uinput = raw_input("\nDo you want to see all functions? (y/n)")
		if uinput == 'y' or uinput == 'Y':
			print r2.cmd('afl')
	#		print "\x1B[31m" + "\nFunction calls: \n" + "\x1B[0m" + callref

	if 'elf' in bintype:
		uinput = raw_input("\nDo you want to run readelf -a?(y/n)")
		if uinput == 'y' or uinput == 'Y':
			print "\x1B[31m" + "\nReadelf \n" + "\x1B[0m"
			print r2.cmd("!readelf -a " + filepath)

	uinput = raw_input("\nDo you want to call strings? (y/n)")
		if uinput == 'y' or uinput == 'Y':
			print r2.cmd("!strings " + filepath)

	
	
	
	
	

