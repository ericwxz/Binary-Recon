import binwalk
from sys import argv

name, filename = argv




def bw(filename):
	for module in binwalk.scan(filename, 
				   signature=True,  
				   quiet=True):
		print "%s Results:" % module.name
		for result in module.results:
			print "\t%s    0x%.8x    %s" % (result.file.name, 
							result.offset,
							result.description)
	binwalk.scan(filename, entropy=True)
	

