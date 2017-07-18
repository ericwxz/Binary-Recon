import binwalk
from sys import argv

name, filename = argv




def bw(filename):
	for module in binwalk.scan(filename, 
				   signature=True,  
				   quiet=True):
		print "%s Binwalk Signature Results:" % module.name
		for result in module.results:
			print "\t%s    0x%.8x    %s" % (result.file.name, 
							result.offset,
							result.description)
	
	print "Binwalk Entropy Scan:"
	binwalk.scan(filename, entropy=True)
	

