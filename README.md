# Binary-Recon

Load like any other python script, and pass arguments to run preliminary analysis on binaries. Saves you maybe ~1-2 minutes of your life each time you use it, printing file info, architecture, etc without you needing to load up all the various tools and dig into it!

Example:

`$ python simba.py ~/Downloads/shady.bin -aB -b -r -o out.txt`

## Parameters

Add -a to run angr analyses showing architecture, functions and stack protection

Add -aB to run angr to only load the binary and print the architecture

Add -b to run a binwalk signature and entropy scan

Add -n to run a netcat service heartbeat

Add -r to run a radare2 analysis that will file info, binary info, functions, and will run readelf/objdump and strings when prompted to do so

Add -c to run a cpu_rec analysis if the other analyses still can't find the architecture

Add -o to output the scan results to either a text file or xml file, in which case you will have to supply another argument containing the name of the file you wish to write to

Add -h to repeat this information

## Requirements

Requires all analysis tools to already be installed and accessible to the user running the program: [angr](https://github.com/angr/angr), [binwalk](https://github.com/devttys0/binwalk) with its recommended dependencies, and [radare2](https://github.com/radare/radare2) with r2pipe.

R2pipe can be installed with `$ pip install r2pipe`

cpu_rec is not necessary to run the tool.
