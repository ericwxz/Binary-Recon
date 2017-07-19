# Binary-Recon

Load like any other python script, and pass arguments to run preliminary analysis on binaries. Saves you ~1-2 minutes of your life each time you use it, printing file info, architecture, etc without you needing to load up all the various tools and dig into it!

Example:

`$ python simba.py ~/Downloads/shady.bin -a -n -b -r -aB`

## Parameters

Add -a to run angr analyses

Add -aB to run angr to only load the binary and print the architecture

Add -b to run a binwalk signature and entropy scan

Add -n to run a netcat service heartbeat

Add -r to run a radare2 analysis

Add -h to repeat this information

Requires all analysis tools to already be installed and accessible to the user running the program: [angr](https://github.com/angr/angr), [binwalk](https://github.com/devttys0/binwalk) with its recommended dependencies, and [radare2](https://github.com/radare/radare2) with r2pipe.

R2pipe can be installed with `$ pip install r2pipe`


