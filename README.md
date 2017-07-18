# Binary-Recon

Load like any other python script, and pass arguments to run preliminary analysis on binaries.

Example:

`$ python simba.py ~/Downloads/shady.bin -a -n -b -r -aB`

## Parameters

Add -a to run a full angr analyses


Add -aB to run angr to only load the binary and print the architecture

Add -b to run a binwalk signature and entropy scan

Add -n to run a netcat service heartbeat

Add -r to run a radare2 analysis

Add -h to repeat this information

Requires all analysis tools to already be installed: [angr](https://github.com/angr/angr), [binwalk](https://github.com/devttys0/binwalk), and [radare2](https://github.com/radare/radare2) with r2pipe.

R2pipe can be installed with `$ pip install r2pipe`


