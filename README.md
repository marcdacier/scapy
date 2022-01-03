# scapy
This repository contains a number of simple scapy scripts used within a lecture given at KAUST (King Abdullah University of Sciences and Technology) 
entitled "Applied Network Security", given by M. Dacier (marc.dacier@kaust.edu.sa)
These scripts can be used 'as is' within a dedicated GNS3 environment created for that lecture.
If you want to use it in another environment, you will have to modify a few things here and there.

These scripts are part of a paedagogical process and, therefore, some of them contain intentionally bugs, vulnerabilities, misleading statements or errors.
Handle with care and know what you do. 

interactive_synack:
illustrates how to use scapy to establish the 3 way TCP handshake between a client (where scapy runs) and a server.
By default, the server should be listening on port 2000, on the machine s3.net3.local :  nc -l 2000.
You must have an iptables rules on the client to prevent the emission of a RST packet when receiving the SYNACK:
iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP

3wayexpect.exp:
illustrates how to use expect to write a script to send interactive commands to scapy to execute the same think a interactive_synack.

normal_tcp_session.py:
illustrates how to write a python script that uses scapy to do the same as interactive_synack.
The main difference resides
i) in using the argparse module to provide flexibility with the arguments,
ii) in using the logging module to facilitate debugging or tracing and
iii) in using the doctest module to test the various functions used
iiv) in adopting a defensive programming approach (partially) to deal with possible corner cases 
This program requires the functions defines in the file lib_scapy.py

lib_scapy.py:
contains functions used by normal_tcp_session.py

sniff.exp:
illustrates how to use expect to send scapy commands to hijack an existing connection between two machines

