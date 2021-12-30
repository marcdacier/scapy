#!/usr/bin/python3

"""
Simple program that executes the TCP  three way handshake using scapy
The client needs to add a iptables rule to prevent the emission of RST
packets that would prevent the establishment of the session:
iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP


Author: M. Dacier
December 2021
"""


import logging # docs.python.org/3/library/logging.html
import sys
import lib_scapy
from scapy.all  import *
# Our default logging is at WARNING level
# 10: DEBUG, 20: INFO, 30: WARNING, 40:ERROR, 50: CRITICAL

logging_level = 30
# unless if changed by the command line argument.

# the default text to be sent from client to server is
text="The client says hello to the server \n\n\n "


logging.basicConfig(stream=sys.stderr, level=logging_level)
mylog=logging.getLogger("mainlogger")
mylog.warning("Program starts")


# Getting all the arguments from the command line with their default values
# if any ...

(si,sp,di,dp,cseq,debug,return_code,return_string)=lib_scapy.get_args(sys.argv, mylog)

# Setting the debug level according to a possible value provided as an argument

mylog.setLevel(debug)

# If the debug level is higher than the INFO level, ie 20, then we put
# scapy in non verbose mode (nothing goes to stdout after sr1() and send() )

if debug>20:
    scapy_verbose=0
else:
    scapy_verbose=10


# At this point, we know that si and di are either an IP or a resolvable name
# We do not know if we have a route to reach them
# We do not know if si is the same as the host we execute the code from
#
# We know that sp and dp are within acceptable margins for a port
#
# We know that cseq is within acceptable range for a sequence number [0:2**32]

# A negative return code means that something went wrong with the args
# we have to abort the execution

if return_code < 0:
    mylog.critical(return_string)
    exit()

# ##########################
# Beginning of the main execution after the preliminaries
# ##########################


mylog.debug("src IP = %s ; src port = %s", si, sp)
mylog.debug("dst IP = %s ; dst port = %s", di, dp)
mylog.debug("inital seq number = %s",cseq)


# SYN PACKET

synpkt = IP(src=si, dst=di) / TCP (seq=cseq, sport=sp, dport=dp)
mylog.debug("synpkt %s", synpkt.summary())

# synackpkt=sr1(synpkt, verbose=scapy_verbose)
pair, unans = sr(synpkt, verbose=scapy_verbose)

mylog.info("SYN packet sent")

if len(pair) != 1:
    mylog.critical("We have received %s answers to the SYN pckt instead of 1.\nAborting", len(pair))
    exit()

    
if str(pair[0][1][TCP].flags)=="SA":
    mylog.info("SYN ACK packet received")
    synackpkt=pair[0][1]
else:
    mylog.critical("Response to the SYN Packet had the %s flags instead of SYN ACK\n===>You probably forgot to launch your server. By default it should be on s3.net3.local, port 2000\n\"nc -l 2000\"\n\nAborting", str(pair[0][1][TCP].flags))
    exit()
    

# ACK PACKET

ackpkt = synpkt.copy()
ackpkt[TCP].seq = ackpkt[TCP].seq + 1
ackpkt[TCP].flags = "A"
ackpkt[TCP].ack=synackpkt[TCP].seq + 1

# normally, the server does not reply to the ACK
# thus we use send() instead of sr() which would be waiting for ever
# (or for some timeout)

send(ackpkt, verbose=scapy_verbose)
mylog.info("ACK packet sent")

# If the server sends a RST, because, eg, we forgot the iptables rule
# and the client has sent a RST .. we will miss that packet and will
# continue, unaware of what is going on.

# DATA PACKET

datapkt=ackpkt.copy()
datapkt[TCP].flags="PA"
datapkt = datapkt / Raw(load=text)

# the DATA packet should be acknowledged if everything goes well
# Thus, we can use sr() and check what we got back

pair, unans = sr(datapkt, verbose=scapy_verbose)

mylog.info("DATA packet sent")

if len(pair) != 1:
    mylog.critical("We have received %s answers to DATA packet instead of 1.\nAborting", len(pair))
    exit()

    
if str(pair[0][1][TCP].flags)=="A":
    mylog.info("ACK packet received")
    dataackpkt=pair[0][1]
    expected_ack=datapkt[TCP].seq + len(datapkt[TCP].payload)
    if expected_ack != dataackpkt[TCP].ack:
        mylog.critical("Wrong ACK value from the server: got %s instead of the expected %s value. \nAborting", dataackpkt[TCP].ack, expected_ack)
        exit()
else:
    mylog.critical("Response to the DATA Packet had the %s flags instead of ACK \n===>You probably forgot to prevent your client from emitting a RST packet.\n\"iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP\"\n\nAborting", str(pair[0][1][TCP].flags))
    exit()
    

mylog.info("data packet sent with %s bytes: \'%s\'", len(text), text)

# FIN/ACK PACKET

finpkt = datapkt.copy()
finpkt[TCP].flags="FA"
finpkt[TCP].seq=finpkt[TCP].seq + len(datapkt[TCP].payload)
finpkt[TCP].remove_payload()

serverfinpkt=sr1(finpkt, verbose=scapy_verbose)

# We could check here that we did get what we were expecting from the server
# Instead of blinding trusting whatever packet has been received

# ACK PACKET 

finfinpkt=finpkt.copy()
finfinpkt[TCP].flags="A"
finfinpkt[TCP].seq = finfinpkt[TCP].seq +1
finfinpkt[TCP].ack = finfinpkt[TCP].ack +1

send(finfinpkt, verbose=scapy_verbose)

mylog.warning("Program Ends successfully")

