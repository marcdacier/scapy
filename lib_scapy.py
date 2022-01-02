# invoke this file with -v in order to run all doctests
# namely:  python3 lib_scapy.py -v
#

import doctest # docs.python.org/3/library/doctest.html
import random
import sys
import argparse # docs.python.org/3/library/argparse.html
import logging 

# --------------------------
# HIJACK_GET_ARGS(line_args, mylog)
# --------------------------


def hijack_get_args(line_args, mylog):
 
    """
    This module reads the args from the command line and produces some check
    line_args are all the arguments whereas mylog is a handler for logging
    it returns all the arguments with their default values if they have 
    not been explicitly defined on the command line
>>> import logging
>>> logging.basicConfig(stream=sys.stdout, level=logging.INFO)
>>> templog=logging.getLogger("mainlogger")
>>> get_args(['lib_scapy.py','-sq','1000','-db', '20', '-sp','1500'],templog)
INFO:mainlogger:all arguments have been parsed
('c3.net3.local', 1500, 's3.net3.local', 2000, 1000, 20, 0, '')
>>> get_args(['lib_scapy.py','-sq','1000', '-sp','1500'],templog)
('c3.net3.local', 1500, 's3.net3.local', 2000, 1000, 30, 0, '')

    """

    # Initializing return codes for the function
    status_code=0
    status=""

    # Parsing all provided arguments
    parser = argparse.ArgumentParser(description="TCP hijack with scapy")

    parser.add_argument('-si' , help='the source ip to connect from', default="s3.net3.local")
    parser.add_argument('-sm',  type=int , help='the source MAC address of the session to hijack', default="aa:03:03:03:03:03")
    parser.add_argument('-di' , help='the destination ip to connect to', default="r23.net3.local")
    parser.add_argument('-sm',  type=int , help='the destination MAC address of the session to hijack', default="unknown")
    parser.add_argument('-dp',  type=int , help='the destination port  of the session to hijack', default=80)
    parser.add_argument('-db',  type=int , help='debug level (0,10,20,30,40,50)', default=30)

    # args[0] is the script name, first argument starts at args[1]
    args=parser.parse_args(line_args[1:])


    # Now, we verify all causes for aborting the execution
    

    # Check validity of provided destination port 
    if args.dp > 65535 or args.dp <= 0 :
        mylog.error("Destination port, %s,  must be bigger than 0 and smaller than 65536", args.dp)
        status="Fatal Error: Erroneous Destination Port:  \'" + str(args.dp) + "\'"
        status_code=-1

    # Check validity of seq number 
    elif args.sq < 0 or args.sq > 2**32 :
        mylog.error("Sequence number, %s, must be contained within range [0:2**32]", args.sq)
        status="Fatal Error: incorrect sequence number: \'" + str(args.sq) + "\'"
        status_code=-1
        
    # Check if si is an IP or a name
    elif not is_ip(args.si, mylog) and not resolvable(args.si, mylog):
        mylog.error("Source address, %s, is neither an IP nor a resolvable name", args.si)
        status_code=-1
        status="Fatal Error: erroneous source IP:  \'" + str(args.si) + "\'"
        
    # Check if di is an IP or a name
    elif not is_ip(args.di, mylog) and not resolvable(args.di, mylog):
        mylog.error("Destination address, %s,  is neither an IP nor a resolvable name", args.di)
        status_code=-1
        status="Fatal Error: erroneous destination IP:  \'" + str(args.di) + "\'"

    # Check validity of source MAC address
elif not re.match("([0-9a-f]{2}:){5}[0-9a-f]{2}",args.sm.lower():
                  mylog.critical("Provided source MAC addres, \'%s\', is not valid.\nAborting", args.sm)
                  status_code=-1
                  status="Fatal Error: wrong source MAC address: \'" + str(args.sm) + "\'"

    # Checking validity of destination MAC address, if provided
    elif args.dm != "unknown":
                      if not re.match("([0-9a-f]{2}:){5}[0-9a-f]{2}",args.dm.lower():
                                      mylog.critical("Provided destination MAC addres, \'%s\', is not valid.\nAborting", args.dm)
                                      status_code=-1
                                      status="Fatal Error: wrong destination MAC address: \'" + str(args.dm) + "\'"

                                      
    # Check validity of debug level
    elif args.db < 0 or args.db>50:  
        mylog.error("Debug level should be a value between 0 and 50: \n 0 = NOTSET \n 10 = DEBUG  \n 20 = INFO  \n 30 = WARNING \n 40 = ERROR \n 50 = CRITICAL" )
        status_code=-1
        status="Fatal Error: erroneous debugging level:  \'" + str(args.db) + "\'"
    else:
        mylog.setLevel(args.db)

    mylog.info("all arguments have been parsed")

    

# Code should be added to
# 1) check if di can be reached, once resolved
# 2) check if si is the IP of the host we are in, if not ARP must be considered
#    a new return value (source_is_local) could be added, as a boolean

    return(args.si,args.sp,args.di,args.dp,args.dm,args.db,status_code,status)





# --------------------------
# GET_ARGS(line_args, mylog)
# --------------------------


def get_args(line_args, mylog):
     """
    This module reads the args from the command line and produces some check
    line_args are all the arguments whereas mylog is a handler for logging
    it returns all the arguments with their default values if they have 
    not been explicitly defined on the command line
>>> import logging
>>> logging.basicConfig(stream=sys.stdout, level=logging.INFO)
>>> templog=logging.getLogger("mainlogger")
>>> get_args(['lib_scapy.py','-sq','1000','-db', '30', '-sp','1500'],templog)
('c3.net3.local', 1500, 's3.net3.local', 2000, 1000, 30, 0, '')
>>> get_args(['lib_scapy.py','-sq','1000','-db', '20', '-sp','1500'],templog)
INFO:mainlogger:all arguments have been parsed
('c3.net3.local', 1500, 's3.net3.local', 2000, 1000, 20, 0, '')
>>> get_args(['lib_scapy.py','-sq','1000', '-sp','1500'],templog)
('c3.net3.local', 1500, 's3.net3.local', 2000, 1000, 30, 0, '')
    """

    # Initializing return codes for the function
    status_code=0
    status=""
    # Parsing all provided arguments
    parser = argparse.ArgumentParser(description="TCP handshake with scapy")
    parser.add_argument('-si' , help='the source ip to connect from', default="c3.net3.local")
    parser.add_argument('-sp',  type=int , help='the source port to connect from')
    parser.add_argument('-di' , help='the destination ip to connect to', default="s3.net3.local")
    parser.add_argument('-dp',  type=int , help='the destination port to connect to', default=2000)
    parser.add_argument('-sq',  type=int , help='initial sequence number of the client', default=1000)
    parser.add_argument('-db',  type=int , help='debug level (0,10,20,30,40,50)', default=30)
    # args[0] is the script name, first argument starts at args[1]
    args=parser.parse_args(line_args[1:])

    # Checking the arguments provided
    # If no source port provided, choose a random one, below 65535
    if args.sp==None:
        args.sp=random.randrange(1,65535)
        mylog.debug("source port chosen equal to: \'%s\'", args.sp)

    # Now, we verify all causes for aborting the execution
    
    # Check validity of provided source port
    if args.sp > 65535 or args.sp <= 0 :
        mylog.error("Source port, %s, must be bigger than 0 and smaller than 65536", args.sp)
        status="Fatal Error: Erroneous Source Port:  \'" + str(args.sp) + "\'"
        status_code=-1

    # Check validity of provided destination port 
    elif args.dp > 65535 or args.dp <= 0 :
        mylog.error("Destination port, %s,  must be bigger than 0 and smaller than 65536", args.dp)
        status="Fatal Error: Erroneous Destination Port:  \'" + str(args.dp) + "\'"
        status_code=-1

    # Check validity of seq number 
    elif args.sq < 0 or args.sq > 2**32 :
        mylog.error("Sequence number, %s, must be contained within range [0:2**32]", args.sq)
        status="Fatal Error: incorrect sequence number: \'" + str(args.sq) + "\'"
        status_code=-1
        
    # Check if si is an IP or a name
    elif not is_ip(args.si, mylog) and not resolvable(args.si, mylog):
        mylog.error("Source address, %s, is neither an IP nor a resolvable name", args.si)
        status_code=-1
        status="Fatal Error: erroneous source IP:  \'" + str(args.si) + "\'"
    # Check if di is an IP or a name
    elif not is_ip(args.di, mylog) and not resolvable(args.di, mylog):
        mylog.error("Destination address, %s,  is neither an IP nor a resolvable name", args.di)
        status_code=-1
        status="Fatal Error: erroneous destination IP:  \'" + str(args.di) + "\'"

    # Check validity of debug level
    elif args.db < 0 or args.db>50:  
        mylog.error("Debug level should be a value between 0 and 50: \n 0 = NOTSET \n 10 = DEBUG  \n 20 = INFO  \n 30 = WARNING \n 40 = ERROR \n 50 = CRITICAL" )
        status_code=-1
        status="Fatal Error: erroneous debugging level:  \'" + str(args.db) + "\'"
    else:
        mylog.setLevel(args.db)

    mylog.info("all arguments have been parsed")

    

# Code should be added to
# 1) check if di can be reached, once resolved
# 2) check if si is the IP of the host we are in, if not ARP must be considered
#    a new return value (source_is_local) could be added, as a boolean

    return(args.si,args.sp,args.di,args.dp,args.sq,args.db,status_code,status)


# --------------------------
# RESOLVABLE(name, mylog)
# --------------------------


import socket
import re

def resolvable(name, mylog):
    """
    This method takes a FQDN name as input and a logging handler
    it returns True if that FQDN can be resolved to an IP
    it returns False otherwise
>>> import logging
>>> logging.basicConfig(stream=sys.stdout, level=logging.INFO)
>>> templog=logging.getLogger("mainlogger")
>>> resolvable('c3.net3.local',templog)
True
>>> resolvable('1.2.3.4',templog)
False
>>> resolvable('1.2.3.4.a5',templog)
False
>>> resolvable('1.2',templog)
False
>>> resolvable('google.com',templog)
True
    """

    try:
        # an IP could be defined with less than 4 groups of digits
        # for instance: gethostbyname("1.1") returns "1.0.0.1"
        # but ipaddress.ip_address("1.1") returns false!
        # we must verify that "name" does not only contain digits
        only_digits=not re.search('[a-z|A-Z]+',name)
        # if it does only contain digit, we do not call gethostbyname
        
        if not only_digits:
            mylog.debug("\'%s\' contains alphabetical characters", name)
            ip = socket.gethostbyname(name)
        else:
            mylog.debug("\'%s\' does not contain alphabetical characters", name)
            ip = False            
        if ip:
            return True
        else:
            return False
    except Exception:
        return False

# --------------------------
# IS_IP(address, mylog)
# --------------------------

    
import ipaddress
def is_ip(address, mylog):
    """
    This method takes a string as input and a logging handler 
    it returns True if that string is an IP address
    it returns False if not
>>> import logging
>>> logging.basicConfig(stream=sys.stdout, level=logging.INFO)
>>> templog=logging.getLogger("mainlogger")
>>> is_ip('c3.net3.local',templog)
False
>>> is_ip('1.2.3.4',templog)
True
>>> is_ip('0.0.0.0',templog)
True
>>> is_ip('1.2.3.4.5',templog)
False
>>> is_ip('300.2.3.4',templog)
False
>>> is_ip('1.2.3.4.a5',templog)
False
>>> is_ip('1.2',templog)
False
>>> is_ip('google.com',templog)
False
    """

    try:
        valid_ip=ipaddress.ip_address(address)
        if valid_ip:
            mylog.debug("\'%s\' seems valid according to the ipaddress module",address)
            return True
    except Exception:
        mylog.debug("\'%s\' is not an IP address according to the ipaddress module", address)
        return False

# -----
# MAIN 
# -----



if __name__ == "__main__":
    print("This line is only written when this file is invoked as main")
    import doctest
    doctest.testmod()
 
