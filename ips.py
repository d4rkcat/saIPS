#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Coded by Sam (info@sam3.se)

import threading, Queue, logging, imp
import subprocess, shlex, time, os, sys
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from struct import *
from socket import *


'''
-- Load troll and death modules --
'''

trolldir = 'troll_module/'
sys.path.append(trolldir)
troll_modules = next(os.walk(trolldir))[2]
trolls = []
troll_count = 0

for troll in troll_modules:
    if troll.endswith('.py'):
        trollbridge = os.path.join(trolldir, troll)
        mod = imp.load_source('trollmod', trollbridge)
        trolls.append(mod)
        troll_count += 1

print '[+] Loaded %s troll module(s)' % troll_count    

#trolls[0].run('FUCK YOU')  
deathdir = 'death_module/'
sys.path.append(deathdir)
deaths = []  
death_modules = next(os.walk(deathdir))[2]
death_count = 0

for death in death_modules:
    if death.endswith('.py'):
        deathsdoor = os.path.join(deathdir, death)
        mod = imp.load_source('deathmod', deathsdoor)
        deaths.append(mod)
        death_count += 1
        
print '[+] Loaded %s death module(s)' % death_count           
        

'''
Initial config of network interface to sniff with
'''

# Add support for arch's interface structure

print '\nWhich interface should we monitor DHCP requests on? '
nr = 0
interfaces =[]
proc = subprocess.Popen('ifconfig', stdout=subprocess.PIPE)
while True:
    line = proc.stdout.readline()
    if line != '':
        if line.find('eth') != -1 or line.find('wlan') != -1 or line.find('vmnet') != -1: 
            interfaces.append(str(line.split(' ')[0]))
    else:
        break

for i in interfaces:
    nr += 1
    print '(%i) %s' % (nr, i)


interface = interfaces[input('\nInput: ')-1]
del interfaces, nr

p = subprocess.Popen(shlex.split('ifconfig %s' % interface), stdout=subprocess.PIPE)
while True:
    line = p.stdout.readline()
    if line != '':
        if line.find('inet addr:') != -1:
            whitelist_ip = str(line.split(' Bcast:')[0]).split(':')[1].strip(' ')
    else:
        break

if not whitelist_ip:
    print '[!] Couldn\'t find your IP by running \'ifconfig %s\'. WTF is wrong with you? Quitting' % interface
    quit()


# ----------------------------------------------------------------

def lookup(ip): # from stackoverflow. cant remember url :(
    f = unpack('!I',inet_pton(AF_INET,ip))[0]
    private = (
        [ 2130706432, 4278190080 ], # 127.0.0.0,   255.0.0.0   http://tools.ietf.org/html/rfc3330
        [ 3232235520, 4294901760 ], # 192.168.0.0, 255.255.0.0 http://tools.ietf.org/html/rfc1918
        [ 2886729728, 4293918720 ], # 172.16.0.0,  255.240.0.0 http://tools.ietf.org/html/rfc1918
        [ 167772160,  4278190080 ], # 10.0.0.0,    255.0.0.0   http://tools.ietf.org/html/rfc1918
    )
    subnetmask = ['/8', '/24', '/12', '/8'  ]
    i = 0
    for net in private:
        if (f & net[1] == net[0]):
            return subnetmask[i]
        i += 1
    print '[!] Could not find the correct subnetmask. Are you really on a private IP?'
    quit()



'''
DHCP intruder thread
Scan and put list of new intruder in queue
'''


queue = Queue.Queue()
class DHCP_SCAN(threading.Thread):
    def __init__ (self, q, interface):
        self.q = q
        self.interface = interface
        threading.Thread.__init__ (self)
   
    def run(self):
        conf.checkIPaddr = False
        fam, hw = get_if_raw_hwaddr(interface)
        #sendp(Ether(dst="ff:ff:ff:ff:ff:ff")/IP(src="0.0.0.0",dst="255.255.255.255")/UDP(sport=68,dport=67)/BOOTP(chaddr=hw)/DHCP(options=[("message-type","discover")]),count=3)
        sniff(filter="udp and (port 67 or 68)", prn=self.dhcp_discover, store=1)        
        
    def dhcp_discover(self, resp):
        intruder = []
        new_intruder = False
        source = resp[Ether].src
        try:
            for opt in resp[DHCP].options:
                if opt == 'end' or opt == 'pad':
                    break
                if opt[0] == 'message-type' and opt[1] == 3:
                    new_intruder = True
                    intruder.append(source)
                if new_intruder and (opt[0] == 'requested_addr' or opt[0] == 'vendor_class_id' or opt[0] == 'hostname'):
                    intruder.append(opt[1])
            if intruder:
                self.q.put(intruder)
        except:
            pass

# ----------------------------------------------------------------

class victim(threading.Thread):           # This needs massive werk
    def __init__ (self, q, victim):
        self.q = q
        self.victim = victim
        threading.Thread.__init__ (self)    
    def run(self):
        print 'Do something with: ',
        print self.victim
        print len(trolls)
        trolls[0].run(self.victim)
    
    def attack(self):
        pass
        
    
    
def checklist(whitelist, intruder):
    for credentials in whitelist:
        w_ip = credentials.split('-')[0]
        w_mac = credentials.split('-')[1]
        #if w_ip.find(intruder[1]) != -1 and w_mac.find(intruder[0]) != -1:
        if credentials.split('-')[0].find(intruder[1]) != -1 and credentials.split('-')[1].find(intruder[0]) != -1:
            return True
    return False
      
      
def build_whitelist():
    whitelist = []
    f = open('whitelist.lst', 'r')  #   127.0.0.1:MAC
    for line in f.readlines():
        whitelist.append(line.strip('\n'))
    if not whitelist:
        print '[!] Could not build whitelist. Wtf is wrong with you?'
        quit()
    else:
        return whitelist


def findgateway():
    proc = subprocess.Popen(
        'route -n | grep \'UG[ \t]\' | awk \'{print $2}\'', 
        stdout=subprocess.PIPE, shell=True)
    while True:
        line = proc.stdout.readline()
        if line != '':
            g_answ = raw_input( '\nI think your gateway IP is (%s). Is this correct (default = yes)? ' % line.strip('\n') )
            gateway = line.strip('\n')
            if (g_answ.upper() != 'Y' and g_answ.upper() != 'YES' and g_answ != None and g_answ != ''):
                    gateway = raw_input('No? What is it then? ' )            
            return gateway
        else:            
            break



# Build whitelist to check IP:MAC towards

alive_intruders = []
whitelist = build_whitelist()
gateway = findgateway()

subnetmask = lookup(gateway)
subnetmask = gateway+subnetmask

print '[+] Starting ARP ping scan [%s]' % subnetmask



# Start arp ping scan and append intruders to list
conf.verb=0
ans,unans=srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=subnetmask), timeout=3)

for snd,rcv in ans:
    mac = rcv.sprintf(r"%Ether.src%")
    ip = rcv.sprintf(r"%ARP.psrc%")
    if  ip != gateway:
        print mac, ip # remove this later on
        alive_intruders.append('%s-%s' % (mac, ip))

        
'''
example victim
thread = victim(queue, 'FUCK')
thread.daemon = True
thread.start()
'''




while True:
    try:
        thread = DHCP_SCAN(queue, interface)
        thread.daemon = True
        thread.start()
    except:
        pass
    time.sleep(1)         # i know, i know
    if thread.isAlive():
        break
    
    
while True:
    if not queue.empty():
        val = queue.get()
        if len(val) == 4 :
            if checklist(whitelist, val):
                print 'Whitelisted client connected %s-%s' % ( val[1], val[0] )
            else:
                print '\n----------------------------\nIntruder alert!\nSource MAC: %s\nIP: %s\nClass Id: %s\nHostname: %s' % ( val[0], val[1], val[2], val[3] )
                alive_intruders.append('%s-%s' % (val[0] , val[1]))
                
    #if alive_intruders:
     #   print 'Do something nasty with intruders here'
                
    
  
    
