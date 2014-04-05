#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Coded by Sam (info@sam3.se)

import threading, Queue, logging, imp, nmap
import subprocess, shlex, time, os, sys
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from struct import *
from socket import *
from random import randint


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


class Scan_Hosts(threading.Thread):
    def __init__(self, queue, output):
        threading.Thread.__init__(self)
        self.queue=queue
        self.output=output
    def run(self):
        self.host=self.queue.get()
        ip = pingandarp(self.host)
        if ip:
            self.output.put(ip)
        self.queue.task_done()

def pingandarp(ip):
    while True:
        os.system('ping %s -c 1 > /dev/null' % ip)
        p = subprocess.Popen('arp -a %s' % ip, shell=True, stdout=subprocess.PIPE)
        while True:
            line = p.stdout.readline()
            if line != '':
                if line.find('(%s) at' % ip) != -1 and line.find('at <incomplete> on') == -1:
                    return '%s-%s' % (line.split(' [')[0].split('at ')[1], line.split(')')[0].split('(')[1])
                else:
                    return 'DEAD HOST'                
            else:
                break     
    
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
    def __init__ (self, victim):
        self.ip = victim.split('-')[1]
        self.mac = victim.split('-')[0]
        self.victim = victim
        self.alive = True
        threading.Thread.__init__ (self)    
    def run(self):
        while True:
            i = randint(1,2)
            if i == 1:  #troll
                self.attack(1, randint(0, troll_count-1))
                
            elif i == 2:  #death
                self.attack(2, randint(0, death_count-1))
                
            client = pingandarp(self.ip)
            if client == 'DEAD HOST':
                print '[+] %s is dead. Stopping attacks on that host.' % self.ip
                break
            
    def attack(self, i, nr):
        if i == 1:
            print '[+] Starting troll attack (%s) on %s' % (trolls[nr].getname(), self.ip)
            trolls[nr].run(self.victim)
        if i == 2:
            print '[+] Starting death attack (%s) on %s' % (deaths[nr].getname(), self.ip)
            deaths[nr].run(self.victim)
            
        
            
    
def checklist(whitelist, intruder):
    for credentials in whitelist:
        w_ip = credentials.split('-')[0]
        w_mac = credentials.split('-')[1]
        if credentials.split('-')[0].find(intruder[0]) != -1 and credentials.split('-')[1].find(intruder[1]) != -1:
            return True
    return False
      
      
def build_whitelist(gateway):
    whitelist = []
    f = open('whitelist.lst', 'r')  #  Format in whitelist.lst = ff:ff:ff:ff:ff:ff-127.0.0.1
    for line in f.readlines():
        whitelist.append(line.strip('\n') + '-' + gateway)
    if not whitelist:
        print '[!] Could not build whitelist. Wtf is wrong with you?'
        quit()
    else:
        return whitelist


def findgateway():
    proc = subprocess.Popen('route -n | grep \'UG[ \t]\' | awk \'{print $2}\'', stdout=subprocess.PIPE, shell=True)
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



# Build whitelist to check MAC:IP towards

alive_intruders = []
gateway = findgateway()
whitelist = build_whitelist(gateway)
subnetmask = gateway+lookup(gateway)

print '[+] Starting ARP ping and ping scan [%s]' % subnetmask



# Start arp ping scan and append intruders to list

output = Queue.Queue()
hosts = []
nm = nmap.PortScanner() 
nm.scan(hosts=subnetmask, arguments='-n -sn --send-ip')
hosts_list = [(x, nm[x]['status']['state']) for x in nm.all_hosts()]
for host, status in hosts_list:
    if not host == whitelist_ip and host != gateway:
        hosts.append(host)

nm.scan(hosts=subnetmask, arguments='-n -sP -PE -PA21,23,80,3389')
hosts_list = [(x, nm[x]['status']['state']) for x in nm.all_hosts()]
for host, status in hosts_list:
    if not host == whitelist_ip and host != gateway:
        hosts.append(host)
        

hosts = set(list(hosts))
for i in range(len(hosts)):
    t=Scan_Hosts(queue, output)
    t.setDaemon(True)
    t.start()
    
for host in hosts:
    queue.put(host.strip())
    queue.join()
        
print '[+] Scan done'   
while True:
    if not output.empty():
        val = output.get()
        print '[-] Found host: ' + str(val)
        alive_intruders.append('%s-%s' % (val, gateway))
    else:
        break

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

print '[+] Removing whitelisted hosts'
alive_intruders = list(set(alive_intruders) - set(whitelist))
   
while True:
    if not queue.empty():
        val = queue.get()
        if len(val) == 4 :
            if checklist(whitelist, val):
                print 'Whitelisted client connected [%s-%s]' % ( val[1], val[0] )
            else:
                print '\n----------------------------\nIntruder alert!\nSource MAC: %s\nIP: %s\nClass Id: %s\nHostname: %s\n----------------------------\n' % ( val[0], val[1], val[2], val[3] )
                alive_intruders.append('%s-%s-%s' % (val[0] , val[1], gateway))
    
    if len(alive_intruders) != 0:
        thread = victim(alive_intruders[-1])
        thread.daemon = True
        thread.start()        
        alive_intruders.pop()
        