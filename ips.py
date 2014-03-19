import threading, Queue, logging, subprocess, time
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *




'''
Initial config of network interface to sniff with
'''

print 'Which interface should we monitor DHCP requests on? '
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


# nr = input('\nInput: ')-1
interface = interfaces[input('\nInput: ')-1]

del interfaces, nr




# ----------------------------------------------------------------
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

class nmap_scan(threading.Thread):           # This needs massive werk
    def __init__ (self, q, interface):
        self.q = q
        threading.Thread.__init__ (self)    
    def run(self):
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






# Build whitelist to check IP:MAC towards
# whitelist = build_whitelist()

whitelist = build_whitelist()

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
                print 'Return False'
                print '\n----------------------------\nIntruder alert!\nSource MAC: %s\nIP: %s\nClass Id: %s\nHostname: %s' % ( val[0], val[1], val[2], val[3] )
                
   
    
  
    
