import dpkt
FILENAME = 'assignment2.pcap'
SOURCE_IP = '130.245.145.12'
DEST_IP = '128.208.2.198'

class TCPFlow:
    def __init__(self, sourcePort, sourceIP, destPort, destIP, seqNum1, seqNum2, ackNum1, ackNum2, windowSize1, windowSize2, throughput, awaitingSecond, time, push):
        self.sourcePort = sourcePort #Source Port
        self.sourceIP = sourceIP #Source IP Address
        self.destPort = destPort #Destination Port
        self.destIP = destIP #Destination IP Address
        self.seqNum1 = seqNum1 #Sequence Number for transaction 1
        self.seqNum2 = seqNum2 #Sequence Number for transaction 2
        self.ackNum1 = ackNum1 #ACK Number for transaction 1
        self.ackNum2 = ackNum2 #ACK Number for transaction 2
        self.windowSize1 = windowSize1 #Window Size for transaction 1.
        self.windowSize2 = windowSize2 #Window Size for transaction 2.
        self.throughput = throughput #Throughput
        self.awaitingSecond = awaitingSecond #Boolean that when switched on, will enable second ACK to be read.
        self.time = time #First packet sent. 
        self.push = push #Push = PSH read. 
class WindowSize:
    def __init__(self, arr, index, syn):
        self.arr = arr #Array containing window size. 
        self.index = index #Tells which index of array to be on.
        self.syn = syn #Initialized.
class RetransmissionCounter:
    def __init__(self, count, triple, currentseq, timeoutCount):
        self.count = count #Number of retransmits due to triple,
        self.triple = triple #Number of errors found. 
        self.currentseq = currentseq #Current Sequence Number. 
        self.timeoutCount = timeoutCount #Number of retransmits due to timeout.
f = open(FILENAME, 'rb') #You can only read bytes.
pcap = dpkt.pcap.Reader(f) #Read PCAP.
tcp_flows = [] #Will hold all TCP Flows.
time = 0 #Timestamp
for (ts, buf) in pcap:
    eth = dpkt.ethernet.Ethernet(buf)
    ip = eth.data  
    tcp = ip.data #eth.data.data
    if(time == 0):
        time = ts #Base Time
    if(tcp.flags == 2 and tcp.sport != 80): #SYN
        tcpFlow = TCPFlow(tcp.sport, SOURCE_IP, tcp.dport, DEST_IP, 0, 0, 0, 0, 0, 0, 0, False, ts, False) #Initialize tcpFlow with ports/IPs. Everything else needs to be filled in.
        tcp_flows.append(tcpFlow) #Add to array.
    elif(tcp.flags == 24 and tcp.sport != 80): #PSH + ACK
        for i in tcp_flows:
            if(i.sourcePort == tcp.sport):
                i.push = True #Initial handshake pushed. 
            else:
                continue
    elif(tcp.flags == 16 and tcp.sport != 80): #ACK
        for i in tcp_flows:
            if(i.sourcePort == tcp.sport and i.push):
                if(i.windowSize2 == 0 and i.seqNum2 == 0 and i.ackNum2 == 0 and i.awaitingSecond == True):
                    i.windowSize2 = tcp.win * ip.off #Window * Scale.
                    i.seqNum2 = tcp.seq
                    i.ackNum2 = tcp.ack
                    i.awaitingSecond = False
                if(i.windowSize1 == 0 and i.seqNum1 == 0 and i.ackNum1 == 0):
                    i.windowSize1 = tcp.win * ip.off #Window * Scale.
                    i.seqNum1 = tcp.seq
                    i.ackNum1 = tcp.ack
                    i.awaitingSecond = True
            else:
                continue
    elif(tcp.flags == 25 and tcp.sport != 80): #PSH + ACK + FIN
        for i in tcp_flows:
            if(i.sourcePort == tcp.sport):
                i.throughput = (tcp.seq - i.seqNum1) / ((ts - i.time) * 1000000)#Throughput = Difference in sequence numbers divided by time. Value is in MB/s
            else:
                continue
f.close()
print('Part A:\n')
print('Number of TCP Flows: ' + str(len(tcp_flows)))
print('\nSources: ')
for i in tcp_flows:
    print('\nSource Port: ' + str(i.sourcePort) + ' Source IP: ' + str(i.sourceIP)
    + ' Destination Port: ' + str(i.destPort) + ' Destination IP: ' + str(i.destIP)
    + ' Sequence Number 1: ' + str(i.seqNum1) + ' Sequence Number 2: ' + str(i.seqNum2) 
    + ' ACK Number 1: ' + str(i.ackNum1) + ' ACK Number 2: ' + str(i.ackNum2)
    + ' Window Size 1: ' + str(i.windowSize1) + ' Window Size 2: ' + str(i.windowSize2) 
    + ' Throughput: ' + str(i.throughput)) 
print('\nReceivers: ')
for i in tcp_flows:
    print('\nSource Port: ' + str(i.destPort) + ' Source IP: ' + str(i.destIP)
    + ' Destination Port: ' + str(i.sourcePort) + ' Destination IP: ' + str(i.sourceIP)
    + ' Sequence Number 1: ' + str(i.ackNum1) + ' Sequence Number 2: ' + str(i.ackNum2) 
    + ' ACK Number 1: ' + str(i.seqNum1) + ' ACK Number 2: ' + str(i.seqNum2)
    + ' Window Size 1: ' + str(i.windowSize1) + ' Window Size 2: ' + str(i.windowSize2) 
    + ' Throughput: ' + str(i.throughput)) 
#End of Part A. 
#Part B:
windowSizes = {} #For each element in tcp_flows, the corresponding window Size (itself an array).
retransmissionCounter = {} #Counter for TCP Retransmissions. 
tsSeq = {} #Timestamp and Sequence number combo. 
f = open(FILENAME, 'rb') #You can only read bytes.
pcap = dpkt.pcap.Reader(f) #Read PCAP again. 
rtt_estimate = 0 #Estimate RTT used for timeout. 
time = 0 #Timestamp used for starting window. 
for i in tcp_flows:
    windowSizes[i.sourcePort] = WindowSize([0] * (len(tcp_flows) + 1), 0, False)
    retransmissionCounter[i.sourcePort] = RetransmissionCounter(0, 0, 0, 0)
while(rtt_estimate == 0): #Setup RTT
    for (ts, buf) in pcap:
        eth = dpkt.ethernet.Ethernet(buf)
        ip = eth.data  
        tcp = ip.data #eth.data.data
        if(tcp.flags == 2 and time == 0):
            port = tcp.sport
            time = ts #Beginning.
        elif(tcp.flags == 18 and tcp.dport == port):
            rtt_estimate = ts - time #This will be the initialized RTT.
f.close()
f = open(FILENAME, 'rb') #You can only read bytes.
pcap = dpkt.pcap.Reader(f) #Read PCAP again. 
for (ts, buf) in pcap:
    eth = dpkt.ethernet.Ethernet(buf)
    ip = eth.data  
    tcp = ip.data #eth.data.data
    if(tcp.flags == 2):
        windowSizes[tcp.sport].syn = True
    if(tcp.sport != 80):
        if(ts - time > rtt_estimate): #You're at a new window. 
            for i in tcp_flows:
                if(windowSizes[i.sourcePort].syn):
                    windowSizes[i.sourcePort].index += 1
            time = ts #Update starting window.
        if(windowSizes[tcp.sport].index < 4): 
            temp = windowSizes[tcp.sport].arr
            temp[windowSizes[tcp.sport].index] += 1 #Add 1 to the number of packets being sent. 
            windowSizes[tcp.sport].arr = temp
        if(tcp.seq < retransmissionCounter[tcp.sport].currentseq): #Triple ACK checker. 
            retransmissionCounter[tcp.sport].triple += 1 #Add 1 to number of errors 
            if(retransmissionCounter[tcp.sport].triple == 3):
                retransmissionCounter[tcp.sport].count += 1 #Add 1 to number of retransmits.  
                retransmissionCounter[tcp.sport].triple = 0
        elif(tcp.seq > retransmissionCounter[tcp.sport].currentseq): #Else, update currentSeq.
            retransmissionCounter[tcp.sport].currentseq = tcp.seq
        tsSeq.update({tcp.seq : ts}) #Update seqNum and timestamp into dictionary. 
    elif(tcp.sport == 80 and tsSeq.get(tcp.ack) != None):
        if((ts - tsSeq.get(tcp.ack)) > (2 * rtt_estimate)):
            retransmissionCounter[tcp.dport].timeoutCount += 1 #Timeout occurs here.  
for i in windowSizes:
    windowSizes[i].arr.pop(0) #Remove first element of array (handshake)
print("\nPart B: \n")
print("Congestion Window Sizes: ")
for i in windowSizes:
    print("{} : {}".format(i,windowSizes[i].arr))
print("\nRetransmissions: ")
for i in windowSizes:
    print("{} : Triple ACK: {}, Timeout: {}".format(i, retransmissionCounter[i].count, retransmissionCounter[i].timeoutCount))

