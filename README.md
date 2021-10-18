# CSE-310-Assignment-2
Attached is an analysis_pcap_tcp.py file and an assignment2.pcap file. 

# Running the Program
1. Run python analysis_pcap_cp.py in the folder containing the two files. 
2. If you wish to change settings, specifically the Source/Dest IP Addresses and the pcap file being used, those can be found in the first few lines of the Python file. 

# How Everything Was Calculated
• Number of TCP Flows, Source/Dest Port: Iterate through packets in assignment2.pcap. If the TCP flag is 2 (SYN), add 1 to the number of TCP Flows. You can also obtain Source/Dest Port through tcp.sport and tcp.dport respectively with a SYN. 
• Source/Dest IP: Hard Coded after looking through the pcap in Wireshark. 
• SEQ/ACK/Receive Window: For every TCP flow, first parse the initial handshake (TCP connection being setup here), before finding a TCP flag of 16 (ACK) and obtaining the first sequence number, ACK number, and window size through tcp.seq, tcp.ack, and tcp.win * ip.off (window * scale) respectively. Repeat for the second ACK. 
• Throughput: For every TCP flow, find a TCP flag of 25 (PSH + ACK + FIN). The throughput is defined as (tcp.seq - i.seqNum1) / ((ts - i.time) * 1000000), where tcp.seq is the FIN's sequence number, i.seqNum1 is the first sequence number of the port, ts is the current timestamp, and i.time is the time the first packet was read for the port. Note that we are dividing by 1000000 to ensure the final result is in MB/s. 
• RTT: This is technically not required, but it is very helpful for the following calculations. Define an rtt_estimate of 0. While the rtt_estimate is 0, find a TCP flag of 2 (SYN), and save the corresponding port and timestamp. Then find a TCP flag of 18 (SYN + ACK) along with a destination port corresponding to the saved port. The rtt_estimate is the difference between the timestamp of 18 and the timestamp of 2. 
• Congestion Window Sizes: For every TCP flow that does not have a source port of 80, first find the SYN, and the starting time (represents the start of the window). From there, add 1 to the window size for every packet read as long as the difference in current timestamp and starting time is less than the rtt_estimate. When current timestamp - starting time is greater than rtt_estimate, move to the next window (defined in an array) by adding 1 to the index. Also reset the starting time to the current timestamp to represent the new start of window. Do this 3 times to get the first 3 congestion window sizes. 
• Triple ACK Retransmissions: For every TCP flow that does not have a source port of 80, determine if the current sequence number is less than the previous sequence number. If so, add 1 to the number of errors. When that number hits 3, add 1 to the number of triple ACK retransmissions and reset the number of errors to 0. 
• Timeout: Save every packet that does not have a source port of 80 in a dictionary mapping sequence number to timestamp. For every packet whose source port is 80, determine if the difference in current timestamp and the dictionary timestamp is greater than 2 * rtt_estimate. If so, add 1 to the number of timeouts to the corresponding destination port. 
