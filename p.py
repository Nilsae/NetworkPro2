# #!/usr/bin/python3
# from socket import *
import json
import time
import matplotlib.pyplot as plt
import numpy as np
import re
# sockobj = socket(AF_INET, SOCK_STREAM)
# sockobj.bind(('', 5000))
# sockobj.listen(10)
#
# while True:
#     conn_sock, client_address = sockobj.accept()
#     print('client connected')
#     while True:
#         message = conn_sock.recv(24000)
#         if not message: break
#         print("message received")
#         print("The sent message is: ", message.decode())
import socket
import pyshark


#create an INET, raw socket
# s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
# # receive a packet
# while True:
#   print(s.recvfrom(65565))
# capture = pyshark.LiveCapture(interface='ens33')
# capture.sniff(timeout=5)
# for packet in capture._packets()
#   print('Just arrived:{}'.format(packet))
# count_packets = 0
t0 = time.time()
# capture = pyshark.LiveCapture(interface='en1')
# , display_filter='tcp.analysis.fast_retransmission'
# capture.sniff(timeout=50)
#
# for packet in capture.sniff_continuously():
# #   # print ('Just arrived:', packet)
#   count_packets=count_packets+1
#   t1 = time.time()
#   total = t1-t0
#   if(total>100):
#       break
#   print("m_m")
#
# # import pyshark
# cap = pyshark.FileCapture(filename)
# for packet in cap:


timeout=50
interface='lo'
bpf_filter=None
display_filter="tcp.port == 4040"
tshark_path=None
output_file=None


capture_output = []
if interface is None:
    raise Exception("Please provide the interface used.")
else:
    capture_all = pyshark.LiveCapture(
        interface=interface,
        bpf_filter=bpf_filter,
        tshark_path=tshark_path,
        output_file=output_file,
    )
    capture_all.sniff(timeout=timeout)
    num_of_packets = len(capture_all)
    # return capture, length
    print('number of captured packets =',num_of_packets)
    f = open('file.json', )
    data = json.load(f)
    num_retransmits = data['intervals'][0]['sum']['retransmits']
    sum_throughput=0
    time_list = []
    rate_list = []
    for i in range(len(data['intervals'])):
        s_throughput = data['intervals'][i]['sum']['bits_per_second']
        sum_throughput=sum_throughput+s_throughput
        rate_list.append(s_throughput)
        time_list.append( data['intervals'][i]['sum']['end'])

    ret_capture = pyshark.LiveCapture(interface='lo', display_filter='tcp.analysis.retransmission')
    ret_capture.sniff(timeout=50)
    # for packet in ret_capture.sniff_continuously(packet_count=num_of_packets):
    num_retransmits_valid = len(ret_capture)

    mean_throughput = sum_throughput/len(data['intervals'])
    print("number of tcp retransmittions : ",num_retransmits_valid)
    print("mean sender throughput : ", mean_throughput)
    # for packet in capture:



     # iperf-log.txt is the iperf log file name
    # row_data = f.readlines()  # Read each line of the iperf log file into a list
    # for line in row_data:  # Use regular expressions for matching, and the matching content can be changed according to the actual situation
    #     time = re.findall(r"-(.*) sec", line)
    #     rate = re.findall(r"MBytes  (.*) Mbits", line)
    #     if (len(time) > 0):  # Store the data when there is throughput and time data in the current row
    #         print(time)
    #         time_list.append(float(time[0]))
    #         rate_list.append(float(rate[0]))

    plt.figure()
    plt.plot(time_list, rate_list)
    plt.xlabel('Time(sec)')
    plt.ylabel('throughput(bits/sec)')
    plt.grid()
    plt.show()