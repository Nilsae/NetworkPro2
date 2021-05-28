# #!/usr/bin/python3
# from socket import *
import json
import time
import matplotlib.pyplot as plt
import numpy as np
import re
import socket
import pyshark
t0 = time.time()
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

    # ret_capture = pyshark.LiveCapture(interface='lo', display_filter='tcp.analysis.retransmission')
    # ret_capture.sniff(timeout=50)
    # for packet in ret_capture.sniff_continuously(packet_count=1):
    #     print(packet.type)
    capture = pyshark.FileCapture('test.pcap', display_filter='tcp.analysis.retransmission')
    counter = 0
    for packet in capture:
        counter += 1
    num_retransmits= counter
    # num_retransmits_valid = len(ret_capture)

    mean_throughput = sum_throughput/len(data['intervals'])
    print("number of tcp retransmittions : ",num_retransmits)
    print("mean sender throughput : ", mean_throughput)
    # for packet in capture:
    plt.figure()
    plt.plot(time_list, rate_list)
    plt.xlabel('Time(sec)')
    plt.ylabel('throughput(bits/sec)')
    plt.grid()
    plt.show()