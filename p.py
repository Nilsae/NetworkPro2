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
    print('number of captured packets =',num_of_packets)
    f_sender = open('sender.json', )
    data = json.load(f_sender)

    sum_throughput_sender=0
    time_list_sender = []
    rate_list_sender = []
    for i in range(len(data['intervals'])):
        s_throughput = data['intervals'][i]['sum']['bits_per_second']
        sum_throughput_sender=sum_throughput_sender+s_throughput
        rate_list_sender.append(s_throughput)
        time_list_sender.append( data['intervals'][i]['sum']['end'])
    capture = pyshark.FileCapture('receiver.txt', display_filter='tcp.analysis.retransmission')
    counter = 0
    for packet in capture:
        counter += 1
    num_retransmits= counter

    mean_throughput_sender = sum_throughput_sender/len(data['intervals'])
    print("number of tcp retransmittions : ",num_retransmits)
    print("mean sender throughput : ", mean_throughput_sender)
    plt.figure()
    plt.plot(time_list_sender, rate_list_sender)
    plt.xlabel('Time(sec)')
    plt.ylabel('throughput(bits/sec)')
    plt.grid()
    plt.show()
    #
    sum_throughput_receiver=0
    time_list_receiver = []
    rate_list_receiver = []
    with open('receiver.txt', 'r') as f_receiver:  # iperf-log.txt is the iperf log file name
        row_data = f_receiver.readlines()  # Read each line of the iperf log file into a list
        for line in row_data:  # Use regular expressions for matching, and the matching content can be changed according to the actual situation
            time = re.findall(r"-(.*) sec", line)
            rate = re.findall(r"MBytes (.*) Gbits", line)
            if (len(time) > 0):
                time_list_receiver.append(float(time[0]))
                # rate_list_receiver.append(float(rate[0]))
                rate_list_receiver.append(5.00)
    # for i in range(len(data['intervals'])):
    #     r_throughput = data['intervals'][i]['sum']['bits_per_second']
    #     sum_throughput_receiver=sum_throughput_receiver+r_throughput
    #     rate_list_receiver.append(r_throughput)
    #     time_list_receiver.append( data['intervals'][i]['sum']['end'])
    # plt.figure()
    # plt.plot(time_list_receiver, rate_list_receiver)
    # plt.xlabel('Time(sec)')
    # plt.ylabel('throughput(Mbits/sec)')
    # plt.grid()
    # plt.legend(["Sender", "Receiver"])
    # plt.show()