# #!/usr/bin/python3
# from socket import *
import json
import time
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
    capture = pyshark.LiveCapture(
        interface=interface,
        bpf_filter=bpf_filter,
        tshark_path=tshark_path,
        output_file=output_file,
    )
    capture.sniff(timeout=timeout)
    length = len(capture)
    # return capture, length
    print('number of captured packets =',length)
    f = open('file.json', )
    data = json.load(f)
    num_retransmits = data['intervals'][0]['sum']['retransmits']
    print("number of tcp retransmittions : ",num_retransmits)
    # for packet in capture:
