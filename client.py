# # import iperf3
# #
# # client = iperf3.Client()
# # client.duration = 1
# # client.server_hostname = '127.0.0.1'
# # client.port = 4040
# # result = client.run()
# # # var = result.sent_Mbps
# # # var1 = result.
# # # 32583.293914794922
# #
# # # print(var)
# from socket import *
#
# serverName = "127.0.0.1"
# serverPort = 12000
# clientSocket =socket(AF_INET,SOCK_STREAM)
# clientSocket.connect((serverName,serverPort))
# sentense = input("Input:")
# clientSocket.send(sentense.encode())
# modifiedSentense=clientSocket.recv(1024)
# print("from tcp server:",modifiedSentense.decode())
# clientSocket.close()
from socket import *
import tqdm
import time
serverName = "127.0.0.1"
serverPort = 4040
clientSocket =socket(AF_INET,SOCK_STREAM)
clientSocket.connect((serverName,serverPort))
SEPERATOR = "            "
ans = clientSocket.recv(1024)
print(ans.decode())
sentense = input()
while sentense.upper()!="QUIT":

    clientSocket.send(sentense.encode())
    ans = clientSocket.recv(1024)

    if sentense.upper().startswith("DWLD"):
        print("dwld")
        filename,filesize=(ans.decode()).split(SEPERATOR)
        filesize=int(filesize)
        progress = tqdm.tqdm(range(filesize), f"Receiving {filename}", unit="B", unit_scale=True, unit_divisor=1024)
        list=sentense.split(" ")
        filename=list[1]
        t= filesize/1024
        t=int(t)+1
        with open(filename, "wb") as f:
            for ii in range(t):
    #             # read 1024 bytes from the socket (receive)
                bytes_read = clientSocket.recv(1024)
                if not bytes_read:
                    # nothing is received
                    # file transmitting is done
                    break
                # write to the file the bytes we just received
                f.write(bytes_read)
                # update the progress bar
                for i in range(2000):
                    time.sleep(0.002)
                    progress.update(len(bytes_read))
                    # if not bytes_read:
                    #     ans = clientSocket.recv(1024)
                    #     print(ans.decode())



        ans = clientSocket.recv(1024)
        print(ans.decode())
        break

                    # update the progress bar
                # if not bytes_read:
                #     ans = clientSocket.recv(1024)
                #     print(ans.decode())
                #     break


    else:
        print(ans.decode())
    sentense = input()



    # print("from tcp server:",ans.decode())

clientSocket.close()
