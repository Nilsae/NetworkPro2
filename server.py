# # # import iperf3
# # #
# # # server = iperf3.Server()
# # # result = server.run()
# # # var =result.remote_host
# # # # "10.10.10.10"
# # # print(var)
# # from socket import *
# #
# # serverName = "127.0.0.1"
# # serverPort  = 12000
# # serverSocket =socket(AF_INET,SOCK_STREAM)
# # serverSocket.bind((serverName,serverPort))
# # serverSocket.listen(5)
# # print("the server is ready to receive")
# # while True:
# #     connectionSocket, addr = serverSocket.accept()
# #     sentense = connectionSocket.recv(1024).decode()
# #     capitaliazedSentense =sentense.upper()
# #     connectionSocket.send(capitaliazedSentense.encode())
# #     connectionSocket.close()
# #
# from socket import *
# import os
# # import socket
# import tqdm
# import time
# import ftplib
# from pprint import pprint
#
# help_Str= "\nCall one of the following functions:\nHELP            :show this help\nLIST            :list files\nPWD             :show current directory\nCD directory   :enter directory\nDWLD file_path  :download file\nQUIT            :exit"
# serverName = "127.0.0.1"
# serverPort  = 4040
# SEPERATOR = "            "
# serverSocket =socket(AF_INET,SOCK_STREAM)
# serverSocket.bind((serverName,serverPort))
# serverSocket.listen(5)
# connectionSocket, addr = serverSocket.accept()
# # # connectionSocket.send(help_z              Str.encode())
# # connectionSocket.send("Welcome to the FTP client\n".encode())
# # # connectionSocket.send(help_Str.encode())
# # sentense = connectionSocket.recv(1024).decode()
# # while sentense.upper()!="QUIT":
# #     # connectionSocket, addr = serverSocket.accept()
# #
# #     if sentense.upper()=="HELP":
# #         connectionSocket.send(help_Str.encode())
# #     elif sentense.upper()=="LIST":
# #         dirlist = os.listdir(os.getcwd())
# #         dirlist2=[]
# #         for obj in dirlist:
# #             objsize = os.path.getsize(obj)
# #             dirlist2.append(f"{obj}{SEPERATOR}{objsize}{' bytes'}")
# #         # dir_str=str(dirlist).strip('[]')
# #         connectionSocket.send(('\n'.join(dirlist2)).encode())
# #     elif sentense.upper()=="PWD":
# #         connectionSocket.send( os.getcwd().encode())
# #     elif sentense.upper().startswith('CD'):
# #         list = sentense.split(" ")
# #         dir_to_cd=list[1]
# #         os.chdir(dir_to_cd)
# #         connectionSocket.send( os.getcwd().encode())
# #     elif sentense.upper().startswith('DWLD'):
# #         list=sentense.split(" ")
# #         file_to_dwld=list[1]
# #         dirlist = os.listdir(os.getcwd())
# #         dir_str = str(dirlist).strip('[]')
# #         if not dir_str.find(file_to_dwld):
# #             connectionSocket.send(("file not found!").encode())
# #         else:
# #             filesize = os.path.getsize(file_to_dwld)
# #             connectionSocket.send(f"{file_to_dwld}{SEPERATOR}{filesize}".encode())
# #             progress = tqdm.tqdm(range(filesize), f"Sending {file_to_dwld}", unit="B", unit_scale=True, unit_divisor=1024)
# #             t= filesize/1024
# #             t=int(t)+1
# #             with open(file_to_dwld, "rb") as f:
# #                 rep=0
# #                 # while True:
# #                 #     rep=rep+1
# #                     # read the bytes from the file
# #                 bytes_read = f.read(1024)
# #                 connectionSocket.sendall(bytes_read)
# #                 for i in range(2000):
# #                     if not bytes_read:
# #                         connectionSocket.send(f"{'transition of file '}{file_to_dwld}{' complete'}".encode())
# #                         break
# #                     # update the progress bar
# #                     time.sleep(0.002)
# #                     progress.update(len(bytes_read))
# #                 break
# #         connectionSocket.send(f"{'transition of file '}{file_to_dwld}{' complete'}".encode())
# #
# #     elif sentense.upper()=="QUIT":
# #         connectionSocket.send("Exiting the server".encode())
# #         connectionSocket.close()
# #     else:
# #         connectionSocket.send("command not found".encode())
# #     sentense = connectionSocket.recv(1024).decode()
