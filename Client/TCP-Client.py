import socket
import file_encrypt as fien
import os
from Crypto.Cipher import AES

host_ip, server_port = "127.0.0.1", 8001
# data = " Hello how are you?\n"

# Initialize a TCP client socket using SOCK_STREAM
tcp_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM, )


def create_new_session_key():
    pswd = input("Enter physical key's password ")
    new_key = input("Enter new session key")
    new_key = new_key.encode().rjust(32)
    fien.decrypt(fien.getKey(pswd), 'encrypted_initial_key.txt')
    f = open('initial_key.txt')
    key_data = f.read().rjust(32)
    cipher = AES.new(key_data, AES.MODE_ECB).encrypt(new_key)
    f.close()
    os.remove('initial_key.txt')
    return cipher


try:
    # Establish connection to TCP server and exchange data
    tcp_client.connect((host_ip, server_port))
    # pswd = input("Enter physical key's password ")
    # new_key = input("Enter new session key")
    # new_key = new_key.encode().rjust(32)
    # fien.decrypt(fien.getKey(pswd), 'encrypted_initial_key.txt')
    # f = open('initial_key.txt')
    # key_data = f.read().rjust(32)
    # cipher = AES.new(key_data, AES.MODE_ECB).encrypt(new_key)
    # f.close()
    # os.remove('initial_key.txt')
    while True:
        data = ''
        session_key = ''
        choose_action = input('Enter e to start new session\nEnter d to send data\n')
        if choose_action == 'e':
            session_key = create_new_session_key()
            data = b'send keys' + session_key

        elif choose_action == 'd':
            pass
        tcp_client.sendall(data)
        received = tcp_client.recv(1024)
        print("Bytes Sent:     {}".format(data))
        print("Bytes Received: {}".format(received.decode()))
    # data = cipher
    # tcp_client.sendall(data)
    # received = tcp_client.recv(1024)
    # print("Bytes Sent:     {}".format(data))
    # print("Bytes Received: {}".format(received.decode()))
    # while True:
    #     data = input('eeeennnnter: ').rjust(16)
    #     tcp_client.sendall(data.encode())
    #     received = tcp_client.recv(1024)
    #     print("Bytes Sent:     {}".format(data))
    #     print("Bytes Received: {}".format(received.decode()))

    # Read data from the TCP server and close the connection

finally:
    tcp_client.close()

# try:
#     # Establish connection to TCP server and exchange data
#     tcp_client.connect((host_ip, server_port))
#     tcp_client.sendall(data.encode())
#
#     # Read data from the TCP server and close the connection
#     received = tcp_client.recv(1024)
# finally:
#     tcp_client.close()
#
# print("Bytes Sent:     {}".format(data))
# print("Bytes Received: {}".format(received.decode()))
