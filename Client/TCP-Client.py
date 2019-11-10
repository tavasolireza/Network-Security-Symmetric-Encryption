import socket
import file_encrypt as fien
import os
from Crypto.Cipher import AES

host_ip, server_port = "127.0.0.1", 8002
# data = " Hello how are you?\n"

# Initialize a TCP client socket using SOCK_STREAM
tcp_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM, )


def create_new_session_key():
    pswd = input("Enter physical key's password: ")
    new_key = input("Enter new session key: ")
    new_key = new_key.encode().rjust(32)
    # print(len(new_key))
    fien.decrypt(fien.getKey(pswd), 'encrypted_initial_key.txt')
    initial_file = open('initial_key.txt', 'r')
    key_data = initial_file.read().rjust(32)
    cipher = AES.new(key_data, AES.MODE_ECB).encrypt(new_key)
    initial_file.close()
    os.remove('initial_key.txt')
    return cipher, new_key


try:
    # Establish connection to TCP server and exchange data
    tcp_client.connect((host_ip, server_port))
    enc_session_key, orig_session_key = '', ''

    while True:
        data = ''
        print('----------+----------+----------')
        choose_action = input('Type \'n\' to start new session:\nType \'d\' to send data:\n')
        if choose_action == 'n':
            enc_session_key, orig_session_key = create_new_session_key()
            orig_session_key = orig_session_key.decode().strip()
            data = b'send keys' + enc_session_key

        elif choose_action == 'd':
            data = b'send data'
            file_name = input('Enter filename:\n')
            # print('this is session key', orig_session_key)
            fien.encrypt(fien.getKey(orig_session_key), file_name)
            enc_file_name = 'encrypted_' + file_name
            f = open(enc_file_name, 'rb')
            # print(f.read())
            encrypted_file = f.read()
            f.close()
            data += encrypted_file
        # print('this is data:    ', data)
        tcp_client.sendall(data)
        received = tcp_client.recv(1024)
        # print("Bytes Sent:     {}".format(data))
        print("Bytes Received: {}".format(received.decode()))

finally:
    tcp_client.close()
