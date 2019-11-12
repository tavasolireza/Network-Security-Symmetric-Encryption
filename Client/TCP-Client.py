import socket
import file_encrypt as fien
import os
from Crypto.Cipher import AES
import threading
import datetime

data = ''
enc_session_key, orig_session_key = '', ''
physical_key = ''
s_time = datetime.datetime.now()
f_time = datetime.datetime.now()

host_ip, server_port = "127.0.0.1", 8031
# data = " Hello how are you?\n"

# Initialize a TCP client socket using SOCK_STREAM
tcp_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM, )


def create_new_session_key(pswd):
    # pswd = input("Enter physical key's password: ")
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


def expire_session_key():
    print("Session key has expired.")


# timer = threading.Timer(2.0, gfg)
# timer.start()
def key_exchange(p_key):
    encrypted_session_key, original_session_key = create_new_session_key(p_key)
    original_session_key = original_session_key.decode().strip()
    sent_data = b'send keys' + encrypted_session_key
    return sent_data, original_session_key


def data_exchange(session_key):
    sent_data = b'send data'
    file = input('Enter filename:\n')
    fien.encrypt(fien.getKey(session_key), file)
    enc_file_name = 'encrypted_' + file
    f = open(enc_file_name, 'rb')
    encrypted_file = f.read()
    f.close()
    sent_data += encrypted_file
    return sent_data


def decrypt_physical_key():
    pswd = input("Enter physical key's password: ")
    return pswd


def exchange_new_key(pre_session_key):
    sent_data = b'send nkey'
    print('Session key expired')
    new_key = input("Enter new session key: ")
    new_key = new_key.encode().rjust(32)
    cipher = AES.new(fien.getKey(pre_session_key), AES.MODE_ECB).encrypt(new_key)
    sent_data += cipher
    return sent_data, new_key.decode().strip()


# timer = threading.Timer(20.0, expire_session_key)
try:
    physical_key = decrypt_physical_key()
    s_time = datetime.datetime.now()
    # timer = threading.Timer(10.0, gfg)
    # timer.start()

    # Establish connection to TCP server and exchange data
    tcp_client.connect((host_ip, server_port))
    enc_session_key, orig_session_key = '', ''

    while True:
        data = ''
        f_time = datetime.datetime.now()
        if (f_time - s_time).total_seconds() > 15:
            print('yes')
            data, orig_session_key = exchange_new_key(orig_session_key)
            s_time = datetime.datetime.now()
        else:
            print('----------+----------+----------')
            choose_action = input('Type \'n\' to start new session:\nType \'d\' to send data:\n')
            if choose_action == 'n':
                data, orig_session_key = key_exchange(physical_key)
            elif choose_action == 'd':
                data = data_exchange(orig_session_key)

        # print('----------+----------+----------')
        # choose_action = input('Type \'n\' to start new session:\nType \'d\' to send data:\n')

        # if choose_action == 'n':
        #     # enc_session_key, orig_session_key = create_new_session_key()
        #     # orig_session_key = orig_session_key.decode().strip()
        #     # data = b'send keys' + enc_session_key
        #     data, orig_session_key = key_exchange(physical_key)
        #
        # elif choose_action == 'd':
        #     data = data_exchange(orig_session_key)
        #     # data = b'send data'
        #     # file_name = input('Enter filename:\n')
        #     # # print('this is session key', orig_session_key)
        #     # fien.encrypt(fien.getKey(orig_session_key), file_name)
        #     # enc_file_name = 'encrypted_' + file_name
        #     # f = open(enc_file_name, 'rb')
        #     # # print(f.read())
        #     # encrypted_file = f.read()
        #     # f.close()
        #     # data += encrypted_file
        # print('this is data:    ', data)
        print(data)
        tcp_client.sendall(data)

        received = tcp_client.recv(1024)
        # print("Bytes Sent:     {}".format(data))
        print("Bytes Received: {}".format(received.decode()))

finally:
    tcp_client.close()
