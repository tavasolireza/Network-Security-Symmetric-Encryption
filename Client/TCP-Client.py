import socket
import file_encrypt as fien
import os
from Crypto.Cipher import AES
import datetime

data = ''
enc_session_key, orig_session_key = '', ''
physical_key = ''
s_time = datetime.datetime.now()
f_time = datetime.datetime.now()

host_ip, server_port = "127.0.0.1", 8034

tcp_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM, )

username = input('Username: ')


def create_new_session_key(pswd):
    new_key = input("Enter new session key: ")
    new_key = new_key.encode().rjust(32)
    fien.decrypt(fien.getKey(pswd), 'encrypted_initial_key.txt')
    initial_file = open('initial_key.txt', 'r')
    key_data = initial_file.read().rjust(32)
    cipher = AES.new(key_data, AES.MODE_ECB).encrypt(new_key)
    initial_file.close()
    # os.remove('initial_key.txt')
    return cipher, new_key


def expire_session_key():
    print("Session key has expired.")


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
    print('## Session key expired ##')
    new_key = input("Enter new session key: ")
    new_key = new_key.encode().rjust(32)
    cipher = AES.new(fien.getKey(pre_session_key), AES.MODE_ECB).encrypt(new_key)
    sent_data += cipher
    return sent_data, new_key.decode().strip()


try:

    physical_key = decrypt_physical_key()
    s_time = datetime.datetime.now()
    tcp_client.connect((host_ip, server_port))
    enc_session_key, orig_session_key = '', ''
    tcp_client.sendall(b'send user' + username.encode())

    while True:
        data = ''
        f_time = datetime.datetime.now()
        if (f_time - s_time).total_seconds() > 15:
            data, orig_session_key = exchange_new_key(orig_session_key)
            s_time = datetime.datetime.now()
        else:
            print('----------+----------+----------')
            choose_action = input('Type \'n\' to start new session, \'d\' to send data, \'e\' to end connection.\n')
            if choose_action == 'e':
                raise ConnectionError
            if choose_action == 'n':
                data, orig_session_key = key_exchange(physical_key)
            elif choose_action == 'd':
                data = data_exchange(orig_session_key)

        print(data)
        tcp_client.sendall(data)

        received = tcp_client.recv(1024)
        print("Bytes Received: {}".format(received.decode()))
except ConnectionError:
    inp = input('Enter new physical key')
    f = open('initial_key.txt', 'w')
    f.write(inp)
    f.close()
    pswd = input("Enter physical key's password: ")
    fien.encrypt(fien.getKey(pswd), 'initial_key.txt')
    # os.remove('initial_key.txt')
    cipher = AES.new(fien.getKey(orig_session_key), AES.MODE_ECB).encrypt(inp.rjust(32))
    new_data = b'send phys' + cipher
    tcp_client.send(new_data)
    print('connection closed!!!')

finally:
    tcp_client.close()
