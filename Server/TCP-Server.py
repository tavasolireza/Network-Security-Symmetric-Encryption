import socketserver
import file_encrypt as fien
from Crypto.Cipher import AES
import os
import datetime as dt


def read_physical_key():
    pswd = input("Enter physical key's password: ")
    fien.decrypt(fien.getKey(pswd), 'encrypted_initial_key.txt')
    initial_file = open('initial_key.txt', 'r')
    key_data = initial_file.read().rjust(32)
    initial_file.close()
    os.remove('initial_key.txt')
    return key_data


class ServerHandler(socketserver.BaseRequestHandler):
    session_key = ''
    counter = 0
    counter2 = 0
    enc_data = b''
    new_data = b''
    action = ''

    def handle(self):

        while True:
            self.data = b''
            self.new_data = b''
            self.data = self.request.recv(1024)
            try:
                self.action = self.data[:9].decode()
                if not (self.action.startswith('send')):
                    raise ValueError
                self.new_data = self.data[9:]
                self.enc_data = b''
                c_time = ' ' + str(dt.datetime.now()).split('.')[0]
            except (UnicodeDecodeError, ValueError):
                self.new_data = self.data

            finally:
                if self.action == 'send keys':
                    decipher = AES.new(read_physical_key().rjust(32), AES.MODE_ECB).decrypt(self.new_data)
                    self.session_key = decipher.decode().strip()
                elif self.action == 'send nkey':
                    print('#important#', self.new_data)
                    decipher = AES.new(fien.getKey(self.session_key), AES.MODE_ECB).decrypt(self.new_data)
                    self.session_key = decipher.decode().strip()
                    print('##server session key##' + self.session_key)
                elif self.action == 'send data':
                    self.enc_data += self.new_data
                    f = open('received__file' + c_time, 'wb')
                    f.write(self.enc_data)
                    f.close()
                    try:
                        fien.decrypt(fien.getKey(self.session_key), 'received__file' + c_time)
                        os.remove('received__file' + c_time)
                    except Exception as e:
                        os.remove('received__file' + c_time)
                elif self.action == 'send phys':
                    decipher = AES.new(fien.getKey(self.session_key), AES.MODE_ECB).decrypt(self.new_data)
                    decipher = decipher.decode().strip()
                    new_file = open('initial_key.txt', 'w')
                    new_file.write(decipher)
                    new_file.close()
                    pswd = input("Enter physical key's password: ")
                    fien.encrypt(fien.getKey(pswd), 'initial_key.txt')
                    # os.remove('initial_key.txt')
                    print('new physical key is', decipher)

            try:
                self.request.sendall("ACK from TCP Server".encode())
            except OSError:
                print('connection not found')


if __name__ == "__main__":
    HOST, PORT = "localhost", 8031

    tcp_server = socketserver.TCPServer((HOST, PORT), ServerHandler)

    tcp_server.serve_forever()
