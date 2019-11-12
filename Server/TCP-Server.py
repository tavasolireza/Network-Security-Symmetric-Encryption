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


class Handler_TCPServer(socketserver.BaseRequestHandler):
    session_key = ''
    counter = 0
    counter2 = 0
    enc_data = b''
    new_data = b''
    action = ''
    """
    The TCP Server class for demonstration.

    Note: We need to implement the Handle method to exchange data
    with TCP client.

    """

    def handle(self):

        while True:
            self.data = b''
            self.new_data = b''
            # self.request - TCP socket connected to the client
            self.data = self.request.recv(1024)
            # print(self.data)
            # print('first counter: ', self.counter2)
            try:
                self.action = self.data[:9].decode()
                if not (self.action.startswith('send')):
                    raise ValueError
                # print('how many times i came here')
                self.new_data = self.data[9:]
                self.enc_data = b''
                c_time = ' ' + str(dt.datetime.now()).split('.')[0]
            except (UnicodeDecodeError, ValueError):
                self.new_data = self.data

            finally:
                if self.action == 'send keys':
                    # self.data = self.data[9:]
                    # print(len(self.data))
                    decipher = AES.new(read_physical_key().rjust(32), AES.MODE_ECB).decrypt(self.new_data)
                    self.session_key = decipher.decode().strip()
                    # print(self.session_key, '112222233333333333')
                    # print("{} sent:".format(self.client_address[0]))
                elif self.action == 'send nkey':
                    print('#important#', self.new_data)
                    decipher = AES.new(fien.getKey(self.session_key), AES.MODE_ECB).decrypt(self.new_data)
                    self.session_key = decipher.decode().strip()
                    print('##server session key##'+self.session_key)
                elif self.action == 'send data':
                    # print('second counter: ', self.counter)
                    self.enc_data += self.new_data
                    f = open('received__file' + c_time, 'wb')
                    f.write(self.enc_data)
                    f.close()
                    try:
                        fien.decrypt(fien.getKey(self.session_key), 'received__file' + c_time)
                        os.remove('received__file' + c_time)
                    except Exception as e:
                        os.remove('received__file' + c_time)

                    # self.data = self.data[9:]
                    # f = open('received_file', 'ab')
                    # f.write(self.data)
                    # print(self.data)
                    # f.close()
                    # print('this is session key', self.session_key)
                    # fien.decrypt(fien.getKey(self.session_key), 'received_file')

            self.request.sendall("ACK from TCP Server".encode())
            # print('encoded data is', self.enc_data)


if __name__ == "__main__":
    HOST, PORT = "localhost", 8031

    # Init the TCP server object, bind it to the localhost on 9999 port
    tcp_server = socketserver.TCPServer((HOST, PORT), Handler_TCPServer)

    # Activate the TCP server.
    # To abort the TCP server, press Ctrl-C.
    tcp_server.serve_forever()
