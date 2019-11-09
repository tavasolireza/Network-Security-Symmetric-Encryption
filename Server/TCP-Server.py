import socketserver
import file_encrypt as fien
from Crypto.Cipher import AES


class Handler_TCPServer(socketserver.BaseRequestHandler):
    session_key = ''
    """
    The TCP Server class for demonstration.

    Note: We need to implement the Handle method to exchange data
    with TCP client.

    """

    def handle(self):

        while True:
            # self.request - TCP socket connected to the client
            self.data = self.request.recv(1024).strip()
            action = self.data[:9].decode()
            print('this is action', action)
            if action == 'send keys':
                self.data = self.data[9:]
                # print(len(self.data))
                decipher = AES.new('RezaTavasoli98'.rjust(32), AES.MODE_ECB).decrypt(self.data)
                self.session_key = decipher.decode().strip()
                print(self.session_key, '112222233333333333')
                print("{} sent:".format(self.client_address[0]))
            elif action == 'send data':
                self.data = self.data[9:]
                f = open('received_file', 'wb')
                f.write(self.data)
                print(self.data)
                f.close()
                print('this is session key', self.session_key)
                fien.decrypt(fien.getKey(self.session_key), 'received_file')

            self.request.sendall("ACK from TCP Server".encode())


if __name__ == "__main__":
    HOST, PORT = "localhost", 8032

    # Init the TCP server object, bind it to the localhost on 9999 port
    tcp_server = socketserver.TCPServer((HOST, PORT), Handler_TCPServer)

    # Activate the TCP server.
    # To abort the TCP server, press Ctrl-C.
    tcp_server.serve_forever()
