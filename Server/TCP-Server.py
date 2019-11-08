import socketserver
import file_encrypt as fien
from Crypto.Cipher import AES


class Handler_TCPServer(socketserver.BaseRequestHandler):
    """
    The TCP Server class for demonstration.

    Note: We need to implement the Handle method to exchange data
    with TCP client.

    """

    def handle(self):
        while True:
            # self.request - TCP socket connected to the client
            self.data = self.request.recv(1024).strip()
            print(self.data)
            print(len(self.data))
            action = self.data[:8].decode()
            print(action)
            self.data = self.data[9:]
            print(self.data)
            decipher = AES.new('RezaTavasoli98'.rjust(32), AES.MODE_ECB).decrypt(self.data)
            print(decipher.strip())
            print("{} sent:".format(self.client_address[0]))
            print(self.data)
            # just send back ACK for data arrival confirmation
            self.request.sendall("ACK from TCP Server".encode())

    # # self.request - TCP socket connected to the client
    # self.data = self.request.recv(1024).strip()
    # print("{} sent:".format(self.client_address[0]))
    # print(self.data)
    # # just send back ACK for data arrival confirmation
    # self.request.sendall("ACK from TCP Server".encode())


if __name__ == "__main__":
    HOST, PORT = "localhost", 8001

    # Init the TCP server object, bind it to the localhost on 9999 port
    tcp_server = socketserver.TCPServer((HOST, PORT), Handler_TCPServer)

    # Activate the TCP server.
    # To abort the TCP server, press Ctrl-C.
    tcp_server.serve_forever()
