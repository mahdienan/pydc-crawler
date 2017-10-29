#   DCbot metadata crawler for forensic lab at TU Darmstadt.
#   2017 - Mahdi Enan and Florian Platzer

#   'connection.py' handles socket connections with server and clients.

import sys
import fcntl
import socket
import struct
import signal

from urllib2 import urlopen


class Connector():

    def __init__(self, logger):
        self.logger = logger
        self.sockets = {}
        self.sock = None  # server socket

        signal.signal(signal.SIGINT, self.signal_handler)

    def open_sock(self, host, port, nic):
        """Opens a socket to establish connection with hub.\n
        Args:
            host (string): Hub (Server) domain name or ip address.
            port (string): Hub (Server) port number.
            nic (stirng): The network interface card (depricated).
        Returns:
            A socket for client to server connection.
        """
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sockets['hub'] = [self.sock, self.get_public_ip()]
        try:
            self.sock.connect((host, port))
        except Exception:
            self.logger.display("No route to host: '{host}:{port}'".
                                format(host=host, port=port), "err")
            exit(0)
        self.logger.display("Connection established with '{host}/{port}'".
                            format(host=host, port=port), "ok")
        return self.sock

    def get_ip_address(self, nic):
        """Get the local ip address.\n
        Args:
            nic (string): The network interface card.\n
        Returns:
            The ip address using nic as interface.
        """
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        return socket.inet_ntoa(fcntl.ioctl(
            s.fileno(),
            0x8915,  # SIOCGIFADDR
            struct.pack('256s', nic[:15])
        )[20:24])

    def get_public_ip(self):
        """Get the public ip address using 'http://ip.42.pl/raw'.\n
        Returns:
            The public ip address.
        """
        return urlopen('http://ip.42.pl/raw').read()

    def signal_handler(self, signal, frame):
        """Signal handler to close the connection to the hub.\n
        Args:
            signal (signal): The signal.\n
            frame (frame): The frame.
        """
        self.sock.close()
        self.logger.display("Disconnected!", "warn")
        sys.exit(0)

    def direct_connect(self, user, cc_port):
        """Create a socket and listen for connections.\n
        As the name suggests, this function is essential to the protocol.\n
        Args:
            user (string): Username (unused).
            cc_port (stirng): The port that connecting user will use.\n
        Returns:
            clink (socket): The socket for client to client connection.
        """
        cc_sock = socket.socket(socket.AF_INET,
                                socket.SOCK_STREAM)
        cc_sock.setsockopt(socket.SOL_SOCKET,
                           socket.SO_REUSEADDR, 1)
        cc_sock.settimeout(1)
        cc_sock.bind(('', cc_port))
        cc_sock.listen(1)
        conn, addr = cc_sock.accept()
        self.sockets[user] = [conn, addr]
        self.logger.display("New connection with '{host}/{port}'".
                            format(host=addr[0], port=addr[1]), "ok")
        clink = self.sockets[user][0]
        return clink
