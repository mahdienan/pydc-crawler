#   DCbot metadata crawler for forensic lab at TU Darmstadt.
#   2017 - Mahdi Enan and Florian Platzer

#   'protocol.py' implements the direct connect commands

import sys
import socket


class DC():

    def __init__(self, logger, connector, BUFFER_SIZE, args, coupler):
        self.dcbot = coupler
        self.logger = logger
        self.connector = connector
        self.BUFFER_SIZE = BUFFER_SIZE
        self.nick = args['nick']
        self.supports = "UserCommand UserIP2 TTHSearch GetZBlock"

    def calculate_key(self, lock):
        """Implemented on the basis of information from
        Measurement and Analysis of Direct Connect Peer-to-Peer
        File Sharing Network by Karl Molin.\n
        Args:
            lock (string): The calculated lock.\n
        Returns:
            the calculated key.
        """
        lock = [ord(c) for c in lock]
        key = [0]
        for i in range(1, len(lock)):
            key.append(lock[i] ^ lock[i - 1])
        key[0] = lock[0] ^ lock[len(lock) - 1] ^ lock[len(lock) - 2] ^ 5
        # Swap every nibble (4 bits) for every char in the key
        for i in range(len(lock)):
            key[i] = ((key[i] << 4) & 240 | (key[i] >> 4) & 15)
        # There are some forbidden ASCII schars: 0, 5, 36, 96, 124, 126
        # Substitute it with the string: /%DCN0<0|5|36|96|124|126>%/
        result = ""
        for c in key:
            if c in [0, 5, 36, 96, 124, 126]:
                result += "/%%DCN%.3i%%/" % c
            else:
                result += chr(c)
        return result

    def get_key(self, data, sock):
        """Get servers lock from the whole server answer.\n
        Return:
            The calculated key.

        """
        x = data.split()
        key = ""
        if(x[0] == "$Lock"):
            key = self.calculate_key(x[1])
        else:
            self.logger.display("Failed to aquire lock, exiting!", "err")
            sock.close()
            sys.exit(0)
        return key

    def handshake_c2s(self, sock):
        """Handshake between client and hub to establish a connection\n
        Args:
            sock (socket): Server connection socket.

        """
        lock = sock.recv(self.BUFFER_SIZE)
        self.logger.display("Received lock from server.", "recv")
        key = self.get_key(lock, sock)
        payload = "$Key " + key + "|" + \
                  "$ValidateNick {nick}|".format(nick=self.nick)
        if self.supports is not None:
                payload = "$Supports {supports} |" \
                          .format(supports=self.supports) + payload
        sock.send(payload)
        self.logger.display("Sending supported functions.", "sent")
        sock.settimeout(5)
        recv_hello = sock.recv(self.BUFFER_SIZE)
        self.logger.display("Received hello message from server.", "mesg")
        self.handle_response_restrictions(recv_hello)

        self.send_infos(sock)
        recv_shake = sock.recv(self.BUFFER_SIZE)
        self.handle_response_restrictions(recv_shake)
        self.logger.display("Success in performing handshake with server.", "mesg")
        self.handle_response_restrictions(recv_shake)

    def handle_response_restrictions(self, message):
        """Handle restrictions displayed in the hello response message
        uses blacklisting because now standard was specified.\n
        Args:
            message (string): The message to be checked.
        """
        if "$ForceMove" in message:
            redirect = message.split("$")[1].split(" ")[1].split("|")[0]
            host, port = redirect.split(":")
            self.logger.display("Redirecting to: " + host + ".", "warn")
            self.dcbot.reconnect(host, port)
        if "Max unlimited share" in message:
            self.logger.display("This server requires registered users!",
                                "warn")
            self.logger.display("exiting.", "warn")
            exit(0)
        if "only for registered users" in message:
            self.logger.display("This server requires registered users!",
                                "warn")
            self.logger.display("exiting.", "warn")
            exit(0)
        if "but minimum allowed is" in message or \
           "A da bi prestupili na hub" in message:
            self.logger.display("This server requires more sharing!", "warn")
            self.logger.display("exiting.", "warn")
            exit(0)
            # it would be nice to increase the share dynamically then reconnect
        if "Searching and downloading is disabled" in message:
            self.logger.display("Searching and downloading is disabled",
                                "warn")
            self.logger.display("exiting", "warn")
            exit(0)

    def handshake_c2c(self, user, clink):
        """Handshake between client and client to establish a P2P connection.\n
        Args:
            user (string): Username.
            clink (socket): Socket for user to user connection.
        """
        re = self.connector.sockets[user][0].recv(self.BUFFER_SIZE)
        lock = re.split('|')[1] + '|'
        shakestart = "$MyNick {}|"\
                     "$Lock EXTENDEDPROTOCOLABCABCABCABCABCABC "\
                     "Pk=DCPLUSPLUS0.865ABCABC|".format(self.nick)
        supports = "$Supports MiniSlots XmlBZList ADCGet TTHL TTHF ZLIG|"
        direction = "$Direction Download 32766|"
        key = "$Key " + self.get_key(lock, clink) + "|"

        clink.send(shakestart + supports + direction + key)

        clink.recv(self.BUFFER_SIZE)
        self.logger.display("Received handshake response.", "recv")

    def send_infos(self, sock):
        """Send the Client version to the connected Hub. Default version is 1.0091.\n
        Args:
            sock (socket): User to Server socket connection.
        """
        msg = "$Version 1.0091|" + \
              "$MyINFO $ALL {nick} ".format(nick=self.nick) + \
              "<pyDC V:1,M:A,H:0/1/0,S:2>$ " + \
              "$100{flag}$".format(flag=chr(1)) + \
              "${size}".format(size=1073741824) + \
              "$|$GetNickList|"
        try:
            sock.send(msg)
        except socket.error as e:
            print e
        self.logger.display("Sending bot information.", "sent")

    def connect_to_me(self, sock, user, ip, cc_port):
        """ Send the ConnectToMe command to as user to connection to created socket.\n
        Args:
            sock (socket): Server connection socket.
            user (stirng): Name of the user that is asked to connect.
            ip (string): crawler ip
            cc_port: (socket): crawlers c2c socket.
        """
        payload = "$ConnectToMe {} "\
            "{}:{}|".format(user, ip, cc_port)
        self.logger.display("Sending connection request to {}.".format(user), "sent")
        sock.send(payload)
