#!/usr/bin/env python
# -*- coding: utf-8 -*-
#   DCbot metadata crawler for forensic lab at TU Darmstadt.
#   2017 - Mahdi Enan and Florian Platzer

import os
import bz2
import sys
import math
import time
import zlib
import uuid
import errno
import fcntl
import socket
import hashlib
import argparse
import settings
import threading

from datetime import datetime
from utils.connection import Connector
from utils.protocol import DC
from utils.logs import Logger


class DCbot:

    # default values
    nick = "defaultNickname"
    verbose = False
    nic = "tun0"  # Network device; eth0, enp0s3, wlp3s0, ...
    user_count = 0  # number of user lists fetched

    def __init__(self):
        """Implement main functionality
            * parse arguments.
            * create logging instance.
            * create connction instance.
            * create model (dc) instance.
            * create server conneciton socket.
            * perform handshake with server.
            * fetch userlist.
            * traversere users and retrieve information.
        """
        if not os.path.exists(settings.TMP_FOLDER):
            os.makedirs(settings.TMP_FOLDER)
        if not os.path.exists('debug/'):
            os.makedirs('debug/')

        self.parse_args()

        self.logger = Logger(self.verbose, True)
        self.connection = Connector(self.logger)
        self.dc = DC(self.logger,
                     self.connection,
                     settings.BUFFER_SIZE,
                     dict([("nick", self.nick)]),
                     self)

        self.sock = self.connection.open_sock(self.host, self.port, self.nic)
        self.dc.handshake_c2s(self.sock)

        userlist, rawlist = self.fetch_users(self.sock)

        if userlist is not None or userlist is not []:
            self.traverse_users(self.sock, userlist)
        else:
            self.logger.display("Could not fetch user list exiting", "err")
        recveived = self.sock.recv(settings.BUFFER_SIZE)
        if recveived != '':
            self.logger.display(recveived)

        self.sock.close()

    def reconnect(self, host, port):
        self.host = host
        self.port = int(port)

        self.sock.close()
        self.sock = self.connection.open_sock(self.host, self.port, self.nic)
        self.dc.handshake_c2s(self.sock)

        userlist, rawlist = self.fetch_users(self.sock)

        if userlist is not None or userlist is not []:
            self.traverse_users(self.sock, userlist)
        else:
            self.logger.display("Could not fetch user list exiting", "err")
        recveived = self.sock.recv(settings.BUFFER_SIZE)
        if recveived != '':
            self.logger.display(recveived)

        self.sock.close()




    def parse_args(self):
        """Parse arguments passed to script
        """
        parser = argparse.ArgumentParser()
        parser.add_argument("-a", "--address", help="DC hub (server) address.",
                            required=True)
        parser.add_argument("-d", "--debug",
                            help="Additional verbosity for "
                                 "debugging purposes.")
        parser.add_argument("-p", "--port", help="DC hub (server) port",
                            required=True)
        parser.add_argument("-n", "--nick", help="DC hub nickname",
                            required=False)
        parser.add_argument("-v", "--verbose", help="increase verbosity",
                            action='store_true', required=False)
        parser.add_argument("-i", "--interface", help="network interface",
                            required=False)

        args = parser.parse_args()
        self.host = str(args.address)
        self.port = int(args.port)
        self.nick = args.nick if args.nick is not None else self.nick
        self.nic = args.interface if args.interface is not None else self.nic
        self.verbose = args.verbose

    def traverse_users(self, sock, userlist):
        """+ Iterate over found users and for each:
            * establish connection,\n
            * perform handshake,\n
            * retrieve filelist.\n
        + Calculate percentage of users that send their info,
        + Write down server information.
           Args:
               sock (socket): Socket for server connection.
               userlist (list): List of available users.
        """
        self.logger.display("Adjusting buffer size to: 16", "warn")
        settings.BUFFER_SIZE = 16
        cc_port = settings.CC_PORT
        ip = self.connection.get_public_ip()
        self.logger.display("Found [" + str(len(userlist)) + "] users.")
        for user in userlist:
            try:
                self.dc.connect_to_me(sock, user, ip, cc_port)  # Co
                clink = self.connection.direct_connect(user, cc_port)
                self.dc.handshake_c2c(user, clink)
                self.get_filelist(user, clink, True)
                if self.user_list_fetched:
                    self.user_count += 1
                cc_port += 1
            except socket.timeout:
                self.logger.display("socket timeout: "
                                    "Could not establish "
                                    "connection with user.", "err")
                cc_port += 1
            except Exception as e:
                self.logger.display(str(e), "err")
                cc_port += 1
        perc = 0
        if userlist is not None and len(userlist) > 0:
            perc = str((100.0 * float(self.user_count)) /
                       float(len(userlist)))[:5]
            self.logger.display("Percentage userlists fetched: " +
                                perc + "%", "ok")

        # write down hub (server) information
        servinfo = open(settings.TMP_FOLDER + "servinfo", "a")
        servinfo.write(str(self.host) + "|" +
                       str(self.port) + "|" +
                       str(perc) + "|" +
                       "false|false\n")
        servinfo.close()

    def get_filelist(self, user, clink, trail):
        """Retrieve filelist (files.xml.bz2) from user.
           If successfull it is extracted and downloaded into tmp
        Args:
            user (string): The current username.
            clink (socket): Socket for direct connection with user.
        """

        start_time = datetime.now()  # record time it takes to load list
        self.user_list_fetched = False
        getlist = "$ADCGET file files.xml.bz2 0 -1 ZL1|"
        clink.send(getlist)
        self.logger.display(getlist, "sent")
        clink.recv(settings.BUFFER_SIZE * 1024)
        # self.logger.display(adcsnd, "sent")
        content = b""
        packet = None
        fcntl.fcntl(clink, fcntl.F_SETFL, os.O_NONBLOCK)
        timeout_set = False  # for the heuristic
        clink.settimeout(1)
        t = threading.Thread(target=self.empty_thread_skeleton)
        while True:
            try:
                if timeout_set:
                    self.logger.display("Continuing...")
                    timeout_set = False
                start = time.time()
                packet = clink.recv(settings.BUFFER_SIZE)
                if not t.isAlive():
                    t = threading.Thread(target=self.h_rate,
                                         args=(start, len(packet)))
                    t.start()
                content += packet
            except socket.error as e:
                err = e.args[0]
                if err == errno.EAGAIN or err == errno.EWOULDBLOCK:
                    self.logger.display("No data is being received...",
                                        "debug")
                elif err == "timed out":
                    self.logger.display("Download stopped.", "debug")
                    break
                else:
                    self.logger.display(err, "err")
                    break
                if not timeout_set:
                    self.logger.display("Setting timeout: " +
                                        str(settings.CLIENT_TIMEOUT) +
                                        "s...", "debug")
                    clink.settimeout(settings.CLIENT_TIMEOUT)
                    timeout_set = True

        self.logger.display("Extracting...", "debug")
        # use with caution, potential for memory bombs!
        try:
            content = bz2.decompress(zlib.decompress(content))
        except Exception:
            try:
                content = bz2.decompress(content)
            except Exception as e:
                if "invalid data stream" in e:
                    if trail:
                        self.logger.display("Invalid data stream", "err")
                        self.logger.display("Second attempt!", "warn")
                        self.get_filelist(user, clink, False)

        uid = str(uuid.uuid4())
        self.logger.display("Writing file: " + uid, "debug")
        filelist = open(settings.TMP_FOLDER + uid + ".fl", "w")
        filelist.write(content)
        filelist.close()
        self.user_list_fetched = True

        self.logger.display("Done!", "debug")

        elapsed_time = str((datetime.now() - start_time).total_seconds())
        self.logger.display("Elapsed time: " + elapsed_time, "debug")

        # write user-list mapping
        uf_map = open(settings.TMP_FOLDER + "umap", "a")
        md5sum = hashlib.md5(settings.TMP_FOLDER + uid + ".fl").hexdigest()
        uf_map.write(user + "|" +
                     uid + "|" +
                     md5sum + "|" +
                     elapsed_time + "\n")
        uf_map.close()

    def fetch_users(self, sock):
        """Fetches users from Nicklist if it is found and
        ignores users in Oplist

        Args:
            sock (int): Server connection socket.
        Returns:
            list: List of online users, otherwise empty list.
        """
        self.logger.display("Fetching userlist using method 'fetch_users'.",
                            "mesg")
        # exeprimentary: timeout initial message(s)
        s_msg = ""
        user_fetch_time = time.time() + 1.0
        while True:
            try:
                s_msg += sock.recv(settings.BUFFER_SIZE)
                if time.time() >= user_fetch_time:
                    break
            except Exception:
                break
        self.dc.handle_response_restrictions(s_msg)
        userlist = []
        try:
            for msg in s_msg.split('|'):
                if "NickList" in msg:
                    userlist = msg
                if "OpList" in msg:
                    oplist = msg
            if userlist is None:
                # that's sad, just exit!
                self.logger.display("I didn't find any friends!", "warn")
                exit(0)
            if oplist is None:
                oplist = []
            userlist = userlist.split(' ')[1].split('$$')[:-1]
            # cleanup user, operators and bots
            userlist.remove(self.nick)
            for bot in oplist.split(' ')[1].split('$$'):
                if bot != '':
                    userlist.remove(bot)
            return userlist, s_msg
        except Exception:
            self.logger.display("Could not retrieve list.", "err")
            return [], s_msg

    def h_rate(self, start, size):
        total = (time.time() - start)
        if int(total) == 0:
            total = 0.00001
        speed, r = str(math.ceil(
            (settings.BUFFER_SIZE / total / 1024) * 100) / 100), "B"

        if int(speed.split(".")[0]) > 100:
            speed, r = str(math.ceil((float(speed)/1024) * 100) / 100), "KB"
            if int(speed.split(".")[0]) > 100:
                speed, r = str(math.ceil(
                    (float(speed)/1024) * 100) / 100), "MB"

        # dynamic timeout adjustment
        if r == "B":
            settings.CLIENT_TIMEOUT = 0.1
        elif r == "KB":
            settings.CLIENT_TIMEOUT = 0.05
        elif r == "MB":
            settings.CLIENT_TIMEOUT = 0.001

        speed = "{} {}/s \r".format(speed, r)
        time.sleep(0.5)
        sys.stdout.flush()
        sys.stdout.write("\033[94m"
                         "[down]:\t\t "
                         "Downloading at " + speed + "\033[0m",)
        sys.stdout.flush()

    def empty_thread_skeleton(self):
        pass

if __name__ == '__main__':
    bot = DCbot()
