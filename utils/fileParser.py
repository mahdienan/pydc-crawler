#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#   DCbot metadata crawler for forensic lab at TU Darmstadt.
#   2017 - Mahdi Enan and Florian Platzer

#   'fileParser.py' handles parsing for various files.

from logs import Logger


class FileParser:

    def __init__(self):
        self.logger = Logger(True, False)

    def parse_servinfo(self, servinfo):
        """Parses the servinfo file. A file that maps:
        (Hubname|port|fetched|min_share|reg).\n
        Args:
            servinfo (string): servinfo file.
        Returns:
            hubs (array): Array including for each entry a dict
            with name, port, fetched, min_share and reg.
        """
        hubs = []
        with open(servinfo) as servinfo_file:
            for line in servinfo_file:
                values = line.split('|')
                if len(values) == 5:
                    hub_dic = {'name': values[0], 'port': values[1],
                               'fetched': values[2], 'min_share': values[3],
                               'reg': values[4]}
                    hubs.append(hub_dic)
                else:
                    self.logger.display("Invalid servinfo file!", "err")
        return hubs

    def parse_umap(self, umap_file):
        """Parses the umap file. A file that maps:
        (username|checksum|md5sum|elapsed_time).\n
        Args:
            umap (string): umap file.
        Returns:
            umap (array): Array including for each entry a dict
            with users, uid, md5sum and elapsed_time.
        """
        umap = []
        with open(umap_file) as umap_file:
            for line in umap_file:
                values = line.split('|')
                if len(values) == 4:
                    try:
                        username = values[0].encode('utf-8', 'ignore')
                    except Exception:
                        username = 'not_printable'
                    userlist = {'user': username, 'uid': values[1],
                                'md5sum': values[2], 'elapsed_time': values[3]}
                    umap.append(userlist)
                else:
                    self.logger.display("Invalid umap file!", "err")
        return umap

    def parse_hubs(self, hub_file):
        """Parses a hublist file. A file that includes
        one hub address per line:\n
        Args:
            hub_file (string): hublist file.
        Returns:
            hubs (array): Array including for each entry a dict
            with hub address and hab port.
        """
        hubs = []
        with open(hub_file) as hub_file:
            for line in hub_file:
                if 'dchub://' in line:
                    line = line.replace('dchub://', '')
                values = line.split(':')
                if len(values) == 2:
                    try:
                        address = values[0].encode('utf-8', 'ignore')
                        port = values[1]
                        hub = {'address': address, 'port': port}
                        hubs.append(hub)
                    except Exception:
                        self.logger.display("Address can not be resolved"
                                            " " + address, "err")
                else:
                    self.logger.display("Invalid hub list!", "err")
        return hubs
