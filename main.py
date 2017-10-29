#!/usr/bin/env python
# -*- coding: utf-8 -*-
#   DCbot metadata crawler for forensic lab at TU Darmstadt.
#   2017 - Mahdi Enan and Florian Platzer

import argparse
import os

import settings

from utils.fileParser import FileParser
from utils.logs import Logger


class Main:

    def __init__(self):
        self.logger = Logger(True, False)
        self.parse_args()
        self.fileParser = FileParser()
        self.scan_hub_list()
        if self.parser is True:
            command = 'python manage.py --parse_filelists'
            os.system(command)
        if self.stat is True:
            command = 'python manage.py --statistics'
            os.system(command)

    def parse_args(self):
        """Parses command-line arguments.
        """
        parser = argparse.ArgumentParser()
        parser.add_argument("--p",
                            help="Parse all file lists and insert "
                                 "all data into database",
                            action='store_true')
        parser.add_argument("--s",
                            help="Create statistics and "
                            "afterwards statistics.html",
                            action='store_true')

        args = parser.parse_args()
        self.parser = args.p
        self.stat = args.s

    def scan_hub_list(self):
        """Starts dcBot for each hub address in the hublist file with
        python dcbot.py -v -a [ADDRESS] -p [PORT]
        """
        if not os.path.isfile(settings.HUB_LIST):
            self.logger.display("No hub list file in data/ found!", "err")
            return
        self.hubs = self.fileParser.parse_hubs(settings.HUB_LIST)
        for hub in self.hubs:
            command = 'python dcbot.py -v -a ' + hub['address'] + ' -p ' + hub['port']
            print(command)
            os.system(command)


if __name__ == '__main__':
    main = Main()
