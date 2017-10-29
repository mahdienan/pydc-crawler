#!/usr/bin/env python
# -*- coding: utf-8 -*-
#   DCbot metadata crawler for forensic lab at TU Darmstadt.
#   2017 - Mahdi Enan and Florian Platzer
import argparse
import glob
import os
import hashlib

import settings

from utils.backend import Database
from utils.fileListParser import FileListParser
from utils.fileParser import FileParser
from utils.statistics import Statistics
from utils.logs import Logger


class Manage:

    def __init__(self):
        self.logger = Logger(True, False)
        self.parse_args()
        self.xmlP = FileListParser()
        self.fileParser = FileParser()
        self.db = Database()
        self.stat_instance = Statistics()

        if self.parser is True:
            self.parse_filelist()
        elif self.stat is True:
            self.stats()

    def parse_args(self):
        """Parses command-line arguments.
        """
        parser = argparse.ArgumentParser()
        parser.add_argument("--parse_filelists",
                            help="Parse all file lists and insert "
                                 "all data into database",
                            action='store_true')
        parser.add_argument("--statistics",
                            help="Create statistics and "
                            "afterwards statistics.html",
                            action='store_true')

        args = parser.parse_args()
        self.parser = args.parse_filelists
        self.stat = args.statistics

    #############################
    # ### XML parser stuff #### #
    ############################

    def parse_filelist(self):
        """Parses downloaded filelists of users.\n
        """

        if not settings.REMOVE_TMP_FILES:
            self.logger.display('REMOVE_TMP_FILES is set to False!', 'warn')

        # parse umap first!
        self.parse_umap()

        # all files in TMP_FOLDER
        files = glob.glob(settings.TMP_FOLDER + "*")
        fl_counter = len(glob.glob(settings.TMP_FOLDER + "*.fl"))
        if not fl_counter > 0:
            self.logger.display("No filelist in \'" + settings.TMP_FOLDER +
                                "\' found!", "warn")
            return

        self.logger.display('Parsing may take several minutes depending ' +
                            'on the size of each file list!', 'warn')
        counter = 1
        for f in files:
            # parse all file lists
            if '.fl' in f:
                md5sum = hashlib.md5(f).hexdigest()
                self.logger.display('Parsing: Filelist ' +
                                    str(counter) + ' of ' +
                                    str(fl_counter) + '...', 'debug')
                counter += 1
                if self.is_filelist_in_DB(md5sum):
                    self.logger.display('Skipping. User\'s file list already '
                                        'in DB.', 'debug')
                    continue
                filelist_size = os.path.getsize(f)
                parsed_filelist = self.xmlP.parseFilelist(f)
                if len(parsed_filelist) < 1:
                    continue

                self.insert_files_into_db(parsed_filelist, f.split('/')[1],
                                          filelist_size)
            # parse servinfo file
            elif 'servinfo' in f:
                hubs = self.fileParser.parse_servinfo(f)
                for hub in hubs:
                    self.insert_hub_into_db(hub)
            # ignore all others
            else:
                pass

        if settings.REMOVE_TMP_FILES:
            self.remove_all_tmpfiles()

    def parse_umap(self):
        """Insert umap informations into database. A file that maps:
        (username|checksum|md5sum|elapsed_time).
        """
        if not os.path.isfile(settings.TMP_FOLDER + 'umap'):
            self.logger.display("No umap file in \'" + settings.TMP_FOLDER +
                                "\' found!", "warn")
            return
        self.umaps = self.fileParser.parse_umap(settings.TMP_FOLDER + 'umap')
        for umap in self.umaps:
            # check if, filelist is already in DB
            if not self.is_filelist_in_DB(umap['md5sum']):
                self.insert_filelist_into_db({'md5sum': umap['md5sum'],
                                             'elapsed_time':
                                              umap['elapsed_time']})

    def remove_all_tmpfiles(self):
        """Removes all tmp files after parsing.
        """
        files = os.listdir(settings.TMP_FOLDER)
        for f in files:
            os.remove(os.path.join(settings.TMP_FOLDER, f))
        self.logger.display("All tmp files removed.", "debug")

    #############################
    # ### Database stuff ###### #
    ############################

    def is_filelist_in_DB(self, md5sum):
        """Checks if user's file list is already in DB.\n
        Args:
            md5sum (string): md5 hash of file list.
        Returns:
            Boolean: True if user's file list is already in DB, False else.
        """
        if len(self.db.get_user_ID_from_md5(md5sum)) > 0:
            return True
        return False

    def insert_files_into_db(self, parsed_filelist, filename, filelist_size):
        """Inserts filelist information into database.\n
        Args:
            parsed_filelist (string): The filelist data.
            filename (string): The filename.
            filelist_size (string): The file size.
        """
        username = 'unknown'
        md5sum = 'unknown'
        for umap in self.umaps:
            if umap['uid'] == filename[:-3]:
                username = umap['user']
                md5sum = umap['md5sum']
                break
        CID = parsed_filelist[0]
        dic = parsed_filelist[1]
        # insert all files and corresponding paths
        files = []
        self.db.begin_transaction()
        for file in dic:
            path = dic[file]['path']
            size = dic[file]['size']
            type = dic[file]['type']
            category = dic[file]['category']
            name = dic[file]['filename']
            # insert path only if it is not in db already
            if len(self.db.get_pathID(path)) == 0:
                self.db.add_path((path,))
            pathID = self.db.get_pathID(path)[0][0]
            files.append((name, type, category, size, pathID))
        self.db.add_files(files)

        # insert user & update filelist size
        self.db.add_user(username, md5sum, CID)
        self.db.update_filelist_size(filelist_size, md5sum)
        self.db.end_transaction()
        self.logger.display("Done.", "debug")

    def insert_hub_into_db(self, hub_info):
        """Insert hub only if it is not in db already.\n
        Args:
            hub_info (string): Hub information\n
            (name|port|percentage of filelists feched|minShare|registration):
        """
        if len(self.db.get_hubID(hub_info['name'], hub_info['port'])) == 0:
            self.db.add_hub(hub_info['name'], hub_info['port'],
                            hub_info['fetched'], hub_info['min_share'],
                            hub_info['reg'])
            self.db.commit()

    def insert_filelist_into_db(self, filelist_info):
        """Insert filelist only if it is not in db already.\n
        Args:
            filelist_info (string): Filelist information\n
            (md5sum|elapsed_time)
        """
        if len(self.db.get_filelist_ID(filelist_info['md5sum'])) == 0:
            self.db.add_filelist(filelist_info['md5sum'],
                                 filelist_info['elapsed_time'])
            self.db.commit()

    #############################
    # ### Statistic stuff ###### #
    ############################

    def stats(self):
        """Calls the statistics.py instance.\n
        """
        self.logger.display("Creating statistics...", "debug")
        self.stat_instance.show_statistics()


if __name__ == '__main__':
    manage = Manage()
