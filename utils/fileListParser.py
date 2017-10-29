#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#   DCbot metadata crawler for forensic lab at TU Darmstadt.
#   2017 - Mahdi Enan and Florian Platzer

#   'fileListParser.py' handles parsing for file lists.

import random

from lxml import etree
from fileTypeParser import FileTypeParser
from logs import Logger


class FileListParser:

    def __init__(self):
        self.logger = Logger(True, False)
        self.file_types = FileTypeParser().get_file_types()

    def parseFilelist(self, filelist):
        """Parses a given file list.\n
            Args:
                filelist (string): File list to parse.
            Returns:
                user_filelist (array): Including for each file a dict with
                category, path, size, type, filename.
        """
        user_filelist = []
        filelist_dic = {}
        try:
            tree = etree.parse(filelist)
        except Exception:
            self.logger.display("Invalid filelist found: {}.".format(filelist),
                                "warn")
            return []

        root = tree.getroot()
        cid = root.get("CID")

        unknown_dic = {}
        for elem in root.iter():
            file_dic = {}
            if elem.tag == "File":
                path = '/'
                p = elem
                while True:
                    # get path of file
                    try:
                        p = p.getparent()
                        path = "/" + p.get("Name") + path
                    except Exception:
                        break
                file_name = elem.get("Name")
                file_path = path
                file_type = 'unknown'
                file_category = 'unknown'
                try:
                    file_extension = file_name.rsplit('.', 1)[1]
                    # check if file extension is known
                    for extension in self.file_types.values():
                        if file_extension.lower() in extension:
                            file_type = file_extension.lower()
                            # get file category
                            try:
                                file_category = \
                                    [key for key, value in
                                        self.file_types.iteritems()
                                        if file_type in value][0]
                            except Exception:
                                pass

                            break
                    if file_type == 'unknown':
                        if file_extension in unknown_dic:
                            unknown_dic[file_extension] = \
                                unknown_dic[file_extension]+1
                        else:
                            unknown_dic[file_extension] = 1
                except Exception:
                    pass

                file_size = elem.get("Size")
                file_dic["filename"] = file_name
                file_dic["path"] = file_path
                file_dic["type"] = file_type
                file_dic["category"] = file_category
                file_dic["size"] = file_size
                filelist_dic[random.randint(1, 99999)] = file_dic
        user_filelist.append(cid)
        user_filelist.append(filelist_dic)
        return user_filelist
