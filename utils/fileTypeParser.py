#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#   DCbot metadata crawler for forensic lab at TU Darmstadt.
#   2017 - Mahdi Enan and Florian Platzer

#   'fileTypeParser.py' handles parsing for file types and file categories.

import settings

from lxml import etree
from collections import defaultdict


class FileTypeParser:

    def __init__(self):
        pass

    def get_file_types(self):
        """Parsed all known file types from the static FILETYPES file.
        The location of the FILETYPES file is written in the settings.py.\n
            Returns:
                file_types (dict): Key: Category, Values: list of file types.
        """
        file_types = defaultdict(list)
        tree = etree.parse(settings.FILETYPES)
        root = tree.getroot()

        for elem in root.iter():
            if elem.tag == "FileExtension":
                file_type = elem.getparent().get("Name")
                file_extension = (elem.get("Name").lower())
                file_types[file_type].append(file_extension)

        return file_types

    def get_file_categories(self):
        """Get all known file categories.
            The location of the FILETYPES file is written in the settings.py.\n
            Returns:
                file_categories (array): All file categories.
        """
        file_categories = []
        tree = etree.parse(settings.FILETYPES)
        root = tree.getroot()

        for elem in root.iter():
            if elem.tag == "FileType":
                file_categories.append(elem.get("Name"))

        return file_categories
