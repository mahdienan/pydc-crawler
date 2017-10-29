#!/usr/bin/env python
# -*- coding: utf-8 -*-
#   DCbot metadata crawler for forensic lab at TU Darmstadt.
#   2017 - Mahdi Enan and Florian Platzer


# Network settings
NIC = "tun0"  # Network device; eth0, enp0s3, wlp3s0 ->!! Currently not used !!
BUFFER_SIZE = 1024
CLIENT_TIMEOUT = 5.0
CC_PORT = 40000

# Database settings
DATABASE_NAME = 'dc.db'

# Log settings
LOG_FILE = "debug/debug.txt"

# Folder and File settings
TMP_FOLDER = 'tmp/'
STATFILES = TMP_FOLDER
FILETYPES = 'data/file_types.xml'
HUB_LIST = 'data/hublist.txt'

# Remove all tmp files after executing parsing
REMOVE_TMP_FILES = True
