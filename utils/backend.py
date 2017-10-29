#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#   DCbot metadata crawler for forensic lab at TU Darmstadt.
#   2017 - Mahdi Enan and Florian Platzer

#   'backend.py' handles database operations.

import sqlite3
import settings

from logs import Logger


class Database:

    def __init__(self):
        self.logger = Logger(True, False)
        self.create_connection(settings.DATABASE_NAME)
        self.init_db()
        # self.close_connection

    def create_connection(self, database):
        """Connect to a database.\n
        Args:
            database: The database to connect to.
        """
        try:
            self.conn = sqlite3.connect(database)
            self.conn.isolation_level = None
            self.cursor = self.conn.cursor()
            self.cursor.execute("PRAGMA synchronous = OFF")
        except sqlite3.Error as e:
            print(e)

    def close_connection(self):
        """Disconnect from connected database.\n
        """
        self.conn.close()

    def begin_transaction(self):
        """ Start a sqlite transaction
        """
        self.cursor.execute("begin")

    def end_transaction(self):
        """ Close a sqlite transaction
        """
        self.cursor.execute("commit")

    def commit(self):
        """Save changes to the connected database.\n
        """
        self.conn.commit()

    def init_db(self):
        """Initial database: creating all tabels
        """
        try:
            cursor = self.conn.cursor()
            table_users = '''CREATE TABLE IF NOT EXISTS users
                (userID integer primary key autoincrement, nickname text,
                 filelist text, cid text,
                 FOREIGN KEY(filelist) REFERENCES files(fileID))'''
            table_hubs = '''CREATE TABLE IF NOT EXISTS  hubs
                (hubID integer primary key autoincrement, name text,
                 port text, fetched text, minShare boolean,
                 registration boolean)'''
            table_filelist = '''CREATE TABLE IF NOT EXISTS  filelist
                (filelistID integer primary key autoincrement, md5sum text,
                 size text, elapsed_time text)'''
            table_files = '''CREATE TABLE IF NOT EXISTS  files
                (fileID integer primary key autoincrement, name text,
                 type text, category text, size text, pathID integer,
                 FOREIGN KEY(pathID) REFERENCES paths(pathID))'''
            table_path = '''CREATE TABLE IF NOT EXISTS  paths
                (pathID integer primary key autoincrement, path text)'''

            cursor.execute(table_users)
            cursor.execute(table_hubs)
            cursor.execute(table_filelist)
            cursor.execute(table_files)
            cursor.execute(table_path)
            self.conn.commit()
        except sqlite3.Error as e:
            print(e)

    def add_user(self, nickname, filelist, cid):
        """Insert user into database.\n
        Args:
            nickname (string): User nickname.
            filelist (string): md5 hash of user's filelist.
            cid (string): User's CID.
        """
        self.cursor.execute("INSERT INTO users (nickname, filelist, cid) " +
                            "VALUES (?, ?, ?)", (nickname, filelist, cid))

    def add_file(self, name, type, category, size, pathID):
        """Insert file into database.\n
        Args:
            name (string): Name of the file.
            type (string): Type of the file.
            category (string): Category of the file.
            size (int): Size of the file.
            pathID (int): FK of file's path.
        """
        self.cursor.executemany("INSERT INTO files \
                            (name, type, category, size, pathID) " +
                                "VALUES (?, ?, ?, ?, ?)",
                                (name, type, category, size, pathID))

    def add_files(self, files):
        """Insert files into database.\n
        Args:
            files (array): A Array with tupels:
                        (name, type, category, size, pathID).
        """
        self.cursor.executemany("INSERT INTO files \
                            (name, type, category, size, pathID) " +
                                "VALUES (?, ?, ?, ?, ?)",
                                files)

    def add_filelist(self, md5sum, elapsed_time):
        """Insert file list into database.\n
        Args:
            md5sum (string): md5 hash of the file list.
            elapsed_time (sting): elapsed download time
            of the file list in seconds.
        """
        self.cursor.execute("INSERT INTO filelist \
                            (md5sum, elapsed_time) " +
                            "VALUES (?, ?)",
                            (md5sum, elapsed_time))

    def add_path(self, path):
        """Insert path into database.\n
        Args:
            path (string): Path of a file.
        """
        self.cursor.execute("INSERT INTO paths (path) VALUES (?)", (path))

    def add_hub(self, name, port, fetched, minShare, registration):
        """Insert hub into database.\n
        Args:
            name (string): Name or address of the hub.
            port (string): Port of hub's service.
            fetch (string): Percentage of successful fetched users.
            minShare (boolean): minShare that you have to have to use the hub.
            registration (boolean): Is on hub a registration required.
        """
        self.cursor.execute(
            "INSERT INTO hubs (name, port, fetched, minShare, registration)" +
            "VALUES (?, ?, ?, ?, ?)", (name,  port, fetched, minShare,
                                       registration))

    def update_filelist_size(self, filelist_size, md5sum):
        """Updates the file list size of the file list table.\n
        Args:
            filelist_size (string): Size of the file list.
            md5sum (string): md5 hash of the file list.
        """
        self.cursor.execute("UPDATE filelist SET size=? WHERE md5sum=?",
                            (filelist_size, md5sum,))
        if self.cursor.rowcount == 0:
            self.logger.display("No file list with such md5 hash in DB."
                                "Could not update file list size.",
                                "warn")

    def get_pathID(self, path):
        """Get the path ID (PK) of a path.\n
        Args:
            path (string): The path as string.
        Returns:
            path_id (int): The path ID of the path.
        """
        self.cursor.execute("SELECT pathID FROM paths WHERE path=?", (path,))
        path_id = self.cursor.fetchall()
        return path_id

    def get_hubID(self, name, port):
        """Get the path ID (PK) of a path.\n
        Args:
            name (string): Name or address of the hub.
            port (string): Port of the hub's service.
        Returns:
            hub_ID (int): The hub ID of the path.
        """
        self.cursor.execute("SELECT hubID FROM hubs WHERE name=? AND port =?",
                            (name, port))
        hub_ID = self.cursor.fetchall()
        return hub_ID

    def get_filelist_ID(self, md5sum):
        """Get the file list ID (PK) of a file list.\n
        Args:
            md5sum (string): md5 hash of the file list.
        Returns:
            fl_ID (int): The file list ID of the file list.
        """
        self.cursor.execute("SELECT filelistID FROM filelist WHERE md5sum=?",
                            (md5sum,))
        fl_ID = self.cursor.fetchall()
        return fl_ID

    def get_user_ID_from_md5(self, md5sum):
        """Get the user ID (PK) from the md5 Hash of his file list.\n
        Args:
            md5sum (string): md5 hash of the file list.
        Returns:
            user_ID (int): The user ID of the user.
        """
        self.cursor.execute("SELECT userID FROM users WHERE filelist=?",
                            (md5sum,))
        user_ID = self.cursor.fetchall()
        return user_ID

# db = Database()
