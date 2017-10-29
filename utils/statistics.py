#   DCbot metadata crawler for forensic lab at TU Darmstadt.
#   2017 - Mahdi Enan and Florian Platzer

#   'statistics.py' performs statistical operations and plots the results.

import sqlite3
import settings
import os

from fileTypeParser import FileTypeParser as ftp
from logs import Logger


class Statistics():

    def __init__(self):
        self.logger = Logger(True, False)
        self.ftp = ftp()  # FileTypeParser
        # set temporary files
        self.generalInfo = 'generalInfo.stat'
        self.fileInfo = 'fileInfo.stat'
        self.fileTypes = 'fileTypes.stat'
        self.sizeFiletype = 'sizeFiletype.stat'
        self.categoryInfo = 'categoryInfo.stat'
        self.fileListInfo = 'fileListInfo.stat'

    def show_statistics(self):
        """Implement main statistic functionality
        """
        self.connection_to_db(settings.DATABASE_NAME)
        self.perform_general_information()
        self.perform_file_info()
        self.perform_filelist_info()
        self.perform_category_Info()
        self.fill_template()
        self.disconnection_from_db()
        self.remove_all_stat_files()

    def connection_to_db(self, database):
        """Connect to a database.\n
        Args:
            database: The database to connect to.
        """
        self.conn = sqlite3.connect(database)

    def disconnection_from_db(self):
        """Disconnect from connected database.
        """
        self.conn.close()

    def perform_general_information(self):
        """Performs general statistic informations.\n
            + Number of users
            + number of hubs
            + number of each file type
            + size of each file type
        """
        self.number_of_users()
        self.number_of_hubs()
        self.filetype()
        self.size_filetype()

    def perform_file_info(self):
        """Performs file statistic informations.\n
            + number of files
            + total file size
            + average file size
            + median file size
        """
        self.number_of_files()
        self.total_filesize()
        self.average_filesize()
        self.median_filesize()

    def perform_filelist_info(self):
        """Performs filel ist statistic informations.\n
            + average file list size
            + median file list size
            + average download time
            + median download time
        """
        self.average_filelist_size()
        self.median_filelist_size()
        self.average_fl_download_time()
        self.median_fl_download_time()

    def perform_category_Info(self):
        """Performs category statistic informations.
        """
        self.write_category_file()

    def filetype(self):
        """Write total number of each file type into tmp file.
        """
        c = self.conn.cursor()
        counter = 1
        for f in c.execute('SELECT type, COUNT(type) as n\
                            FROM files GROUP BY type\
                            ORDER BY n DESC\
                            LIMIT 25'):
            self.write_into_tmp_file(self.fileTypes,
                                     "<b>" + str(counter) + ": </b>" +
                                     str(f[0]) + " : " +
                                     str("{0:,g}".format(f[1])) + "<br>\n")
            counter += 1

    def size_filetype(self):
        """Write total size of each file type into tmp file.
        """
        c = self.conn.cursor()
        counter = 1
        for f in c.execute('SELECT type, SUM(CAST(size as float))/1024 as n\
                            FROM files GROUP BY type\
                            ORDER BY n DESC\
                            LIMIT 25'):
            self.write_into_tmp_file(self.sizeFiletype,
                                     "<b>" + str(counter) + ": </b>" +
                                     str(f[0]) + " : " +
                                     self.format_number(f[1]) + "<br>\n")
            counter += 1

    def total_filesize(self):
        """Write total file size into tmp file.
        """
        c = self.conn.cursor()
        self.write_into_tmp_file(self.fileInfo,
                                 "\nTotal size of all files: ")
        for f in c.execute('SELECT SUM(CAST(size as float))/1024\
                            FROM files'):
            self.write_into_tmp_file(self.fileInfo,
                                     self.format_number(f[0]) + "<br>")

    def average_filesize(self):
        """Write average of file size into tmp file.
        """
        c = self.conn.cursor()
        self.write_into_tmp_file(self.fileInfo,
                                 "\nAverage of file size: ")
        for f in c.execute('SELECT AVG(CAST(size as float))/1024\
                            FROM files'):
            self.write_into_tmp_file(self.fileInfo,
                                     self.format_number(f[0]) + "<br>")

    def median_filesize(self):
        """Write median of file size into tmp file.
        """
        c = self.conn.cursor()
        self.write_into_tmp_file(self.fileInfo,
                                 "\nMedian of file size: ")
        query = 'SELECT CAST(size as float)/1024\
                FROM files ORDER BY size LIMIT 1 OFFSET\
                (SELECT COUNT(*) FROM files) / 2'
        for f in c.execute(query):
            self.write_into_tmp_file(self.fileInfo,
                                     self.format_number(f[0]) + "<br>")

    def number_of_users(self):
        """Write total number of users into tmp file.
        """
        c = self.conn.cursor()
        self.write_into_tmp_file(self.generalInfo,
                                 "\nTotal number of users: ")
        for f in c.execute('SELECT COUNT(*) FROM users'):
            self.write_into_tmp_file(self.generalInfo,
                                     str("{0:,g}".format(f[0])) + "<br>")

    def number_of_hubs(self):
        """Write total number of hubs into tmp file.
        """
        c = self.conn.cursor()
        self.write_into_tmp_file(self.generalInfo,
                                 "\nTotal number of hubs: ")
        for f in c.execute('SELECT COUNT(*) FROM hubs'):
            self.write_into_tmp_file(self.generalInfo,
                                     str("{0:,g}".format(f[0])) + "<br>")

    def number_of_files(self):
        """Write total number of files into tmp file.
        """
        c = self.conn.cursor()
        self.write_into_tmp_file(self.fileInfo,
                                 "\nTotal number of files: ")
        for f in c.execute('SELECT COUNT(*) FROM files'):
            self.write_into_tmp_file(self.fileInfo,
                                     str("{0:,g}".format(f[0])) + "<br>")

    def file_categories_as_stringArray(self, categories):
        """Get all file categories as string array.\n
        Args:
            categories (array): File categories.
        Returns:
            categories_arr (string): String array of all file categories.
        """
        categories_arr = "["
        for category in categories:
            categories_arr += '\'' + category + '\', '
        categories_arr = categories_arr[:-2] + ']\n'
        return categories_arr

    def no_of_categories_as_stringArray(self, categories):
        """Get number of files of each categoriy as string array.\n
        Args:
            categories (array): Categories.
        Returns:
            numbers (string): String array of numbers of files each category.
        """
        c = self.conn.cursor()
        numbers = "["
        for category in categories:
            for f in c.execute('SELECT COUNT(*) FROM files \
                    WHERE category = ?', (category,)):
                    numbers += '\'' + str(f[0]) + '\', '
        numbers = numbers[:-2] + ']'
        return numbers

    def average_filelist_size(self):
        """Write average of file list size into tmp file.
        """
        c = self.conn.cursor()
        self.write_into_tmp_file(self.fileListInfo,
                                 "\nAverage of filelist size: ")
        for f in c.execute('SELECT AVG(CAST(size as float))/1024\
                            FROM filelist'):
            self.write_into_tmp_file(self.fileListInfo,
                                     self.format_number(f[0]) + "<br>")

    def median_filelist_size(self):
        """Write median of file list size into tmp file.
        """
        c = self.conn.cursor()
        self.write_into_tmp_file(self.fileListInfo,
                                 "\nMedian of filelist size: ")
        query = 'SELECT CAST(size as float)/1024\
                FROM filelist ORDER BY size LIMIT 1 OFFSET\
                (SELECT COUNT(*) FROM filelist) / 2'
        for f in c.execute(query):
            self.write_into_tmp_file(self.fileListInfo,
                                     self.format_number(f[0]) + "<br>")

    def average_fl_download_time(self):
        """Write average download time of file lists into tmp file.
        """
        c = self.conn.cursor()
        self.write_into_tmp_file(self.fileListInfo,
                                 "\nAverage download time: ")
        for f in c.execute('SELECT AVG(CAST(elapsed_time as float))\
                            FROM filelist'):
            if f[0] is None:
                self.write_into_tmp_file(self.fileListInfo,
                                         "None sec<br>")
            else:
                self.write_into_tmp_file(self.fileListInfo,
                                         str(format(f[0], '.2f')) + " sec<br>")

    def median_fl_download_time(self):
        """Write median download time of file lists into tmp file.
        """
        c = self.conn.cursor()
        self.write_into_tmp_file(self.fileListInfo,
                                 "\nMedian download time: ")
        query = 'SELECT CAST(elapsed_time as float)\
                FROM filelist ORDER BY elapsed_time LIMIT 1 OFFSET\
                (SELECT COUNT(*) FROM filelist) / 2'
        for f in c.execute(query):
            if f[0] is None:
                self.write_into_tmp_file(self.fileListInfo,
                                         "None sec<br>")
            else:
                self.write_into_tmp_file(self.fileListInfo,
                                         str(format(f[0], '.2f')) + " sec<br>")

    def write_into_tmp_file(self, filename,  msg):
        """Write a message into a tmp file.\n
        Args:
            filename (string): Name of file to write into.

            msg (string): Message to write into file.
        """
        stats = open(settings.STATFILES+filename, 'a')
        stats.write(msg)
        stats.close()

    def write_category_file(self):
        """Creates category tmp file.
        """
        category_file = open(settings.STATFILES + self.categoryInfo, 'w')
        categories = self.get_all_categories()
        category_file.write(self.file_categories_as_stringArray(categories))
        category_file.write(self.no_of_categories_as_stringArray(categories))
        category_file.close()

    def get_all_categories(self):
        """Get all categories from FileTypeParser.\n
        Returns:
            array: Array of all categories.
        """
        categories = self.ftp.get_file_categories()
        return categories

    def fill_template(self):
        """ Uses statistic templates and tmp files
            to creates statistic.html.
        """
        data = self.read_file(settings.STATFILES +
                              self.categoryInfo).split('\n', 1)
        s = self.read_file('style/templates/statistics.temp'). \
            replace('<$ labels $>', data[0]). \
            replace('<$ data $>', data[1]). \
            replace('<$ fileInfo $>',
                    self.read_file(settings.STATFILES +
                                   self.fileInfo)). \
            replace('<$ generalInfo $>',
                    self.read_file(settings.STATFILES +
                                   self.generalInfo)). \
            replace('<$ fileListInfo $>',
                    self.read_file(settings.STATFILES +
                                   self.fileListInfo)).\
            replace('<$ fileTypes $>',
                    self.read_file(settings.STATFILES +
                                   self.fileTypes)).\
            replace('<$ sizeFiletype $>',
                    self.read_file(settings.STATFILES +
                                   self.sizeFiletype))
        view = open('statistics.html', 'w')
        view.write(s)
        view.close()
        self.logger.display("statistics.html created. Open it in your "
                            "web browser to show the statistics.", "debug")

    def read_file(self, filename):
        """ Read a given file.\n
        Args:
            filename (string): Name of file.
        Returns:
            content (string): The conten of the given file.
        """
        file_object = open(filename, 'a+')
        content = file_object.read()
        if content is "":
            self.logger.display("File {} is empty or do not exist"
                                .format(filename), "err")
            exit(1)
        file_object.close()
        return content

    def remove_all_stat_files(self):
        """Removes all stat files after calculating statistics.
        """
        files = os.listdir(settings.STATFILES)
        for f in files:
            if f.endswith(".stat"):
                os.remove(os.path.join(settings.TMP_FOLDER, f))

    def format_number(self, number):
        """ Formats a number corresponding to the unit size:
            + supports KB, MB, GB, TB, PB.
        Args:
            Number to format.
        Returns:
            Formated number.
        """
        if number is None:
            return 'None'
        if number < 1024:
            return "{} KB".format(format(number, '.2f'))
        if number > 1024 and number < 1048576:
            return "{} MB".format(format(number/1024, '.2f'))
        elif number > 1048576 and number < 1073741824:
            return "{} GB".format(format(number/1024/1024, '.2f'))
        elif number > 1073741824 and number < 1099511627776:
            return "{} TB".format(format(number/1024/1024/1024, '.2f'))
        else:
            return "{} PB".format(format(number/1024/1024/1024/1024, '.2f'))
