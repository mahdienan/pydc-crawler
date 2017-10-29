#!/usr/bin/env python
#   DCbot metadata crawler for forensic lab at TU Darmstadt.
#   2017 - Mahdi Enan and Florian Platzer

#   'logs.py' handles display and writting logs into debug file.

from datetime import datetime
import settings


class Logger:
    debug = False
    verbose = False

    def __init__(self, verbose, debug):
        self.debug = debug
        self.verbose = verbose

    def display(self, msg, type="debug"):
        """Display logging information.\n
        Colors have different meanings:
            * 'err' is red.
            * 'warn' is yellow.
            * 'ok' is green.
            * 'debug' is blue.
            * The rest 'sent', 'recv' and 'info' are colorless.
        Args:
            msg (string): The message to display.
            type (string): The message type.
        """
        msg = str(msg)
        message = ""
        if type == 'sent':
            message = "[sent]:\t\t " + msg
            print message
        elif type == 'recv':
            message = "[recv]:\t\t " + msg
            print message
        elif type == 'mesg':
            message = "[mesg]:\t\t " + msg
            print message
        elif type is None:
            message = msg
            print msg
        elif self.verbose:
            if type == 'err':
                message = "[err ]:\t\t " + msg
                print "\033[91m" + message + "\033[0m"
            elif type == 'warn':
                message = "[warn]:\t\t " + msg
                print "\033[93m" + message + "\033[0m"
            elif type == 'ok':
                message = "[ok  ]:\t\t " + msg
                print "\033[92m" + message + "\033[0m"
            elif type == 'debug':
                message = "[dbg ]:\t\t " + msg
                print "\033[94m" + message + "\033[0m"
            elif type == 'info':
                message = "[info]:\t\t " + msg
                print message
        if self.debug:
            self.debugLog(message)

    def debugLog(self, msg):
        """Write debug information to log file.\n
        Args:
            msg (string): The actual message to write.
        """
        time = datetime.now().strftime('%d.%m.%y %H:%M:%S')
        debug_file = open(settings.LOG_FILE, 'a')
        debug_file.write(time + ": " + msg + "\n")
        debug_file.close()
