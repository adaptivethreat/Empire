"""

Module handling functionality for Empire.

Right now, just loads up all modules from the
install path in the common config.

"""

import sqlite3
import fnmatch
import os
import imp
import messages
import helpers
import platform


class Modules:

    def __init__(self, MainMenu, args):

        self.mainMenu = MainMenu

        # pull the database connection object out of the main menu
        self.conn = self.mainMenu.conn

        self.args = args

        # module format:
        #     [ ("module/name", instance) ]
        self.modules = {}

        # pull out the code install path from the database config
        cur = self.conn.cursor()
        cur.execute("SELECT install_path FROM config")
        self.installPath = cur.fetchone()[0]
        cur.close()

        self.load_modules()


    def load_modules(self):
        """
        Load modules from the install + "/lib/modules/*" path
        """
        
        rootPath = self.installPath + 'lib'+os.sep+'modules'+os.sep
        pattern = '*.py'
         
        for root, dirs, files in os.walk(rootPath):
            for filename in fnmatch.filter(files, pattern):
                filePath = os.path.join(root, filename)

                # don't load up the template
                if filename == "template.py": continue
                
                # extract just the module name from the full path
                moduleName = filePath.split(os.sep+"lib"+os.sep+"modules"+os.sep)[-1][0:-3]

                # TODO: extract and CLI arguments and pass onto the modules

                # instantiate the module and save it to the internal cache
                self.modules[moduleName] = imp.load_source(moduleName, filePath).Module(self.mainMenu, [])


    def reload_module(self, moduleToReload):
        """
        Reload a specific module from the install + "/lib/modules/*" path
        """

        rootPath = self.installPath + 'lib/modules/'.replace('/', os.sep)
        pattern = '*.py'
         
        for root, dirs, files in os.walk(rootPath):
            for filename in fnmatch.filter(files, pattern):
                filePath = os.path.join(root, filename)

                # don't load up the template
                if filename == "template.py": continue
                
                # extract just the module name from the full path
                moduleName = filePath.split("/lib/modules/".replace('/', os.sep))[-1][0:-3]

                # check to make sure we've found the specific module
                if moduleName.lower() == moduleToReload.lower():
                    # instantiate the module and save it to the internal cache
                    self.modules[moduleName] = imp.load_source(moduleName, filePath).Module(self.mainMenu, [])


    def search_modules(self, searchTerm):
        """
        Search currently loaded module names and descriptions.
        """

        print ""

        for moduleName,module in self.modules.iteritems():
            if searchTerm.lower() in moduleName.lower() or searchTerm.lower() in module.info['Description'].lower():
                messages.display_module_search(moduleName, module)

            # for comment in module.info['Comments']:
            #     if searchTerm.lower() in comment.lower():
            #         messages.display_module_search(moduleName, module)
