"""

Module handling functionality for Empire.

Right now, just loads up all modules from the
install path in the common config.

"""

import fnmatch
import os
import imp
import messages
import helpers


class Modules:

    def __init__(self, MainMenu, args):

        self.mainMenu = MainMenu

        # pull the database connection object out of the main menu
        self.conn = self.mainMenu.conn
        self.args = args

        # module format:
        #     [ ("module/name", instance) ]
        self.modules = {}

        self.load_modules()


    def load_modules(self, rootPath=''):
        """
        Load Empire modules from a specified path, default to
        installPath + "/lib/modules/*"
        """
        
        if rootPath == '':
            rootPath = "%slib/modules" % (self.mainMenu.installPath)

        pattern = '*.py'
        print helpers.color("[*] Loading modules from: %s" % (rootPath))
         
        for root, dirs, files in os.walk(rootPath):
            for filename in fnmatch.filter(files, pattern):
                filePath = os.path.join(root, filename)

                # don't load up any of the templates
                if fnmatch.fnmatch(filename, '*template.py'):
                    continue

                # extract just the module name from the full path
                moduleName = filePath.split(rootPath)[-1][0:-3]

                if rootPath != "%slib/modules/" % (self.mainMenu.installPath):
                    moduleName = "external/%s" %(moduleName)

                # instantiate the module and save it to the internal cache
                self.modules[moduleName] = imp.load_source(moduleName, filePath).Module(self.mainMenu, [])


    def reload_module(self, moduleToReload):
        """
        Reload a specific module from the install + "/lib/modules/*" path
        """

        rootPath = "%s/lib/modules/" % (self.mainMenu.installPath)
        pattern = '*.py'
         
        for root, dirs, files in os.walk(rootPath):
            for filename in fnmatch.filter(files, pattern):
                filePath = os.path.join(root, filename)

                # don't load up the template
                if filename == 'template.py': continue
                
                # extract just the module name from the full path
                moduleName = filePath.split("/lib/modules/")[-1][0:-3]

                # check to make sure we've found the specific module
                if moduleName.lower() == moduleToReload.lower():
                    # instantiate the module and save it to the internal cache
                    self.modules[moduleName] = imp.load_source(moduleName, filePath).Module(self.mainMenu, [])


    def search_modules(self, searchTerm):
        """
        Search currently loaded module names and descriptions.
        """

        print ''

        for moduleName, module in self.modules.iteritems():

            if searchTerm.lower() == '' or searchTerm.lower() in moduleName.lower() or searchTerm.lower() in module.info['Description'].lower():
                messages.display_module_search(moduleName, module)

            # for comment in module.info['Comments']:
            #     if searchTerm.lower() in comment.lower():
            #         messages.display_module_search(moduleName, module)
