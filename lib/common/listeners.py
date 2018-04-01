
"""

Listener handling functionality for Empire.

"""
import sys
import fnmatch
import imp
import helpers
import os
import pickle
import hashlib
import copy
import json

from pydispatch import dispatcher

class Listeners:
    """
    Listener handling class.
    """

    def __init__(self, MainMenu, args):

        self.mainMenu = MainMenu
        self.args = args
        self.conn = MainMenu.conn

        # loaded listener format:
        #     {"listenerModuleName": moduleInstance, ...}
        self.loadedListeners = {}

        # active listener format (these are listener modules that are actually instantiated)
        #   {"listenerName" : {moduleName: 'http', options: {setModuleOptions} }}
        self.activeListeners = {}

        self.load_listeners()
        self.start_existing_listeners()


    def load_listeners(self):
        """
        Load listeners from the install + "/lib/listeners/*" path
        """

        rootPath = "%s/lib/listeners/" % (self.mainMenu.installPath)
        pattern = '*.py'
        print helpers.color("[*] Loading listeners from: %s" % (rootPath))

        for root, dirs, files in os.walk(rootPath):
            for filename in fnmatch.filter(files, pattern):
                filePath = os.path.join(root, filename)

                # don't load up any of the templates
                if fnmatch.fnmatch(filename, '*template.py'):
                    continue

                # extract just the listener module name from the full path
                listenerName = filePath.split("/lib/listeners/")[-1][0:-3]

                # instantiate the listener module and save it to the internal cache
                self.loadedListeners[listenerName] = imp.load_source(listenerName, filePath).Listener(self.mainMenu, [])


    def set_listener_option(self, listenerName, option, value):
        """
        Sets an option for the given listener module or all listener module.
        """

        # for name, listener in self.listeners.iteritems():
        #     for listenerOption, optionValue in listener.options.iteritems():
        #         if listenerOption == option:
        #             listener.options[option]['Value'] = str(value)

        for name, listenerObject in self.loadedListeners.iteritems():

            if (listenerName.lower() == 'all' or listenerName == name) and (option in listenerObject.options):

                # parse and auto-set some host parameters
                if option == 'Host':

                    if not value.startswith('http'):
                        parts = value.split(':')
                        # if there's a current ssl cert path set, assume this is https
                        if ('CertPath' in listenerObject.options) and (listenerObject.options['CertPath']['Value'] != ''):
                            protocol = 'https'
                            defaultPort = 443
                        else:
                            protocol = 'http'
                            defaultPort = 80

                    elif value.startswith('https'):
                        value = value.split('//')[1]
                        parts = value.split(':')
                        protocol = 'https'
                        defaultPort = 443

                    elif value.startswith('http'):
                        value = value.split('//')[1]
                        parts = value.split(':')
                        protocol = 'http'
                        defaultPort = 80

                    if len(parts) != 1 and parts[-1].isdigit():
                        # if a port is specified with http://host:port
                        listenerObject.options['Host']['Value'] = "%s://%s" % (protocol, value)
                        if listenerObject.options['Port']['Value'] == '':
                            listenerObject.options['Port']['Value'] = parts[-1]
                    elif listenerObject.options['Port']['Value'] != '':
                        # otherwise, check if the port value was manually set
                        listenerObject.options['Host']['Value'] = "%s://%s:%s" % (protocol, value, listenerObject.options['Port']['Value'])
                    else:
                        # otherwise use default port
                        listenerObject.options['Host']['Value'] = "%s://%s" % (protocol, value)
                        if listenerObject.options['Port']['Value'] == '':
                            listenerObject.options['Port']['Value'] = defaultPort

                    return True

                elif option == 'CertPath':
                    listenerObject.options[option]['Value'] = value
                    host = listenerObject.options['Host']['Value']
                    # if we're setting a SSL cert path, but the host is specific at http
                    if host.startswith('http:'):
                        listenerObject.options['Host']['Value'] = listenerObject.options['Host']['Value'].replace('http:', 'https:')
                    return True

                if option == 'Port':
                    listenerObject.options[option]['Value'] = value
                    return True

                elif option == 'StagingKey':
                    # if the staging key isn't 32 characters, assume we're md5 hashing it
                    value = str(value).strip()
                    if len(value) != 32:
                        stagingKeyHash = hashlib.md5(value).hexdigest()
                        print helpers.color('[!] Warning: staging key not 32 characters, using hash of staging key instead: %s' % (stagingKeyHash))
                        listenerObject.options[option]['Value'] = stagingKeyHash
                    else:
                        listenerObject.options[option]['Value'] = str(value)
                    return True

                elif option in listenerObject.options:

                    listenerObject.options[option]['Value'] = value

                    # if option.lower() == 'type':
                    #     if value.lower() == "hop":
                    #         # set the profile for hop.php for hop
                    #         parts = self.options['DefaultProfile']['Value'].split("|")
                    #         self.options['DefaultProfile']['Value'] = "/hop.php|" + "|".join(parts[1:])

                    return True

            # if parts[0].lower() == 'defaultprofile' and os.path.exists(parts[1]):
            #     try:
            #         open_file = open(parts[1], 'r')
            #         profile_data_raw = open_file.readlines()
            #         open_file.close()

            #         profile_data = [l for l in profile_data_raw if not l.startswith('#' and l.strip() != '')]
            #         profile_data = profile_data[0].strip("\"")

            #         self.mainMenu.listeners.set_listener_option(parts[0], profile_data)

            #     except Exception:
            #         print helpers.color("[!] Error opening profile file %s" % (parts[1]))

                else:
                    print helpers.color('[!] Error: invalid option name')
                    return False


    def start_listener(self, moduleName, listenerObject):
        """
        Takes a listener module object, starts the listener, adds the listener to the database, and
        adds the listener to the current listener cache.
        """

        category = listenerObject.info['Category']
        name = listenerObject.options['Name']['Value']
        nameBase = name

        if not listenerObject.validate_options():
            return

        i = 1
        while name in self.activeListeners.keys():
            name = "%s%s" % (nameBase, i)

        listenerObject.options['Name']['Value'] = name

        try:
            print helpers.color("[*] Starting listener '%s'" % (name))
            success = listenerObject.start(name=name)

            if success:
                listenerOptions = copy.deepcopy(listenerObject.options)
                self.activeListeners[name] = {'moduleName': moduleName, 'options':listenerOptions}
                pickledOptions = pickle.dumps(listenerObject.options)
                cur = self.conn.cursor()
                cur.execute("INSERT INTO listeners (name, module, listener_category, enabled, options) VALUES (?,?,?,?,?)", [name, moduleName, category, True, pickledOptions])
                cur.close()

                # dispatch this event
                message = "[+] Listener successfully started!"
                signal = json.dumps({
                    'print': True,
                    'message': message,
                    'listener_options': listenerOptions
                })
                dispatcher.send(signal, sender="listeners/{}/{}".format(moduleName, name))
            else:
                print helpers.color('[!] Listener failed to start!')

        except Exception as e:
            if name in self.activeListeners:
                del self.activeListeners[name]
            print helpers.color("[!] Error starting listener: %s" % (e))


    def start_existing_listeners(self):
        """
        Startup any listeners that are currently in the database.
        """
        oldFactory = self.conn.row_factory
        self.conn.row_factory = helpers.dict_factory
        cur = self.conn.cursor()
        cur.execute("SELECT id,name,module,listener_type,listener_category,options FROM listeners WHERE enabled=?", [True])
        results = cur.fetchall()
        cur.close()

        for result in results:
            listenerName = result['name']
            moduleName = result['module']
            nameBase = listenerName


            i = 1
            while listenerName in self.activeListeners.keys():
                listenerName = "%s%s" % (nameBase, i)

            # unpickle all the listener options
            options = pickle.loads(result['options'])

            try:
                listenerModule = self.loadedListeners[moduleName]

                for option, value in options.iteritems():
                    listenerModule.options[option] = value

                print helpers.color("[*] Starting listener '%s'" % (listenerName))
                if moduleName == 'redirector':
                    success = True
                else:
                    success = listenerModule.start(name=listenerName)

                if success:
                    listenerOptions = copy.deepcopy(listenerModule.options)
                    self.activeListeners[listenerName] = {'moduleName': moduleName, 'options':listenerOptions}
                    # dispatch this event
                    message = "[+] Listener successfully started!"
                    signal = json.dumps({
                        'print': True,
                        'message': message,
                        'listener_options': listenerOptions
                    })
                    dispatcher.send(signal, sender="listeners/{}/{}".format(moduleName, listenerName))
                else:
                    print helpers.color('[!] Listener failed to start!')

            except Exception as e:
                if listenerName in self.activeListeners:
                    del self.activeListeners[listenerName]
                print helpers.color("[!] Error starting listener: %s" % (e))

        self.conn.row_factory = oldFactory

    def enable_listener(self, listenerName):
        "Starts an existing listener and sets it to enabled"
        if listenerName in self.activeListeners.keys():
            print helpers.color("[!] Listener already running!")
            return False

        oldFactory = self.conn.row_factory
        self.conn.row_factory = helpers.dict_factory
        cur = self.conn.cursor()
        cur.execute("SELECT id,name,module,listener_type,listener_category,options FROM listeners WHERE name=?", [listenerName])
        result = cur.fetchone()
        if not result:
            print helpers.color("[!] Listener %s doesn't exist!" % listenerName)
            return False
        moduleName = result['module']
        options = pickle.loads(result['options'])
        try:
            listenerModule = self.loadedListeners[moduleName]

            for option, value in options.iteritems():
                listenerModule.options[option] = value

            print helpers.color("[*] Starting listener '%s'" % (listenerName))
            if moduleName == 'redirector':
                success = True
            else:
                success = listenerModule.start(name=listenerName)

            if success:
                print helpers.color('[+] Listener successfully started!')
                listenerOptions = copy.deepcopy(listenerModule.options)
                self.activeListeners[listenerName] = {'moduleName': moduleName, 'options': listenerOptions}
                cur.execute("UPDATE listeners SET enabled=? WHERE name=? AND NOT module=?", [True, listenerName, 'redirector'])
            else:
                print helpers.color('[!] Listener failed to start!')
        except Exception as e:
            traceback.print_exc()
            if listenerName in self.activeListeners:
                del self.activeListeners[listenerName]
            print helpers.color("[!] Error starting listener: %s" % (e))

        cur.close()
        self.conn.row_factory = oldFactory


    def kill_listener(self, listenerName):
        """
        Shut down the server associated with a listenerName and delete the
        listener from the database.

        To kill all listeners, use listenerName == 'all'
        """

        if listenerName.lower() == 'all':
            listenerNames = self.activeListeners.keys()
        else:
            listenerNames = [listenerName]

        for listenerName in listenerNames:
            if listenerName not in self.activeListeners:
                print helpers.color("[!] Listener '%s' not active!" % (listenerName))
                return False

            # shut down the listener and remove it from the cache
            if self.mainMenu.listeners.get_listener_module(listenerName) == 'redirector':
                # remove the listener object from the internal cache
                del self.activeListeners[listenerName]
                self.conn.row_factory = None
                cur = self.conn.cursor()
                cur.execute("DELETE FROM listeners WHERE name=?", [listenerName])
                cur.close()
                continue

            self.shutdown_listener(listenerName)

            # remove the listener from the database
            self.conn.row_factory = None
            cur = self.conn.cursor()
            cur.execute("DELETE FROM listeners WHERE name=?", [listenerName])
            cur.close()

    def delete_listener(self, listener_name):
        """
        Delete listener(s) from database.
        """

        try:
            old_factory = self.conn.row_factory
            self.conn.row_factory = helpers.dict_factory
            cur = self.conn.cursor()
            cur.execute("SELECT name FROM listeners")
            db_names = map(lambda x: x['name'], cur.fetchall())
            if listener_name.lower() == "all":
                names = db_names
            else:
                names = [listener_name]

            for name in names:
                if not name in db_names:
                    print helpers.color("[!] Listener '%s' does not exist!" % name)
                    return False

                if name in self.activeListeners.keys():
                    self.shutdown_listener(name)
                cur.execute("DELETE FROM listeners WHERE name=?", [name])

        except Exception, e:
            print helpers.color("[!] Error deleting listener '%s'" % name)

        cur.close()
        self.conn.row_factory = old_factory

    def shutdown_listener(self, listenerName):
        """
        Shut down the server associated with a listenerName, but DON'T
        delete it from the database.
        """

        if listenerName.lower() == 'all':
            listenerNames = self.activeListeners.keys()
        else:
            listenerNames = [listenerName]

        for listenerName in listenerNames:
            if listenerName not in self.activeListeners:
                print helpers.color("[!] Listener '%s' doesn't exist!" % (listenerName))
                return False

            # retrieve the listener module for this listener name
            activeListenerModuleName = self.activeListeners[listenerName]['moduleName']
            activeListenerModule = self.loadedListeners[activeListenerModuleName]

            if activeListenerModuleName == 'redirector':
                print helpers.color("[!] skipping redirector listener %s. Start/Stop actions can only initiated by the user." % (listenerName))
                continue

            # signal the listener module to shut down the thread for this particular listener instance
            activeListenerModule.shutdown(name=listenerName)

            # remove the listener object from the internal cache
            del self.activeListeners[listenerName]

    def disable_listener(self, listenerName):
        "Wrapper for shutdown_listener(), also marks listener as 'disabled' so it won't autostart"

        activeListenerModuleName = self.activeListeners[listenerName]['moduleName']
        cur = self.conn.cursor()
        if listenerName.lower() == "all":
            cur.execute("UPDATE listeners SET enabled=? WHERE NOT module=?", [False, "redirector"])
        else:
            cur.execute("UPDATE listeners SET enabled=? WHERE name=? AND NOT module=?", [False, listenerName.lower(), "redirector"])
        cur.close()
        self.shutdown_listener(listenerName)
        # dispatch this event
        message = "[*] Listener {} killed".format(listenerName)
        signal = json.dumps({
            'print': True,
            'message': message
        })
        dispatcher.send(signal, sender="listeners/{}/{}".format(activeListenerModuleName, listenerName))


    def is_listener_valid(self, name):
        return name in self.activeListeners


    def get_listener_id(self, name):
        """
        Resolve a name to listener ID.
        """
        oldFactory = self.conn.row_factory
        self.conn.row_factory = None
        cur = self.conn.cursor()
        cur.execute('SELECT id FROM listeners WHERE name=? or id=?', [name, name])
        results = cur.fetchone()
        cur.close()
        self.conn.row_factory = oldFactory

        if results:
            return results[0]
        else:
            return None


    def get_listener_name(self, listenerId):
        """
        Resolve a listener ID to a name.
        """
        cur = self.conn.cursor()
        cur.execute('SELECT name FROM listeners WHERE name=? or id=?', [listenerId, listenerId])
        results = cur.fetchone()
        cur.close()

        if results:
            return results[0]
        else:
            return None


    def get_listener_module(self, listenerName):
        """
        Resolve a listener name to the module used to instantiate it.
        """
        cur = self.conn.cursor()
        cur.execute('SELECT module FROM listeners WHERE name=?', [listenerName])
        results = cur.fetchone()
        cur.close()

        if results:
            return results[0]
        else:
            return None

    def get_listener_options(self):
        """
        Return the options for a listener type
        """
        cur = self.conn.cursor()
        cur.execute('SELECT options FROM listeners')
        results = cur.fetchall()
        cur.close()

        if results:
            return results[0][0]
        else:
            return None


    def get_listener_names(self):
        """
        Return all current listener names.
        """
        return self.activeListeners.keys()

    def get_inactive_listeners(self):
        """
        Returns any listeners that are not currently running
        """

        oldFactory = self.conn.row_factory
        self.conn.row_factory = helpers.dict_factory
        cur = self.conn.cursor()

        cur.execute("SELECT name,module,options FROM listeners")
        db_listeners = cur.fetchall()

        inactive_listeners = {}
        for listener in filter((lambda x: x['name'] not in self.activeListeners.keys()), db_listeners):
            inactive_listeners[listener['name']] = {'moduleName': listener['module'],
                                                    'options': pickle.loads(listener['options'])}

        cur.close()
        self.conn.row_factory = oldFactory
        return inactive_listeners


    def update_listener_options(self, listener_name, option_name, option_value):
        "Updates a listener option in the database"

        try:
            cur = self.conn.cursor()
            cur.execute('SELECT id,options FROM listeners WHERE name=?', [listener_name])
            listener_id, result = cur.fetchone()
            options = pickle.loads(result)
            if not option_name in options.keys():
                print helpers.color("[!] Listener %s does not have the option %s" % (listener_name, option_name))
                return
            options[option_name]['Value'] = option_value
            pickled_options = pickle.dumps(options)
            cur.execute('UPDATE listeners SET options=? WHERE id=?', [pickled_options, listener_id])
        except ValueError:
            print helpers.color("[!] Listener %s not found" % listenerName)
        cur.close()
