"""

Listener handling functionality for Empire.

Handles listener startup from the database, listener
shutdowns, and maintains the current listener 
configuration.

"""

import http
import helpers

from pydispatch import dispatcher
import hashlib
import sqlite3

class Listeners:

    def __init__(self, MainMenu, args=None):
        
        # pull out the controller objects
        self.mainMenu = MainMenu
        self.conn = MainMenu.conn
        self.agents = MainMenu.agents
        self.modules = None
        self.stager = None
        self.installPath = self.mainMenu.installPath

        # {listenerId : EmpireServer object}
        self.listeners = {}

        self.args = args

        # used to get a dict back from the query
        def dict_factory(cursor, row):
            d = {}
            for idx, col in enumerate(cursor.description):
                d[col[0]] = row[idx]
            return d

        # set the initial listener config to be the config defaults
        self.conn.row_factory = dict_factory
        cur = self.conn.cursor()
        cur.execute("SELECT staging_key,default_delay,default_jitter,default_profile,default_cert_path,default_port,default_lost_limit FROM config")
        defaults = cur.fetchone()
        cur.close()
        self.conn.row_factory = None

        # the current listener config options
        self.options = {
            'Name' : {
                'Description'   :   'Listener name.',
                'Required'      :   True,
                'Value'         :   'test'
            },
            'Host' : {
                'Description'   :   'Hostname/IP for staging.',
                'Required'      :   True,
                'Value'         :   "http://" + helpers.lhost() + ":" + defaults['default_port']
            },
            'Type' : {
                'Description'   :   'Listener type (native, pivot, hop, foreign, meter).',
                'Required'      :   True,
                'Value'         :   "native"
            },
            'RedirectTarget' : {
                'Description'   :   'Listener target to redirect to for pivot/hop.',
                'Required'      :   False,
                'Value'         :   ""
            },
            'StagingKey' : {
                'Description'   :   'Staging key for initial agent negotiation.',
                'Required'      :   True,
                'Value'         :   defaults['staging_key']
            },
            'DefaultDelay' : {
                'Description'   :   'Agent delay/reach back interval (in seconds).',
                'Required'      :   True,
                'Value'         :   defaults['default_delay']
            },
            'DefaultJitter' : {
                'Description'   :   'Jitter in agent reachback interval (0.0-1.0).',
                'Required'      :   True,
                'Value'         :   defaults['default_jitter']
            },
            'DefaultLostLimit' : {
                'Description'   :   'Number of missed checkins before exiting',
                'Required'      :   True,
                'Value'         :   defaults['default_lost_limit']
            },
            'DefaultProfile' : {
                'Description'   :   'Default communication profile for the agent.',
                'Required'      :   True,
                'Value'         :   defaults['default_profile']
            },
            'CertPath' : {
                'Description'   :   'Certificate path for https listeners.',
                'Required'      :   False,
                'Value'         :   defaults['default_cert_path']
            },
            'Port' : {
                'Description'   :   'Port for the listener.',
                'Required'      :   True,
                'Value'         :   defaults['default_port']
            },
            'KillDate' : {
                'Description'   :   'Date for the listener to exit (MM/dd/yyyy).',
                'Required'      :   False,
                'Value'         :   ''
            },
            'WorkingHours' : {
                'Description'   :   'Hours for the agent to operate (09:00-17:00).',
                'Required'      :   False,
                'Value'         :   ''
            }
        }


    def start_existing_listeners(self):
        """
        Startup any listeners that are current in the database.
        """

        cur = self.conn.cursor()
        cur.execute("SELECT id,name,host,port,cert_path,staging_key,default_delay,default_jitter,default_profile,kill_date,working_hours,listener_type,redirect_target,default_lost_limit FROM listeners")
        results = cur.fetchall()
        cur.close()

        # for each listener in the database, add it to the cache
        for result in results:
            
            # don't start the listener unless it's a native one
            if result[11] != "native":
                self.listeners[result[0]] = None

            else:
                lhost = http.host2lhost(result[2])
		port = result[3]
		
                # if cert_path is empty, no ssl is used
                cert_path = result[4]

                # build the handler server and kick if off
                server = http.EmpireServer(self.agents, lhost=lhost, port=port, cert=cert_path)

                # check if the listener started correctly
                if server.success:
                    server.start()

                    if (server.base_server()):
                        # store off this servers in the "[id] : server" object array
                        # only if the server starts up correctly
                        self.listeners[result[0]] = server


    def set_listener_option(self, option, value):
        """
        Set a listener option in the listener dictionary.
        """

        # parse and auto-set some host parameters
        if option == "Host":

            if not value.startswith("http"):
                # if there's a current ssl cert path set, assume this is https                
                if self.options['CertPath']['Value'] != "":
                    self.options['Host']['Value'] = "https://"+str(value)
                else:
                    # otherwise assume it's http
                    self.options['Host']['Value'] = "http://"+str(value)

                # if there's a port specified, set that as well
                parts = value.split(":")
                if len(parts) > 1:
                    self.options['Host']['Value'] = self.options['Host']['Value'] + ":" + str(parts[1])
                    self.options['Port']['Value'] = parts[1]

            elif value.startswith("https"):
                self.options['Host']['Value'] = value
                if self.options['CertPath']['Value'] == "":
                    print helpers.color("[!] Error: Please specify a SSL cert path first")
                    return False
                else:
                    parts = value.split(":")
                    # check if we have a port to extract
                    if len(parts) == 3:
                        # in case there's a resource uri at the end
                        parts = parts[2].split("/")
                        self.options['Port']['Value'] = parts[0]
                    else:
                        self.options['Port']['Value'] = "443"

            elif value.startswith("http"):
                self.options['Host']['Value'] = value
                parts = value.split(":")
                # check if we have a port to extract
                if len(parts) == 3:
                    # in case there's a resource uri at the end
                    parts = parts[2].split("/")
                    self.options['Port']['Value'] = parts[0]
                else:
                    self.options['Port']['Value'] = "80"

            return True

        elif option == "CertPath":
            self.options[option]['Value'] = value
            host = self.options["Host"]['Value']
            # if we're setting a SSL cert path, but the host is specific at http
            if host.startswith("http:"):
                self.options["Host"]['Value'] = self.options["Host"]['Value'].replace("http:", "https:")
            return True

        elif option == "Port":
            self.options[option]['Value'] = value
            # set the port in the Host configuration as well
            host = self.options["Host"]['Value']
            parts = host.split(":")
            if len(parts) == 2 or len(parts) == 3:
                self.options["Host"]['Value'] = parts[0] + ":" + parts[1] + ":" + str(value)
            return True

        elif option == "StagingKey":
            # if the staging key isn't 32 characters, assume we're md5 hashing it
            if len(value) != 32:
                self.options[option]['Value'] = hashlib.md5(value).hexdigest()
            return True

        elif option in self.options:

            self.options[option]['Value'] = value
            if option.lower() == "type":
                if value.lower() == "hop":
                    # set the profile for hop.php for hop
                    parts = self.options['DefaultProfile']['Value'].split("|")
                    self.options['DefaultProfile']['Value'] = "/hop.php|" + "|".join(parts[1:])
            return True

        else:
            print helpers.color("[!] Error: invalid option name")
            return False


    def get_listener_options(self):
        """
        Return all currently set listener options.
        """
        return self.options.keys()


    def kill_listener(self, listenerId):
        """
        Shut a listener down and remove it from the database.
        """
        self.shutdown_listener(listenerId)
        self.delete_listener(listenerId)


    def delete_listener(self, listenerId):
        """
        Shut down the server associated with a listenerId and delete the
        listener from the database.
        """

        # see if we were passed a name instead of an ID
        nameid = self.get_listener_id(listenerId)
        if nameid : listenerId = nameid

        # shut the listener down and remove it from the cache
        self.shutdown_listener(listenerId)

        # remove the listener from the database
        cur = self.conn.cursor()
        cur.execute("DELETE FROM listeners WHERE id=?", [listenerId])
        cur.close()


    def shutdown_listener(self, listenerId):
        """
        Shut down the server associated with a listenerId/name, but DON'T 
        delete it from the database.

        If the listener is a pivot, task the associated agent to kill the redirector.
        """
        
        try:
            # get the listener information
            [ID,name,host,port,cert_path,staging_key,default_delay,default_jitter,default_profile,kill_date,working_hours,listener_type,redirect_target,default_lost_limit] = self.get_listener(listenerId)

            listenerId = int(ID)

            if listenerId in self.listeners:
                # can't shut down hop, foreign, or meter listeners
                if listener_type == "hop" or listener_type == "foreign" or listener_type == "meter":
                    pass
                # if this listener is a pivot, task the associated agent to shut it down
                elif listener_type == "pivot":
                    print helpers.color("[*] Tasking pivot listener to shut down on agent " + name)
                    killCmd = "netsh interface portproxy reset"
                    self.agents.add_agent_task(name, "TASK_SHELL", killCmd)
                else:
                    # otherwise get the server object associated with this listener and shut it down
                    self.listeners[listenerId].shutdown()

                # remove the listener object from the internal cache
                del self.listeners[listenerId]

        except Exception as e:
            dispatcher.send("[!] Error shutting down listener " + str(listenerId), sender="Listeners")


    def get_listener(self, listenerId):
        """
        Get the a specific listener from the database.
        """
        
        # see if we were passed a name instead of an ID
        nameid = self.get_listener_id(listenerId)
        if nameid : listenerId = nameid

        cur = self.conn.cursor()
        cur.execute("SELECT id,name,host,port,cert_path,staging_key,default_delay,default_jitter,default_profile,kill_date,working_hours,listener_type,redirect_target,default_lost_limit FROM listeners WHERE id=?", [listenerId])
        listener = cur.fetchone()

        cur.close()
        return listener


    def get_listeners(self):
        """
        Return all listeners in the database.
        """
        cur = self.conn.cursor()
        cur.execute("SELECT * FROM listeners")
        results = cur.fetchall()
        cur.close()
        return results


    def get_listener_names(self):
        """
        Return all listener names in the database.
        """
        cur = self.conn.cursor()
        cur.execute("SELECT name FROM listeners")
        results = cur.fetchall()
        cur.close()
        results = [str(n[0]) for n in results]
        return results


    def get_listener_ids(self):
        """
        Return all listener IDs in the database.
        """
        cur = self.conn.cursor()
        cur.execute("SELECT id FROM listeners")
        results = cur.fetchall()
        cur.close()
        results = [str(n[0]) for n in results]
        return results


    def is_listener_valid(self, listenerID):
        """
        Check if this listener name or ID is valid/exists.
        """
        cur = self.conn.cursor()
        cur.execute('SELECT * FROM listeners WHERE id=? or name=? limit 1', [listenerID, listenerID])
        results = cur.fetchall()
        cur.close()
        return len(results) > 0


    def is_listener_empire(self, listenerID):
        """
        Check if this listener name is for Empire (otherwise for meter).
        """
        cur = self.conn.cursor()
        cur.execute('SELECT listener_type FROM listeners WHERE id=? or name=? limit 1', [listenerID, listenerID])
        results = cur.fetchall()
        cur.close()
        if results:
            if results[0][0].lower() == "meter":
                return False
            else:
                return True
        else:
            return None


    def get_listener_id(self, name):
        """
        Resolve a name or port to listener ID.
        """
        cur = self.conn.cursor()
        cur.execute('SELECT id FROM listeners WHERE name=?', [name])
        results = cur.fetchone()
        cur.close()
        if results:
            return results[0]
        else:
            return None


    def get_staging_information(self, listenerId=None, port=None, host=None):
        """
        Resolve a name or port to a agent staging information
            staging_key, default_delay, default_jitter, default_profile
        """

        stagingInformation = None

        if(listenerId):
            cur = self.conn.cursor()
            cur.execute('SELECT host,port,cert_path,staging_key,default_delay,default_jitter,default_profile,kill_date,working_hours,listener_type,redirect_target,default_lost_limit FROM listeners WHERE id=? or name=? limit 1', [listenerId, listenerId])
            stagingInformation = cur.fetchone()
            cur.close()

        elif(port):
            cur = self.conn.cursor()
            cur.execute("SELECT host,port,cert_path,staging_key,default_delay,default_jitter,default_profile,kill_date,working_hours,listener_type,redirect_target,default_lost_limit FROM listeners WHERE port=?", [port])
            stagingInformation = cur.fetchone()
            cur.close()

        # used to get staging info for hop.php relays
        elif(host):
            cur = self.conn.cursor()
            cur.execute("SELECT host,port,cert_path,staging_key,default_delay,default_jitter,default_profile,kill_date,working_hours,listener_type,redirect_target,default_lost_limit FROM listeners WHERE host=?", [host])
            stagingInformation = cur.fetchone()
            cur.close()            

        return stagingInformation


    def get_stager_config(self, listenerID):
        """
        Returns the (server, stagingKey, pivotServer, hop, defaultDelay) information for this listener.

        Used in stagers.py to generate the various stagers.
        """

        listener = self.get_listener(listenerID)

        if listener:
            # TODO: redo this SQL query so it's done by dict values
            name = listener[1]
            host = listener[2]
            port = listener[3]
            certPath = listener[4]
            stagingKey = listener[5]
            defaultDelay = listener[6]
            listenerType = listener[11]
            redirectTarget = listener[12]
            hop = False

            # if we have a pivot listener
            pivotServer = ""
            if listenerType == "pivot":
                # get the internal agent IP for this agent
                temp = self.agents.get_agent_internal_ip(name)
                if(temp):
                    internalIP = temp[0]
                else:
                    print helpers.color("[!] Agent for pivot listener no longer active.")
                    return ""

                if certPath != "":
                    pivotServer = "https://"
                else:
                    pivotServer = "http://"
                pivotServer += internalIP + ":" + str(port)

            elif listenerType == "hop":
                hop = True

            return (host, stagingKey, pivotServer, hop, defaultDelay)

        else:
            print helpers.color("[!] Error in listeners.get_stager_config(): no listener information returned")
            return None


    def validate_listener_options(self):
        """
        Validate all currently set listener options.
        """

        # make sure all options are set
        for option,values in self.options.iteritems():
            if values['Required'] and (values['Value'] == ''):
                return False

        # make sure the name isn't already taken
        if self.is_listener_valid(self.options['Name']['Value']):
            for x in xrange(1,20):
                self.options['Name']['Value'] = self.options['Name']['Value'] + str(x)
                if not self.is_listener_valid(self.options['Name']['Value']):
                    break
            if self.is_listener_valid(self.options['Name']['Value']):
                print helpers.color("[!] Listener name already used.")
                return False

        # if this is a pivot or hop listener, make sure we have a redirect listener target
        if self.options['Type']['Value'] == "pivot" or self.options['Type']['Value'] == "hop":
            if self.options['RedirectTarget']['Value'] == '':
                return False

        return True


    def add_listener_from_config(self):
        """
        Start up a new listener with the internal config information.
        """

        name = self.options['Name']['Value']
        host = self.options['Host']['Value']
        port = self.options['Port']['Value']
        certPath = self.options['CertPath']['Value']
        stagingKey = self.options['StagingKey']['Value']
        defaultDelay = self.options['DefaultDelay']['Value']
        defaultJitter = self.options['DefaultJitter']['Value']
        defaultProfile = self.options['DefaultProfile']['Value']
        killDate = self.options['KillDate']['Value']
        workingHours = self.options['WorkingHours']['Value']
        listenerType = self.options['Type']['Value']
        redirectTarget = self.options['RedirectTarget']['Value']
        defaultLostLimit = self.options['DefaultLostLimit']['Value']

        # validate all of the options
        if self.validate_listener_options():

            # if the listener name already exists, iterate the name 
            # until we have a valid one
            if self.is_listener_valid(name):
                baseName = name
                for x in xrange(1,20):
                    name = str(baseName) + str(x)
                    if not self.is_listener_valid(name):
                        break
            if self.is_listener_valid(name):
                return (False, "Listener name already used.")

            # don't actually start a pivot/hop listener, foreign listeners, or meter listeners
            if listenerType == "pivot" or listenerType == "hop" or listenerType == "foreign" or listenerType == "meter":

                # double-check that the host ends in .php for hop listeners
                if listenerType == "hop" and not host.endswith(".php"):
                    choice = raw_input(helpers.color("[!] Host does not end with .php continue? [y/N] "))
                    if choice.lower() == "" or choice.lower()[0] == "n":
                        return (False, "")

                cur = self.conn.cursor()
                results = cur.execute("INSERT INTO listeners (name, host, port, cert_path, staging_key, default_delay, default_jitter, default_profile, kill_date, working_hours, listener_type, redirect_target,default_lost_limit) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)", [name, host, port, certPath, stagingKey, defaultDelay, defaultJitter, defaultProfile, killDate, workingHours, listenerType, redirectTarget,defaultLostLimit] )

                # get the ID for the listener
                cur.execute("SELECT id FROM listeners where name=?", [name])
                result = cur.fetchone()
                cur.close()

                self.listeners[result[0]] = None
                return (True, name)

            else:
		lhost = http.host2lhost(host)
                # start up the server object
                server = http.EmpireServer(self.agents, lhost=lhost, port=port, cert=certPath)

                # check if the listener started correctly
                if server.success:
                    server.start()

                    if (server.base_server()):

                        # add the listener to the database if start up
                        cur = self.conn.cursor()
                        results = cur.execute("INSERT INTO listeners (name, host, port, cert_path, staging_key, default_delay, default_jitter, default_profile, kill_date, working_hours, listener_type, redirect_target, default_lost_limit) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)", [name, host, port, certPath, stagingKey, defaultDelay, defaultJitter, defaultProfile, killDate, workingHours, listenerType, redirectTarget,defaultLostLimit] )

                        # get the ID for the listener
                        cur.execute("SELECT id FROM listeners where name=?", [name])
                        result = cur.fetchone()
                        cur.close()

                        # store off this server in the "[id] : server" object array
                        #   only if the server starts up correctly
                        self.listeners[result[0]] = server
                        return (True, name)
                    else:
                        return (False, "Misc. error starting listener")

                else:
                    return (False, "Error starting listener on port %s, port likely already in use." %(port))

        else:
            return (False, "Required listener option missing.")


    def add_pivot_listener(self, listenerName, sessionID, listenPort):
        """
        Add a pivot listener associated with the sessionID agent on listenPort.

        This doesn't actually start a server, but rather clones the config
        for listenerName and sets everything in the database as appropriate.

        """

        # get the internal agent IP for this agent
        internalIP = self.agents.get_agent_internal_ip(sessionID)[0]
        if internalIP == "":
            print helpers.color("[!] Invalid internal IP retrieved for "+sessionID+", not adding as pivot listener.")

        # make sure there isn't already a pivot listener on this agent
        elif self.is_listener_valid(sessionID):
            print helpers.color("[!] Pivot listener already exists on this agent.")

        else:
            # get the existing listener options
            [ID,name,host,port,cert_path,staging_key,default_delay,default_jitter,default_profile,kill_date,working_hours,listener_type,redirect_target,defaultLostLimit] = self.get_listener(listenerName)

            cur = self.conn.cursor()

            if cert_path != "":
                pivotHost = "https://"
            else:
                pivotHost = "http://"
            pivotHost += internalIP + ":" + str(listenPort)

            # insert the pivot listener with name=sessionID for the pivot agent
            cur.execute("INSERT INTO listeners (name, host, port, cert_path, staging_key, default_delay, default_jitter, default_profile, kill_date, working_hours, listener_type, redirect_target,default_lost_limit) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)", [sessionID, pivotHost, listenPort, cert_path, staging_key, default_delay, default_jitter, default_profile, kill_date, working_hours, "pivot", name,defaultLostLimit] )

            # get the ID for the listener
            cur.execute("SELECT id FROM listeners where name=?", [sessionID])
            result = cur.fetchone()
            cur.close()

            # we don't actually have a server object, so just store None
            self.listeners[result[0]] = None


    def killall(self):
        """
        Kill all active listeners and remove them from the database.
        """
        # get all the listener IDs from the cache and delete each
        for listenerId in self.listeners.keys():
            self.kill_listener(listenerId)


    def shutdownall(self):
        """
        Shut down all active listeners but don't clear them from
        the database.

        Don't shut down pivot/hop listeners.
        """
        # get all the listener IDs from the cache and delete each
        for listenerId in self.listeners.keys():
            # skip pivot/hop listeners
            if self.listeners[listenerId]:
                self.shutdown_listener(listenerId)
