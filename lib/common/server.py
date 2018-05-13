"""
Server class for Empire. Allows multiple users to connect to a single empire instance.
"""

from pydispatch import dispatcher

# Empire imports
import empire
import helpers
import messages
import agents
import listeners
import modules
import stagers
import credentials
import plugins
import users
from files import fetcher
from events import log_event
from zlib_wrapper import compress
from zlib_wrapper import decompress

# server imports
import sys
import sqlite3
import os
import hashlib
import time
import fnmatch
import shlex
import marshal
import pkgutil
import importlib
import base64
import threading
import json
import StringIO
import copy
import ssl
from flask_socketio import SocketIO, join_room, leave_room, disconnect, send, emit
from flask import Flask, request


class Server():
    """
    The Server class for the server is responsible for maintaining client connections and managing empire
    """

    def __init__(self, args=None):
        
        # Set up the event handling system
        dispatcher.connect(self.handle_event, sender=dispatcher.Any)

        # globalOptions[optionName] = (value, required, description)

        self.globalOptions = {}

        # plugins

        self.loadedPlugins = {}

        # Agent results cache/buffer
        self.historyBuffer = {}

        

        # empty database object
        self.conn = self.database_connect()
        time.sleep(1)

	    # initiate socketio
        self.app = Flask(__name__)
        self.socketio = SocketIO(self.app, async_mode='threading')
        self.lock = threading.Lock()
        (self.isroot, self.installPath, self.ipWhiteList, self.ipBlackList, self.obfuscate, self.obfuscateCommand) = helpers.get_config('rootuser, install_path,ip_whitelist,ip_blacklist,obfuscate,obfuscate_command')
        self.args = args
        # instantiate the agents, listeners, and stagers objects
        self.agents = agents.Agents(self, args=args)
        self.credentials = credentials.Credentials(self, args=args)
        self.stagers = stagers.Stagers(self, args=args)
        self.modules = modules.Modules(self, args=args)
        self.listeners = listeners.Listeners(self, args=args)
        self.users = users.Users(self, args=args)
        self.resourceQueue = []
        #A hashtable of autruns based on agent language
        self.autoRuns = {}
        self.fetcher = fetcher(self, args=args)

        # print the loading menu
        messages.loading()

    def get_db_connection(self):
        """
        Returns the 
        """
        self.lock.acquire()
        self.conn.row_factory = None
        self.lock.release()
        return self.conn

    def handle_event(self, signal, sender):
        """
        Whenever an event is received from the dispatcher, log it to the DB,
        decide whether it should be printed, and if so, print it.
        If self.args.debug, also log all events to a file
        """

        # load up the signal so we can inspect it
        try:
            signal_data = json.loads(signal)
        except ValueError:
            print(helpers.color("[!] Error: bad signal recieved {} from sender {}".format(signal, sender)))
            return

        # this should probably be set in the event itself but we can check
        # here (and for most the time difference won't matter so it's fine)
        if 'timestamp' not in signal_data:
            signal_data['timestamp'] = helpers.get_datetime()

        # if this is related to a task, set task_id; this is its own column in
        # the DB (else the column will be set to None/null)
        task_id = None
        if 'task_id' in signal_data:
            task_id = signal_data['task_id']

        event_data = json.dumps({'signal': signal_data, 'sender': sender})

        # emit any signal that should be printed
        if "agents" in sender:
            
            agentName = sender.split('/')[-1]

            if "[+] Initial agent" in signal:
		self.socketio.emit('agentNew', {'Result':signal_data['message']})
                # create a new results buffer object whenever a new agent checks in
                self.historyBuffer[agentName] = StringIO.StringIO()
            
            elif "returned results" in signal:
                results = {'Agent':agentName,'Result':self.agents.get_agent_results_db(agentName)}
		if results:
		    self.socketio.emit('agentData', {'Result':results})
                # check to make sure the size of the agent results will not exceed the limit when added to the buffer
                if (self.historyBuffer[agentName].len + len(results)) <= 512000:
                    self.historyBuffer[agentName].write(results)
                else:
                    self.historyBuffer[agentName] = StringIO.StringIO()
                    self.historyBuffer[agentName].write(results)
            
            elif ("[+] Listener for" in signal) and ("updated to" in signal):
                send({'Listeners': signal_data['message']})

            elif "[!] Agent" in signal and "exiting" in signal:
                send({'Agents': signal_data['message']})

            elif "WARNING" in signal or "attempted overwrite" in signal:
                send({'Empire': signal_data['message']})

            elif "on the blacklist" in signal:
                send({'Empire':signal_data['message']})

        elif "EmpireServer" in sender:
            if "[!] Error starting listener" in signal:
                send({'Empire':signal_data['message']})

        elif "Listeners" in sender:
            send({'Empire':signal_data['message']})

        elif "Users" in sender:
            send({'Users':signal_data['message']})


    def database_connect(self):
        """
        Connect to the default database at ./data/empire.db.
        """
        try:
            # set the database connectiont to autocommit w/ isolation level
            self.conn = sqlite3.connect('./data/empire.db', check_same_thread=False)
            self.conn.text_factory = str
            self.conn.isolation_level = None
            return self.conn

        except Exception as e:
            print helpers.color("[!] Could not connect to database: {}".format(str(e)))
            print helpers.color("[!] Please run database_setup.py")
            sys.exit()

    
    def start_server(self):
        """
        Start the Empire team server
        """

        ####################################################################
        #    socketIO Server guide:
        #       
        #    - Any client may connect to the server but all custom events require authentication.
        #    - Clients can emit the 'login' custom event to do so. The data should be json (serialized) and include both a username and password field.
        #    - Once the disconnect event occurs on the user is removed from the users table
        #
        #   
        #    - There are custom events for each menu/class per se:
        #    - listeners, modules, agents, stagers, files
        #    - Data sent from the client for any custom event should be in the following json format
        #    * - required arguments
        #
        #   Event - listeners
        #         - Action: VIEW, KILL, OPTIONS, EXECUTE
        #         - Arguments _____________
        #           -VIEW    --- Name
        #           -KILL    --- Name*
        #           -OPTIONS --- Type*
        #           -EXECUTE --- Type*,Options
        #
        #   Event - modules
        #         - Action: VIEW, EXECUTE
        #         - Arguments: arguments can vary per action, per event.
        #   
        #   Event - agents
        #         - Action: VIEW, KILL, INTERACT, EXECUTE, RETURN
        #         - Arguments ______________
        #           - VIEW   --- Name
        #           - KILL   --- Name*
        #           - INTERACT --- Name*
        #           - EXECUTE --- Name*,Command
        #           - RETURN --- Name*
        #
        #   Event - files
        #         - Action: UPLOAD, DOWNLOAD, VIEW
        #         - Arguments _____________
        #           - VIEW --- file_type* (module_output, download, screenshot)
        #           - UPLOAD --- sessionID*, file_data* (base64 encoded), filename*
        #           - DOWNLOAD --- fileID*
        #
        #   Event - stagers
        #         - Action: VIEW, EXECUTE
        #         - Arguments: _______________
        #           - VIEW --- stager_name 
        #           - EXECUTE --- stager_name*,Listener*
        ####################################################################


        @self.socketio.on('login')
        def handle_login(data):
            """
            Authenticate clients. Should be called before anything else, after connecting
            """
            if data['username'] and data['password']:
                if self.users.authenticate_user(request.sid, data['username'], data['password']):
                    emit('user_login', {"Result":"Logon success (%s)" % data['username']})
                    self.socketio.emit('users', {"Result":"Logon success (%s)" % data['username']})
                else:
                    emit('user_login', {"Result":"Logon failure (%s)" % data['username']})
            else:
                emit('user_login',{"Result":"missing username and/or password"})


        @self.socketio.on('connect')
        def handle_connect():
	    """
            Handle when new clients connect. Authentication is not required here. Only when accessing any of the custom events
            """
            signal = json.dumps({
                'print': False,
                'message':"New client session started with sid: {}".format(request.sid)
            })
            dispatcher.send(signal, sender="EmpireServer")
            emit('new_session', {"message": "Session initiated"})

        @self.socketio.on('disconnect')
        def handle_disconnect():
            """
            Handle when a client disconnects
            """
            self.users.remove_user(request.sid)
            emit('message', {"message": "Session disconnected"})

        @self.socketio.on('users')
        def handle_users_event(data):
            """
            Handle all client messages for the users event
            """

            if self.users.is_authenticated(request.sid):
                if data['Action'] and data['Action'] == 'VIEW':
                    users = self.users.get_users()
                    emit('users', {"Result":users})
        
        @self.socketio.on('stagers')
        def handle_stagers_event(data):
            """
            Handles all client messages for the 'stagers' event
            """

            if self.users.is_authenticated(request.sid):
                stagers = ""
                if data['Action'] and data['Action'] == 'VIEW':
                    if data['Arguments'] and data['Arguments']['stager_name'] == '':
                        stagers = []
                        for stagerName, stager in self.stagers.stagers.iteritems():
                            info = copy.deepcopy(stager.info)
                            info['options'] = stager.options
                            info['Name'] = stagerName
                            stagers.append(info)
                    elif data['Arguments'] and data['Arguments']['stager_name'] != '':
                        stager_name = data['Arguments']['stager_name']
                        stagers = []
                        if stager_name not in self.stagers.stagers:
                            stagers.append("{} is not a valid stager name".format(stager_name))
                        else:
                            for stagerName, stager in self.stagers.stagers.iteritems():
                                if stagerName == stager_name:
                                    info = copy.deepcopy(stager.info)
                                    info['options'] = stager.options
                                    info['Name'] = stagerName
                                    stagers.append(info)



                    send({"Result": stagers})

                elif data['Action'] and data['Action'] == 'EXECUTE':
                    if data['Arguments'] and data['Arguments']['stager_name'] != '' and data['Arguments']['Listener'] != '':
                        stager_name = data['Arguments']['stager_name']
                        listener = data['Arguments']['Listener']
                        stagers = []
                        if stager_name not in self.stagers.stagers:
                            stagers.append("{} is not a valid stager name".format(stager_name))
                        else:
                            stager = self.stagers.stagers[stager_name]
                            # set all passed options
                            for option, values in data['Arguments'].iteritems():
                                if option != 'StagerName':
                                    if option not in stager.options:
                                        send({'Result': 'Invalid option {}, check capitalization.'.format(option)})

                                    stager.options[option]['Value'] = values
                            
                            # validate stager options
                            for option, values in stager.options.iteritems():
                                if values['Required'] and ((not values['Value']) or (values['Value'] == '')):
                                    send({'Result': 'required stager options missing'})

                            stagerOut = copy.deepcopy(stager.options)

                            if ('OutFile' in stagerOut) and (stagerOut['OutFile']['Value'] != ''):
                                # if the output was intended for a file, return the base64 encoded text
                                stagerOut['Output'] = base64.b64encode(stager.generate())
                                stagers.append(stagerOut)
                            else:
                                # otherwise return the text of the stager generation
                                stagerOut['Output'] = stager.generate()
                                stagers.append(stagerOut)
                            
                            send({'Result':stagers})

                    else:
                        send({'Result':'Missing required argument'})
                            

            else:
                send({"Result": "Unauthenticated"})


        @self.socketio.on('agents')
        def handle_agents_event(data):
            """
            Handle all client messages for the agents event
            """

            if self.users.is_authenticated(request.sid):
                if data['Action'] and data['Action'] == 'VIEW':
                    agents = []
                    results = self.agents.get_agents_db()

                    for activeAgent in results:
                        [nonce, jitter, results, servers, internal_ip, working_hours, session_key, children, functions, checkin_time, hostname, ID, delay, username, kill_date, parent, process_name, listener, process_id, profile, os_details, lost_limit, taskings, name, language, external_ip, session_id, lastseen_time, language_version, high_integrity] = activeAgent.values()
                        agents.append({"ID":ID, "session_id":session_id, "listener":listener, "name":name, "language":language, "language_version":language_version, "delay":delay, "jitter":jitter, "external_ip":external_ip, "internal_ip":internal_ip, "username":username, "high_integrity":high_integrity, "process_name":process_name, "process_id":process_id, "hostname":hostname, "os_details":os_details, "session_key":session_key.decode('latin-1').encode("utf-8"), "nonce":nonce, "checkin_time":checkin_time, "lastseen_time":lastseen_time, "parent":parent, "children":children, "servers":servers, "profile":profile,"functions":functions, "kill_date":kill_date, "working_hours":working_hours, "lost_limit":lost_limit, "taskings":taskings, "results":results})
                    
                    emit('agents',{'Result':agents})

                elif data['Action'] and data['Action'] == 'VIEW' and data['Arguments']['Name']:
                    agent_name = data['Arguments']['Name']
                    agents = []

                    results = self.agents.get_agent_db(agent_name)
                    for activeAgent in results:
                        [ID, session_id, listener, name, language, language_version, delay, jitter, external_ip, internal_ip, username, high_integrity, process_name, process_id, hostname, os_details, session_key, nonce, checkin_time, lastseen_time, parent, children, servers, profile, functions, kill_date, working_hours, lost_limit, taskings, results] = activeAgent.values()
                        agents.append({"ID":ID, "session_id":session_id, "listener":listener, "name":name, "language":language, "language_version":language_version, "delay":delay, "jitter":jitter, "external_ip":external_ip, "internal_ip":internal_ip, "username":username, "high_integrity":high_integrity, "process_name":process_name, "process_id":process_id, "hostname":hostname, "os_details":os_details, "session_key":session_key.decode('latin-1').encode("utf-8"), "nonce":nonce, "checkin_time":checkin_time, "lastseen_time":lastseen_time, "parent":parent, "children":children, "servers":servers, "profile":profile,"functions":functions, "kill_date":kill_date, "working_hours":working_hours, "lost_limit":lost_limit, "taskings":taskings, "results":results})

                    emit('agents',{'Results':agents})
                
                elif data['Action'] and data['Action'] == 'KILL' and data['Arguments']['Name']:
                    agent_name = data['Arguments']['Name']
                    userName = self.users.get_user_from_sid(request.sid)
                    if agent_name.lower() == "all":
                        agentNameIDs = self.agents.get_agent_ids_db()
                    else:
                        agentNameIDs = self.agents.get_agent_id_db(agent_name)

                    if not agentNameIDs or len(agentNameIDs) == 0:
                        send({'Result': 'agent name {} not found'.format(agent_name)})
		   
                    if isinstance(agentNameIDs,basestring):
                        agentNameIDs = agentNameIDs.split() 
                        
                    for agentNameID in agentNameIDs:
                        agentSessionID = agentNameID

                        # task the agent to exit
                        msg = "{} tasked agent {} to exit".format(userName,agentSessionID)
                        username = self.users.get_user_from_sid(request.sid)
                        self.users.log_user_event("{} tasked agent {} to exit".format(username, agentNameID))
                        self.agents.save_agent_log(agentSessionID, msg)
                        self.agents.add_agent_task_db(agentSessionID, 'TASK_EXIT')

                        send({'Result':msg})

                elif data['Action'] and data['Action'] == 'EXECUTE' and data['Arguments']['Name']:
                    agent_name = data['Arguments']['Name']
                    userName = self.users.get_user_from_sid(request.sid)
                    if agent_name.lower() == "all":
                        agentNameIDs = self.agents.get_agent_ids_db()
                    else:
                        agentNameIDs = self.agents.get_agent_id_db(agent_name)

                    if not agentNameIDs or len(agentNameIDs) == 0:
                        send({'Result': 'agent name {} not found'.format(agent_name)})                

                    if not data['Arguments']['Command']:
                        send({'Result':'Failed. Missing command argument'})

                    command = data['Arguments']['Command']

                    if not isinstance(agentNameIDs,list):
                        agentNameIDs = agentNameIDs.split()

                    for agentNameID in agentNameIDs:
                        # add task command to agent taskings
                        msg = "tasked agent {} to run command {}".format(agentNameID, command)
                        self.agents.save_agent_log(agentNameID, msg)
                        username = self.users.get_user_from_sid(request.sid)
                        self.users.log_user_event("{} tasked agent {} to run command {}".format(username, agentNameID, command))
                    	self.socketio.emit('message', {"Result":"{} tasked agent {} to run command {}".format(username, agentNameID, command)})
                        #Update other users console with the command
                        results = {'Agent':agentNameID,"Result":command,"User":username}
                        self.socketio.emit('agentCommand', {"Result":results}, include_self=False)
                        taskID = self.agents.add_agent_task_db(agentNameID, "TASK_SHELL", command)

                    #self.socketio.emit('message', {"Result":"Success - TaskID: {}".format(taskID)})

                elif data['Action'] and data['Action'] == 'INTERACT' and data['Arguments']['Name']:
                    agent_name = data['Arguments']['Name']
                    agentNameIDs = self.agents.get_agent_id_db(agent_name)

                    if not agentNameIDs or len(agentNameIDs) == 0:
                        send({'Result': 'agent name {} not found'.format(agent_name)})

                    else:
                        # Grab the agent log file                        
                        logPath = os.path.abspath("./downloads/%s/agent.log" % agentNameIDs)
                        logFile = open(logPath,'r')
                        logResults = unicode(logFile.read(), errors='replace')
                        self.socketio.emit('agentData', {'Result': {'Agent':agentNameIDs,'Result':logResults}})
                        #join_room(agentNameIDs)
                        # Get the results history for this agent from the cache
                        #agentResults = self.historyBuffer[agentNameIDs].getvalue()
                        #result = json.dumps({
                        #    'message':'interacting with {}'.format(agentNameIDs),
                        #    'agentResultsCache':agentResults
                        #})
                        #send({'Result':result})

                elif data['Action'] and data['Action'] == 'RETURN' and data['Arguments']['Name']:
                    agent_name = data['Arguments']['Name']
                    agentNameIDs = self.agents.get_agent_id_db(agent_name)

                    if not agentNameIDs or len(agentNameIDs) == 0:
                        send({'Result': 'agent name {} not found'.format(agent_name)})

                    else:
                        leave_room(agentNameIDs)
                        send({'Result': 'No longer interacting with agent {}'.format(agentNameIDs)})

        @self.socketio.on('listeners')
        def handle_listener_event(data):
            """
            Handles all client messages for 'listeners' event
            """

            if self.users.is_authenticated(request.sid):
                listeners = ""
                if data['Action'] and data['Action'] == 'VIEW':
                    activeListenersRaw = self.listeners.get_listener_names()
                    listeners = []


                    for activeListener in activeListenersRaw:
                        listenerObject = self.listeners.activeListeners[activeListener]
                        name = activeListener
                        module = listenerObject['moduleName']
                        ID = self.listeners.get_listener_id(activeListener)
                        options = listenerObject['options']
                        listeners.append({'ID':ID, 'name':name, 'module':module, 'options':options })

                    emit('listeners',{'Result':listeners})

                elif data['Action'] and data['Action'] == 'VIEW' and data['Arguments']['Name']:
                    listener_name = data['Arguments']['Name']
                    activeListenersRaw = self.listeners.activeListeners[listener_name]
                    activeListenersRaw = [activeListenersRaw]
                    listeners = []

                    for activeListener in activeListenersRaw:
                        [name, module, options] = activeListener[listener_name].values()
                        if name == listener_name:
                            ID = self.listeners.get_listener_id(listener_name)
                            listeners.append({'ID':ID, 'name':name, 'module':module, 'options':options })

                    
                    emit('listeners',{'Result':listeners})

                elif data['Action'] and data['Action'] == 'OPTIONS':
                    options = {}
                    for ltype in self.listeners.loadedListeners:
                        options[ltype] = self.listeners.loadedListeners[ltype].options

                    emit('listenerOptions',{'Result':options}) 
                
                elif data['Action'] and data['Action'] == 'OPTIONS' and data['Arguments']['Type']:
                    listener_type = data['Arguments']['Type']

                    if listener_type.lower() not in self.listeners.loadedListeners:
                        emit('listenerOptions',{'Result':'listener type {} not found'.format(listener_type)})

                    options = self.listeners.loadedListeners[listener_type].options
                    emit('listenerOptions',{'Result':options})

                elif data['Action'] and data['Action'] == 'KILL' and data['Arguments']['Name']:
                    listener_name = data['Arguments']['Name']

                    if listener_name.lower() == "all":
                        activeListenersRaw = self.listeners.get_listener_names()
                        for activeListener in activeListenersRaw:
                            username = self.users.get_user_from_sid(request.sid)
                            self.users.log_user_event("{} killed listener {}".format(username, activeListener))
                            self.listeners.kill_listener(activeListener)

                        emit('listeners',{'Result':'Success'})

                    else:
                        if listener_name != "" and self.listeners.is_listener_valid(listener_name):
                            self.listeners.kill_listener(listener_name)
                            emit('listeners',{'Result': 'Success'})
                        else:
                            emit('listeners',{'Result':'listener name {} not found'.format(listener_name)})

                elif data['Action'] and data['Action'] == 'EXECUTE' and data['Arguments']['Type']:
                    listener_type = data['Arguments']['Type']

                    if listener_type.lower() not in self.listeners.loadedListeners:
                        emit('listeners',{'Result':'listener type {} not found'.format(listener_type)})

                    listenerObject = self.listeners.loadedListeners[listener_type]

                    if data['Arguments']['Options']:
                        # Options aren't required
                        for option, values in data['Arguments']['Options'].iteritems():
                            if option == "Name":
                                listenerName = values

                            returnVal = self.listeners.set_listener_option(listener_type, option, values)
                            if not returnVal:
                                emit('listeners',{'Result':'error setting listener value {} with option {}'.format(option, values)})
                        
                    
                        self.listeners.start_listener(listener_type, listenerObject)
                        username = self.users.get_user_from_sid(request.sid)
                        self.users.log_user_event("{} started listener {}".format(username, listenerName))

                    listenerID = self.listeners.get_listener_id(listenerName)
                    if listenerID:
                        emit('listeners',{'Result':'listener {} successfully started'.format(listenerName)})
                    else:
                        emit('listeners',{'Result': 'failed to start listener {}'.format(listenerName)})

                else:
                    emit('listeners',{'Result':'Missing or incorrect listener action'})

            else:
                emit('listeners',{'Result':'Authorization required'})
        
        @self.socketio.on("files")
        def handle_files_event(data):
            """
            Handles all client messages for the 'files' events
            """
            if self.users.is_authenticated(request.sid):
                if data['ACTION'] and data['ACTION'] == 'VIEW' and (data['Arguments']['file_type']):
                    results = self.fetcher.get_files_by_type(file_type=data['Arguments']['file_type'])
                    emit('files',{'Result':results})

                elif (data['ACTION'] and data['ACTION'] == 'UPLOAD') and (data['Arguments']['file_data']):
                    raw_data = helpers.decode_base64(data['Arguments']['file_data'])
                    sessionID = data['Arguments']['sessionID']
                    filename = data['Arguments']['filename']

                    if self.agents.is_agent_present(sessionID):
                        lang = self.agents.get_language_db(sessionID)
                    else:
                        emit('files',{'Result':'Agent doesn\'t exist'})
                    
                    if helpers.get_file_size(raw_data) > 1048576:
                        emit('files',{'Result':'File is too large. Upload limit is 1MB'})
                    
                    if lang.startswith('po'):
                        username = self.users.get_user_from_sid(request.sid)
                        self.users.log_user_event("{} tasked agent to upload {} : {}".format(username, filename, helpers.get_file_size(raw_data)))

                        raw_data = helpers.encode_base64(raw_data)
                        taskdata = filename + "|" + raw_data
                        self.agents.add_agent_task_db(sessionID, "TASK_UPLOAD", taskdata)
                        emit('files',{'Result':'Tasked agent to upload file'})
                    elif lang.startswith('py'):
                        username = self.users.get_user_from_sid(request.sid)
                        self.users.log_user_event("{} tasked agent to upload {} : {}".format(username, filename, helpers.get_file_size(raw_data)))

                        # compress data before we base64
                        c = compress.compress()
                        start_crc32 = c.crc32_data(raw_data)
                        comp_data = c.comp_data(raw_data, 9)
                        raw_data = c.build_header(comp_data, start_crc32)
                        # get final file size
                        raw_data = helpers.encode_base64(raw_data)

                        # upload packets -> "filename | script data"
                        taskdata = filename + "|" + raw_data
                        self.agents.add_agent_task_db(sessionID, "TASK_UPLOAD", taskdata)
                        emit('files',{'Result':'Tasked agent to upload file'})

                elif (data['ACTION'] and data['ACTION'] == 'DOWNLOAD') and (data['Arguments']['fileID']):
                    """
                    Download files shown in the files table from the server. Not directly from agents
                    """
                    enc_file = self.fetcher.get_file(fileID=data['Arguments']['fileID'])
                    if enc_file != None:
                        emit('files',{'Result':enc_file})
                    else:
                        emit('files',{'Result':""})

        # wrap the Flask connection in SSL and start it
        certPath = os.path.abspath("./data/")

        # support any version of tls
        pyversion = sys.version_info
        if pyversion[0] == 2 and pyversion[1] == 7 and pyversion[2] >= 13:
            proto = ssl.PROTOCOL_TLS
        elif pyversion[0] >= 3:
            proto = ssl.PROTOCOL_TLS
        else:
            proto = ssl.PROTOCOL_SSLv23

        try:
            context = ssl.SSLContext(proto)
            context.load_cert_chain("{}/empire-chain.pem".format(certPath), "{}/empire-priv.key".format(certPath))
            print helpers.color("[+] Empire Collaboration Server started:\n Host => 0.0.0.0 \n Port => {} \n Password => {}".format(self.args.port, self.args.shared_password))
            #self.socketio.run(self.app, host='0.0.0.0', port=int(self.args.port))
            self.socketio.run(self.app, host='0.0.0.0', port=int(self.args.port), ssl_context=context)
        except KeyboardInterrupt:
            print helpers.color("[+] Shutting down server")
            sys.exit()
        
