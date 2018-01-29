"""

Common terminal messages used across Empire.

Titles, agent displays, listener displays, etc.

"""

import os
import time
import textwrap

# Empire imports
import helpers


###############################################################
#
# Messages
#
###############################################################

def title(version):
    """
    Print the tool title, with version.
    """
    os.system('clear')
    print "================================================================"
    # print ' [Empire]  PowerShell/Python post-exploitation framework'
    print " [Empire]  Post-Exploitation Framework"
    print '================================================================'
    print " [Version] %s | [Web] https://github.com/empireProject/Empire" % (version)
    print '================================================================'
    print """
   _______ .___  ___. .______    __  .______       _______
  |   ____||   \/   | |   _  \  |  | |   _  \     |   ____|
  |  |__   |  \  /  | |  |_)  | |  | |  |_)  |    |  |__
  |   __|  |  |\/|  | |   ___/  |  | |      /     |   __|
  |  |____ |  |  |  | |  |      |  | |  |\  \----.|  |____
  |_______||__|  |__| | _|      |__| | _| `._____||_______|

"""

def loading():
    """
    Print and ascii loading screen.
    """

    print """
                              `````````
                         ``````.--::///+
                     ````-+sydmmmNNNNNNN
                   ``./ymmNNNNNNNNNNNNNN
                 ``-ymmNNNNNNNNNNNNNNNNN
               ```ommmmNNNNNNNNNNNNNNNNN
              ``.ydmNNNNNNNNNNNNNNNNNNNN
             ```odmmNNNNNNNNNNNNNNNNNNNN
            ```/hmmmNNNNNNNNNNNNNNNNMNNN
           ````+hmmmNNNNNNNNNNNNNNNNNMMN
          ````..ymmmNNNNNNNNNNNNNNNNNNNN
          ````:.+so+//:---.......----::-
         `````.`````````....----:///++++
        ``````.-/osy+////:::---...-dNNNN
        ````:sdyyydy`         ```:mNNNNM
       ````-hmmdhdmm:`      ``.+hNNNNNNM
       ```.odNNmdmmNNo````.:+yNNNNNNNNNN
       ```-sNNNmdh/dNNhhdNNNNNNNNNNNNNNN
       ```-hNNNmNo::mNNNNNNNNNNNNNNNNNNN
       ```-hNNmdNo--/dNNNNNNNNNNNNNNNNNN
      ````:dNmmdmd-:+NNNNNNNNNNNNNNNNNNm
      ```/hNNmmddmd+mNNNNNNNNNNNNNNds++o
     ``/dNNNNNmmmmmmmNNNNNNNNNNNmdoosydd
     `sNNNNdyydNNNNmmmmmmNNNNNmyoymNNNNN
     :NNmmmdso++dNNNNmmNNNNNdhymNNNNNNNN
     -NmdmmNNdsyohNNNNmmNNNNNNNNNNNNNNNN
     `sdhmmNNNNdyhdNNNNNNNNNNNNNNNNNNNNN
       /yhmNNmmNNNNNNNNNNNNNNNNNNNNNNmhh
        `+yhmmNNNNNNNNNNNNNNNNNNNNNNmh+:
          `./dmmmmNNNNNNNNNNNNNNNNmmd.
            `ommmmmNNNNNNNmNmNNNNmmd:
             :dmmmmNNNNNmh../oyhhhy:
             `sdmmmmNNNmmh/++-.+oh.
              `/dmmmmmmmmdo-:/ossd:
                `/ohhdmmmmmmdddddmh/
                   `-/osyhdddddhyo:
                        ``.----.`

                Welcome to the Empire"""
    time.sleep(3)
    os.system('clear')


def wrap_string(data, width=40, indent=32, indentAll=False, followingHeader=None):
    """
    Print a option description message in a nicely
    wrapped and formatted paragraph.

    followingHeader -> text that also goes on the first line
    """

    data = str(data)

    if len(data) > width:
        lines = textwrap.wrap(textwrap.dedent(data).strip(), width=width)

        if indentAll:
            returnString = ' ' * indent + lines[0]
            if followingHeader:
                returnString += " " + followingHeader
        else:
            returnString = lines[0]
            if followingHeader:
                returnString += " " + followingHeader
        i = 1
        while i < len(lines):
            returnString += "\n" + ' ' * indent + (lines[i]).strip()
            i += 1
        return returnString
    else:
        return data.strip()


def wrap_columns(col1, col2, width1=24, width2=40, indent=31):
    """
    Takes two strings of text and turns them into nicely formatted column output.

    Used by display_module()
    """

    lines1 = textwrap.wrap(textwrap.dedent(col1).strip(), width=width1)
    lines2 = textwrap.wrap(textwrap.dedent(col2).strip(), width=width2)

    result = ''

    limit = max(len(lines1), len(lines2))

    for x in xrange(limit):

        if x < len(lines1):
            if x != 0:
                result += ' ' * indent
            result += '{line: <0{width}s}'.format(width=width1, line=lines1[x])
        else:
            if x == 0:
                result += ' ' * width1
            else:
                result += ' ' * (indent + width1)

        if x < len(lines2):
            result += '  ' + '{line: <0{width}s}'.format(width=width2, line=lines2[x])

        if x != limit-1:
            result += "\n"

    return result


def display_options(options, color=True):
    """
    Take a dictionary and display it nicely.
    """
    for key in options:
        if color:
            print "\t%s\t%s" % (helpers.color('{0: <16}'.format(key), "green"), wrap_string(options[key]))
        else:
            print "\t%s\t%s" % ('{0: <16}'.format(key), wrap_string(options[key]))


def display_agents(agents):
    """
    Take a dictionary of agents and build the display for the main menu.
    """

    if len(agents) > 0:

        print ''
        print helpers.color("[*] Active agents:\n")
        print "  Name            Lang  Internal IP     Machine Name    Username            Process             Delay    Last Seen"
        print "  ---------       ----  -----------     ------------    ---------           -------             -----    --------------------"

        for agent in agents:

            if str(agent['high_integrity']) == '1':
                # add a * to the username if it's high integrity
                agent['username'] = '*' + str(agent['username'])
            if not agent['language'] or agent['language'] == '':
                agent['language'] = 'X'
            elif agent['language'].lower() == 'powershell':
                agent['language'] = 'ps'
            elif agent['language'].lower() == 'python':
                agent['language'] = 'py'
            else:
                agent['language'] = 'X'

            print "  %.16s%.6s%.16s%.16s%.20s%.20s%.9s%.20s" % ('{0: <16}'.format(agent['name']), '{0: <6}'.format(agent['language']), '{0: <16}'.format(agent['internal_ip']), '{0: <16}'.format(agent['hostname']), '{0: <20}'.format(agent['username']), '{0: <20}'.format(str(agent['process_name']) + "/" + str(agent['process_id'])), '{0: <9}'.format(str(agent['delay']) + "/"  +str(agent['jitter'])), agent['lastseen_time'])

        print ''
    else:
        print helpers.color('[!] No agents currently registered')


def display_agent(agent, returnAsString=False):
    """
    Display an agent all nice-like.

    Takes in the tuple of the raw agent database results.
    """

    if returnAsString:
        agentString = "\n[*] Agent info:\n"
        for key, value in agent.iteritems():
            if key != 'functions' and key != 'takings' and key != 'results':
                agentString += "  %s\t%s\n" % ('{0: <16}'.format(key), wrap_string(value, width=70))
        return agentString + '\n'
    else:
        print helpers.color("\n[*] Agent info:\n")
        for key, value in agent.iteritems():
            if key != 'functions' and key != 'takings' and key != 'results':
                print "\t%s\t%s" % (helpers.color('{0: <16}'.format(key), "blue"), wrap_string(value, width=70))
        print ''


def display_active_listeners(listeners):
    """
    Take an active listeners list and display everything nicely.
    """

    if len(listeners) > 0:
        print ''
        print helpers.color("[*] Active listeners:\n")

        print "  Name              Module          Host                                 Delay/Jitter   KillDate"
        print "  ----              ------          ----                                 ------------   --------"

        for listenerName, listener in listeners.iteritems():

            moduleName = listener['moduleName']
            if 'Host' in listener['options']:
                host = listener['options']['Host']['Value']
            else:
                host = ''

            if 'DefaultDelay' in listener['options']:
                defaultDelay = listener['options']['DefaultDelay']['Value']
            else:
                defaultDelay = 'n/a'

            if 'DefaultJitter' in listener['options']:
                defaultJitter = listener['options']['DefaultJitter']['Value']
            else:
                defaultJitter = ''
            
            if defaultDelay == 'n/a':
                connectInterval = 'n/a'
            else:
                connectInterval = "%s/%s" % (defaultDelay, defaultJitter)

            if 'KillDate' in listener['options']:
                killDate = listener['options']['KillDate']['Value']
            else:
                killDate = 'n/a'

            print "  %s%s%s%s%s" % ('{0: <18}'.format(listenerName), '{0: <16}'.format(moduleName), '{0: <37}'.format(host), '{0: <15}'.format(connectInterval), '{0: <12}'.format(killDate))

        print ''

    else:
        print helpers.color("[!] No listeners currently active ")


def display_active_listener(listener):
    """
    Displays an active listener's information structure.
    """

    print "\n%s Options:\n" % (listener['options']['Name']['Value'])
    print "  Name              Required    Value                            Description"
    print "  ----              --------    -------                          -----------"

    for option, values in listener['options'].iteritems():
        # if there's a long value length, wrap it
        if len(str(values['Value'])) > 33:
            print "  %s%s%s" % ('{0: <18}'.format(option), '{0: <12}'.format(("True" if values['Required'] else "False")), '{0: <33}'.format(wrap_string(values['Value'], width=32, indent=32, followingHeader=values['Description'])))
        else:
            print "  %s%s%s%s" % ('{0: <18}'.format(option), '{0: <12}'.format(("True" if values['Required'] else "False")), '{0: <33}'.format(values['Value']), values['Description'])

    print "\n"


def display_listener_module(listener):
    """
    Displays a listener module's information structure.
    """

    print '\n{0: >10}'.format("Name: ") + str(listener.info['Name'])
    print '{0: >10}'.format("Category: ") + str(listener.info['Category'])

    print "\nAuthors:"
    for author in listener.info['Author']:
        print "  " +author

    print "\nDescription:"
    desc = wrap_string(listener.info['Description'], width=60, indent=2, indentAll=True)
    if len(desc.splitlines()) == 1:
        print "  " + str(desc)
    else:
        print desc

    if 'Comments' in listener.info:
        comments = listener.info['Comments']
        if isinstance(comments, list):
            comments = ' '.join(comments)
        if comments.strip() != '':
            print "\nComments:"
            if isinstance(comments, list):
                comments = ' '.join(comments)
            comment = wrap_string(comments, width=60, indent=2, indentAll=True)
            if len(comment.splitlines()) == 1:
                print "  " + str(comment)
            else:
                print comment


    print "\n%s Options:\n" % (listener.info['Name'])
    print "  Name              Required    Value                            Description"
    print "  ----              --------    -------                          -----------"

    for option, values in listener.options.iteritems():
        # if there's a long value length, wrap it
        if len(str(values['Value'])) > 33:
            print "  %s%s%s" % ('{0: <18}'.format(option), '{0: <12}'.format(("True" if values['Required'] else "False")), '{0: <33}'.format(wrap_string(values['Value'], width=32, indent=32, followingHeader=values['Description'])))
        else:
            print "  %s%s%s%s" % ('{0: <18}'.format(option), '{0: <12}'.format(("True" if values['Required'] else "False")), '{0: <33}'.format(values['Value']), values['Description'])

    print "\n"


def display_stager(stager):
    """
    Displays a stager's information structure.
    """

    print "\nName: " + stager.info['Name']

    print "\nDescription:"
    desc = wrap_string(stager.info['Description'], width=50, indent=2, indentAll=True)
    if len(desc.splitlines()) == 1:
        print "  " + str(desc)
    else:
        print desc

    # print out any options, if present
    if stager.options:
        print "\nOptions:\n"
        print "  Name             Required    Value             Description"
        print "  ----             --------    -------           -----------"

        for option, values in stager.options.iteritems():
            print "  %s%s%s%s" % ('{0: <17}'.format(option), '{0: <12}'.format(("True" if values['Required'] else "False")), '{0: <18}'.format(values['Value']), wrap_string(values['Description'], indent=49))

    print "\n"


def display_module(moduleName, module):
    """
    Displays a module's information structure.
    """

    print '\n{0: >20}'.format("Name: ") + str(module.info['Name'])
    print '{0: >20}'.format("Module: ") + str(moduleName)
    if 'NeedsAdmin' in module.info:
        print '{0: >20}'.format("NeedsAdmin: ") + ("True" if module.info['NeedsAdmin'] else "False")
    if 'OpsecSafe' in module.info:
        print '{0: >20}'.format("OpsecSafe: ") + ("True" if module.info['OpsecSafe'] else "False")
    if 'Language' in module.info:
        print '{0: >20}'.format("Language: ") + str(module.info['Language'])
    if 'MinLanguageVersion' in module.info:
        print '{0: >20}'.format("MinLanguageVersion: ") + str(module.info['MinLanguageVersion'])
    if 'Background' in module.info:
        print '{0: >20}'.format("Background: ") + ("True" if module.info['Background'] else "False")
    if 'OutputExtension' in module.info:
        print '{0: >20}'.format("OutputExtension: ") + (str(module.info['OutputExtension']) if module.info['OutputExtension'] else "None")

    print "\nAuthors:"
    for author in module.info['Author']:
        print "  " +author

    print "\nDescription:"
    desc = wrap_string(module.info['Description'], width=60, indent=2, indentAll=True)
    if len(desc.splitlines()) == 1:
        print "  " + str(desc)
    else:
        print desc

    if 'Comments' in module.info:
        comments = module.info['Comments']
        if isinstance(comments, list):
            comments = ' '.join(comments)
        if comments.strip() != '':
            print "\nComments:"
            if isinstance(comments, list):
                comments = ' '.join(comments)
            comment = wrap_string(comments, width=60, indent=2, indentAll=True)
            if len(comment.splitlines()) == 1:
                print "  " + str(comment)
            else:
                print comment

    # print out any options, if present
    if module.options:

        # get the size for the first column
        maxNameLen = len(max(module.options.keys(), key=len))

        print "\nOptions:\n"
        print "  %sRequired    Value                     Description" %('{:<{}s}'.format("Name", maxNameLen+1))
        print "  %s--------    -------                   -----------" %('{:<{}s}'.format("----", maxNameLen+1))

        for option, values in module.options.iteritems():
            print "  %s%s%s" % ('{:<{}s}'.format(str(option), maxNameLen+1), '{0: <12}'.format(("True" if values['Required'] else "False")), wrap_columns(str(values['Value']), str(values['Description']), indent=(31 + (maxNameLen-16))))

    print ''


def display_module_search(moduleName, module):
    """
    Displays the name/description of a module for search results.
    """

    # Suffix modules requring elevated context with '*'
    if module.info['NeedsAdmin']:
        print " %s*\n" % (helpers.color(moduleName, 'blue'))
    else:
        print " %s\n" % (helpers.color(moduleName, 'blue'))
    # width=40, indent=32, indentAll=False,

    lines = textwrap.wrap(textwrap.dedent(module.info['Description']).strip(), width=70)
    for line in lines:
        print "\t" + line

    print "\n"


def display_credentials(creds):
    """
    Take a credential array and display everything nicely.
    """

    print helpers.color("\nCredentials:\n", "blue")
    print "  CredID  CredType   Domain                   UserName         Host             Password"
    print "  ------  --------   ------                   --------         ----             --------"

    for cred in creds:
        # (id, credtype, domain, username, password, host, notes, sid)
        credID = cred[0]
        credType = cred[1]
        domain = cred[2]
        username = cred[3]
        password = cred[4]
        host = cred[5]

        print "  %s%s%s%s%s%s" % ('{0: <8}'.format(credID), '{0: <11}'.format(credType), '{0: <25}'.format(domain), '{0: <17}'.format(username), '{0: <17}'.format(host), password)

    print ''
