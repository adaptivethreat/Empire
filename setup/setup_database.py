#!/usr/bin/env python

import sqlite3, os, string, hashlib, random


###################################################
#
# Default values for the config
#
###################################################

# Staging Key is set up via environmental variable
# or via command line. By setting RANDOM a randomly
# selected password will automatically be selected
# or it can be set to any bash acceptable character
# set for a password.

STAGING_KEY = os.getenv('STAGING_KEY', "BLANK")
punctuation = '!#%&()*+,-./:;<=>?@[]^_{|}~'

# otherwise prompt the user for a set value to hash for the negotiation password
if STAGING_KEY == "BLANK":
    choice = raw_input("\n [>] Enter server negotiation password, enter for random generation: ")
    if choice == "":
        # if no password is entered, generation something random
        STAGING_KEY = ''.join(random.sample(string.ascii_letters + string.digits + punctuation, 32))
    else:
        STAGING_KEY = hashlib.md5(choice).hexdigest()
elif STAGING_KEY == "RANDOM":
    STAGING_KEY = ''.join(random.sample(string.ascii_letters + string.digits + punctuation, 32))

# Calculate the install path. We know the project directory will always be the parent of the current directory. Any modifications of the folder structure will
# need to be applied here.
INSTALL_PATH = os.path.dirname(os.path.dirname(os.path.realpath(__file__))) + "/"

# an IP white list to ONLY accept clients from
#   format is "192.168.1.1,192.168.1.10-192.168.1.100,10.0.0.0/8"
IP_WHITELIST = ""

# an IP black list to reject accept clients from
#   format is "192.168.1.1,192.168.1.10-192.168.1.100,10.0.0.0/8"
IP_BLACKLIST = ""

# default credentials used to log into the RESTful API
API_USERNAME = "empireadmin"
API_PASSWORD = ''.join(random.sample(string.ascii_letters + string.digits + punctuation, 32))

# the 'permanent' API token (doesn't change)
API_PERMANENT_TOKEN = ''.join(random.choice(string.ascii_lowercase + string.digits) for x in range(40))

# default obfuscation setting
OBFUSCATE = 0

# default obfuscation command
OBFUSCATE_COMMAND = r'Token\All\1'
###################################################
#
# Database setup.
#
###################################################

conn = sqlite3.connect('%s/data/empire.db'%INSTALL_PATH)

c = conn.cursor()

# try to prevent some of the weird sqlite I/O errors
c.execute('PRAGMA journal_mode = OFF')

c.execute('DROP TABLE IF EXISTS config')
c.execute('''CREATE TABLE config (
    "staging_key" text,
    "install_path" text,
    "ip_whitelist" text,
    "ip_blacklist" text,
    "autorun_command" text,
    "autorun_data" text,
    "rootuser" boolean,
    "api_username" text,
    "api_password" text,
    "api_current_token" text,
    "api_permanent_token" text,
    "obfuscate" integer,
    "obfuscate_command" text
    )''')

# kick off the config component of the database
c.execute("INSERT INTO config VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)", (STAGING_KEY, INSTALL_PATH, IP_WHITELIST, IP_BLACKLIST, '', '', False, API_USERNAME, API_PASSWORD, '', API_PERMANENT_TOKEN, OBFUSCATE, OBFUSCATE_COMMAND))

c.execute('''CREATE TABLE "agents" (
    "id" integer PRIMARY KEY,
    "session_id" text,
    "listener" text,
    "name" text,
    "language" text,
    "language_version" text,
    "delay" integer,
    "jitter" real,
    "external_ip" text,
    "internal_ip" text,
    "username" text,
    "high_integrity" integer,
    "process_name" text,
    "process_id" text,
    "hostname" text,
    "os_details" text,
    "session_key" text,
    "nonce" text,
    "checkin_time" text,
    "lastseen_time" text,
    "parent" text,
    "children" text,
    "servers" text,
    "profile" text,
    "functions" text,
    "kill_date" text,
    "working_hours" text,
    "lost_limit" integer,
    "taskings" text,
    "results" text
    )''')

# the 'options' field contains a pickled version of all
#   currently set listener options
c.execute('''CREATE TABLE "listeners" (
    "id" integer PRIMARY KEY,
    "name" text,
    "module" text,
    "listener_type" text,
    "listener_category" text,
    "enabled" boolean,
    "options" blob
    )''')

# type = hash, plaintext, token
#   for krbtgt, the domain SID is stored in misc
#   for tokens, the data is base64'ed and stored in pass
c.execute('''CREATE TABLE "credentials" (
    "id" integer PRIMARY KEY,
    "credtype" text,
    "domain" text,
    "username" text,
    "password" text,
    "host" text,
    "os" text,
    "sid" text,
    "notes" text
    )''')

c.execute( '''CREATE TABLE "taskings" (
    "id" integer,
    "data" text,
    "agent" text,
    PRIMARY KEY(id, agent)
)''')

c.execute( '''CREATE TABLE "results" (
    "id" integer,
    "data" text,
    "agent" text,
    PRIMARY KEY(id, agent)
)''')

# event_types -> checkin, task, result, rename
c.execute('''CREATE TABLE "reporting" (
    "id" integer PRIMARY KEY,
    "name" text,
    "event_type" text,
    "message" text,
    "time_stamp" text,
    "taskID" integer,
    FOREIGN KEY(taskID) REFERENCES results(id)
)''')

# commit the changes and close everything off
conn.commit()
conn.close()

print "\n [*] Database setup completed!\n"
