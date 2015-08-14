#!/usr/bin/python

import sqlite3, os, string, hashlib
from Crypto.Random import random


###################################################
#
# Default values for the config
#
###################################################

# to set a static key used for initial agent staging:
#   STAGING_KEY = '8q=SDS%l5&Bpf?xIjKL8=Kk2RNwY(f*d'

# otherwise prompt the user for a set value to hash for the negotiation password
choice = raw_input("\n [>] Enter server negotiation password, enter for random generation: ")
if choice == "":
    # if no password is entered, generation something random
    punctuation = '!#$%&()*+,-./:;<=>?@[\]^_`{|}~'
    STAGING_KEY = ''.join(random.sample(string.ascii_letters + string.digits + punctuation, 32))
else:
    STAGING_KEY = hashlib.md5(choice).hexdigest()

# the resource requested by the initial launcher
STAGE0_URI = "index.asp"

# the resource used by the RSA key post
STAGE1_URI = "index.jsp"

# the resource used by the sysinfo checkin that returns the agent.ps1
STAGE2_URI = "index.php"

# the default delay (in seconds) for agent callback
DEFAULT_DELAY = 5

# the default jitter (0.0-1.0) to apply to the callback delay
DEFAULT_JITTER = 0.0

# the default traffic profile to use for agent communications
#   format -> requestUris|user_agent|additionalHeaders
DEFAULT_PROFILE = "/admin/get.php,/news.asp,/login/process.jsp|Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko"

# default https cert to use
DEFAULT_CERT_PATH = ''

# the default port for listeners
DEFAULT_PORT = 8080

# the installation path for Empire, defaults to auto-calculating it
# INSTALL_PATH = "/".join(os.getcwd().split("/")[0:-1])+"/"
# asmc
INSTALL_PATH = os.sep.join(os.getcwd().split(os.sep)[0:-1])+os.sep

# the version version to appear as
SERVER_VERSION = "Microsoft-IIS/7.5"

# an IP white list to ONLY accept clients from
#   format is 192.168.1.1,192.168.1.10-192.168.1.100,10.0.0.0/8
IP_WHITELIST = ""

# an IP black list to reject accept clients from
#   format is 192.168.1.1,192.168.1.10-192.168.1.100,10.0.0.0/8
IP_BLACKLIST = ""

#number of times an agent will call back without an answer prior to exiting
DEFAULT_LOST_LIMIT = 60 



###################################################
#
# Database setup.
#
###################################################


conn = sqlite3.connect('../data/empire.db')

c = conn.cursor()

# try to prevent some of the weird sqlite I/O errors
c.execute('PRAGMA journal_mode = OFF')

c.execute('''CREATE TABLE config (
    "staging_key" text,
    "stage0_uri" text,
    "stage1_uri" text,
    "stage2_uri" text,
    "default_delay" integer,
    "default_jitter" real,
    "default_profile" text,
    "default_cert_path" text,
    "default_port" text,
    "install_path" text,
    "server_version" text,
    "ip_whitelist" text,
    "ip_blacklist" text,
    "default_lost_limit" integer
    )''')

# kick off the config component of the database
c.execute("INSERT INTO config VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (STAGING_KEY,STAGE0_URI,STAGE1_URI,STAGE2_URI,DEFAULT_DELAY,DEFAULT_JITTER,DEFAULT_PROFILE,DEFAULT_CERT_PATH,DEFAULT_PORT,INSTALL_PATH,SERVER_VERSION,IP_WHITELIST,IP_BLACKLIST, DEFAULT_LOST_LIMIT))

c.execute('''CREATE TABLE "agents" (
    "id" integer PRIMARY KEY,
    "session_id" text,
    "listener" text,
    "name" text,
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
    "checkin_time" text,
    "lastseen_time" text,
    "parent" text,
    "children" text,
    "servers" text,
    "uris" text,
    "old_uris" text,
    "user_agent" text,
    "headers" text,
    "functions" text,
    "kill_date" text,
    "working_hours" text,
    "ps_version" text,
    "lost_limit" integer
    )''')

c.execute('''CREATE TABLE "listeners" (
    "id" integer PRIMARY KEY,
    "name" text,
    "host" text,
    "port" integer,
    "cert_path" text,
    "staging_key" text,
    "default_delay" integer,
    "default_jitter" real,
    "default_profile" text,
    "kill_date" text,
    "working_hours" text,
    "listener_type" text,
    "redirect_target" text,
    "default_lost_limit" integer
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
    "sid" text,
    "notes" text
    )''')


# event_types -> checkin, task, result, rename
c.execute('''CREATE TABLE "reporting" (
    "id" integer PRIMARY KEY,
    "name" text,
    "event_type" text,
    "message" text,
    "time_stamp" text
    )''')


# commit the changes and close everything off
conn.commit()
conn.close()

print "\n [*] Database setup completed!\n"
