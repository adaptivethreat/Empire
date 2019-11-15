"""
Connect to the default database at ./data/empire.db.
"""
from __future__ import print_function
from __future__ import absolute_import

import sys
import sqlite3

from . import helpers


def connect_to_db():
    try:
        # set the database connectiont to autocommit w/ isolation level
        conn = sqlite3.connect('./data/empire.db', check_same_thread=False)
        conn.text_factory = str
        conn.isolation_level = None
        return conn
    
    except Exception:
        print(helpers.color("[!] Could not connect to database"))
        print(helpers.color("[!] Please run database_setup.py"))
        sys.exit()


db = connect_to_db()
