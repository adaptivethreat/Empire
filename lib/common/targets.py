"""
target handling functionality for Empire.
"""

import sqlite3
import helpers
import os
from xml.etree import ElementTree

class Targets:

    def __init__(self, MainMenu, args=None):
        
        # pull out the controller objects
        self.mainMenu = MainMenu
        self.conn = MainMenu.conn
        self.agents = None
        self.modules = None
        self.stager = None
        self.installPath = self.mainMenu.installPath
        self.args = args

        """
        c.execute('''CREATE TABLE "targets" (
            "id" integer PRIMARY KEY,
            "target" text,
            "access" text,
            "username" text,
            "password" text,
            "domain" text,
            "authenticated" text,
            "local_admin" text
            )''')
        """

    def is_target_valid(self, targetID):
        """
        Check if this target ID is valid.
        """
        cur = self.conn.cursor()
        cur.execute('SELECT * FROM targets WHERE id=? limit 1', [targetID])
        results = cur.fetchall()
        cur.close()
        return len(results) > 0


    def get_targets(self, filterTerm=None, filterDict=None):
        """
        Return targets from the database.

        'credtype' can be specified to return creds of a specific type.
        Values are: hash, plaintext, and token.
        """

        cur = self.conn.cursor()

        # if we're returning a single target by ID
        if self.is_target_valid(filterTerm):
            cur.execute("SELECT * FROM targets WHERE id=? limit 1", [filterTerm])

        # if we're filtering by target/username
        elif filterTerm and filterTerm != "":
            cur.execute(("SELECT * FROM targets WHERE LOWER(target) LIKE LOWER(?)",
                            "or LOWER(username) like LOWER(?)",
                            "or LOWER(password) like LOWER(?)",
                            "or LOWER(access) like LOWER(?)",
                            "or LOWER(domain) like LOWER(?)"), [filterTerm, filterTerm])

        elif filterDict and isinstance(filterDict, dict):
            filter_str = []
            for key, val in filterDict.items():
                filter_str.append('LOWER({}) LIKE LOWER({})'.format(key, val))

            filter_str = ' AND '.join(filter_str)

            cur.execute("SELECT * FROM targets WHERE {}".format(filter_str))

        # otherwise return all targets
        else:
            cur.execute("SELECT * FROM targets")

        results = cur.fetchall()
        cur.close()

        return results


    def add_target(self, target=None, port=None, access=None, username=None, password=None, domain=None):
        """
        Add a target with the specified information to the database.
        """

        print helpers.color("[+] Adding target: {}".format(target))
        cur = self.conn.cursor()
        cur.execute("INSERT INTO targets (target, port, access, username, password, domain) VALUES (?,?,?,?,?,?)", [target, port,access, username, password, domain] )
        cur.close()


    def add_target_note(self, targetID, note):
        """
        Update a note to a target in the database.
        """
        cur = self.conn.cursor()
        cur.execute("UPDATE targets SET note = ? WHERE id=?", [note,targetID])
        cur.close()


    def remove_targets(self, credIDs):
        """
        Removes a list of IDs from the database
        """
        for credID in credIDs:
            cur = self.conn.cursor()
            cur.execute("DELETE FROM targets WHERE id=?", [credID])
            cur.close()


    def remove_all_targets(self):
        """
        Remove all targets from the database.
        """
        cur = self.conn.cursor()
        cur.execute("DELETE FROM targets")
        cur.close()


    def export_targets(self, credtype=None):
        """
        Export the targets in the database to an output file.
        """
        # TODO: implement lol
        
        if(credtype and credtype.lower() == "hash"):
            # export hashes in user:sid:lm:ntlm format
            pass
        else:
            # export by csv?
            pass

    def import_nmap_xml(self, filename):
        cnt = 0

        if not os.path.exists(filename):
            print helpers.color("[!] File does not exist: {}".format(filename))
            return

        with open(filename) as fh:
            data = fh.read()

        xml = ElementTree.parse(filename)
        for host in xml.findall('host'):
            addr = host.find('address').get('addr')
            try:
                for curr_port in host.find('ports').findall('port'):
                    if curr_port.find('state').get('state') != 'open':
                        continue
                    port = curr_port.get('portid')
                    if port != '445':
                        continue
                    self.add_target(target=addr, port=port)
            except AttributeError:
                pass
