"""

Credential handling functionality for Empire.

"""

import helpers
import os
# import sqlite3

class Credentials:
    """
    Class that handles interaction with the backend credential model
    (adding creds, displaying, etc.).
    """
    def __init__(self, MainMenu, args=None):

        # pull out the controller objects
        self.mainMenu = MainMenu
        self.conn = MainMenu.conn
        self.agents = MainMenu.agents
        self.modules = None
        self.stager = None
        self.installPath = self.mainMenu.installPath
        self.args = args

        # credential database schema:
        #   (ID, credtype, domain, username, password, host, notes, sid)
        # credtype = hash or plaintext
        # sid is stored for krbtgt


    def is_credential_valid(self, credentialID):
        """
        Check if this credential ID is valid.
        """
        cur = self.conn.cursor()
        cur.execute('SELECT * FROM credentials WHERE id=? limit 1', [credentialID])
        results = cur.fetchall()
        cur.close()
        return len(results) > 0


    def get_credentials(self, filterTerm=None, credtype=None, note=None):
        """
        Return credentials from the database.

        'credtype' can be specified to return creds of a specific type.
        Values are: hash, plaintext, and token.
        """

        cur = self.conn.cursor()

        # if we're returning a single credential by ID
        if self.is_credential_valid(filterTerm):
            cur.execute("SELECT * FROM credentials WHERE id=? limit 1", [filterTerm])

        # if we're filtering by host/username
        elif filterTerm and filterTerm != '':
            filterTerm = filterTerm.replace('*', '%')
            cur.execute("SELECT * FROM credentials WHERE LOWER(domain) LIKE LOWER(?) or LOWER(username) like LOWER(?) or LOWER(host) like LOWER(?) or LOWER(password) like LOWER(?)", [filterTerm, filterTerm, filterTerm, filterTerm])

        # if we're filtering by credential type (hash, plaintext, token)
        elif credtype and credtype != "":
            cur.execute("SELECT * FROM credentials WHERE LOWER(credtype) LIKE LOWER(?)", [credtype])

        # if we're filtering by content in the note field
        elif note and note != "":
            cur.execute("SELECT * FROM credentials WHERE LOWER(note) LIKE LOWER(%?%)", [note])

        # otherwise return all credentials
        else:
            cur.execute("SELECT * FROM credentials")

        results = cur.fetchall()
        cur.close()
        return results


    def get_krbtgt(self):
        """
        Return all krbtgt credentials from the database.
        """
        return self.get_credentials(credtype="hash", filterTerm="krbtgt")


    def add_credential(self, credtype, domain, username, password, host, sid="", notes=""):
        """
        Add a credential with the specified information to the database.
        """
        cur = self.conn.cursor()

        cur.execute("SELECT * FROM credentials WHERE LOWER(credtype) LIKE LOWER(?) AND LOWER(domain) LIKE LOWER(?) AND LOWER(username) LIKE LOWER(?) AND password LIKE ?", [credtype, domain, username, password])
        results = cur.fetchall()

        if results == []:
            # only add the credential if the (credtype, domain, username, password) tuple doesn't already exist
            cur.execute("INSERT INTO credentials (credtype, domain, username, password, host, sid, notes) VALUES (?,?,?,?,?,?,?)", [credtype, domain, username, password, host, sid, notes])

        cur.close()


    def add_credential_note(self, credentialID, note):
        """
        Update a note to a credential in the database.
        """
        cur = self.conn.cursor()
        cur.execute("UPDATE credentials SET note = ? WHERE id=?", [note, credentialID])
        cur.close()


    def remove_credentials(self, credIDs):
        """
        Removes a list of IDs from the database
        """
        for credID in credIDs:
            cur = self.conn.cursor()
            cur.execute("DELETE FROM credentials WHERE id=?", [credID])
            cur.close()


    def remove_all_credentials(self):
        """
        Remove all credentials from the database.
        """
        cur = self.conn.cursor()
        cur.execute("DELETE FROM credentials")
        cur.close()


    def export_credentials(self, export_path=''):
        """
        Export the credentials in the database to an output file.
        """

        if export_path == '':
            print helpers.color("[!] Export path cannot be ''")

        export_path += ".csv"

        if os.path.exists(export_path):
            try:
                choice = raw_input(helpers.color("\n[>] File %s already exists, overwrite? [y/N] " % (export_path), "red"))
                if choice.lower() != "" and choice.lower()[0] == "y":
                    pass
                else:
                    return
            except KeyboardInterrupt:
                return

        creds = self.get_credentials()

        if len(creds) == 0:
            print helpers.color("[!] No credentials in the database.")
            return

        output_file = open(export_path, 'w')
        output_file.write("CredID,CredType,Domain,Username,Password,Host,SID,Notes\n")
        for cred in creds:
            output_file.write("\"%s\"\n" % ('","'.join([str(x) for x in cred])))

        print "\n" + helpers.color("[*] Credentials exported to %s\n" % (export_path))
        output_file.close()
