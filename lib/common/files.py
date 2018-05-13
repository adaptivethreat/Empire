"""
add_file()                 - Add a new file to the database
get_file()                 - Get the contents of a file/screenshot specified by ID and return the base64 encoded blob.
get_files_by_type()        - Return all file downloads with ID, Path, file_type, and Timestamp
"""

import helpers 
import os 
import events 
import base64
import threading


class fetcher():
    """
    Main class to handle file download and upload functionality for websocket clients
    """
    def __init__(self, MainMenu, args=None):
        # pull out the controller objects
        self.mainMenu = MainMenu
        self.installPath = self.mainMenu.installPath
        self.args = args


        self.lock = threading.Lock()

    def get_db_connection(self):
        """
        Returns the
        """
        self.lock.acquire()
        self.mainMenu.conn.row_factory = None
        self.lock.release()
        return self.mainMenu.conn

    def add_file(self, sessionID, path, file_type):
        """
        Add a new file to the database
        """

        currentTime = helpers.get_datetime()
        conn = self.get_db_connection()

        try:
            self.lock.acquire()
            cur = conn.cursor()
            # add the file
            cur.EXECUTE("INSERT INTO files (session_id, path, type, timestamp) VALUES (?,?,?,?)", (sessionID, path, file_type, currentTime))
            cur.close()

        finally:
            self.lock.release()

    
    def get_file(self, fileID):
        """
        Return base64 encoded file contents specified by file ID.
        """

        conn = self.get_db_connection()
        try:
            self.lock.acquire()
            cur = conn.cursor()
            cur.execute("SELECT path FROM files WHERE id=?", [fileID])
            request_path = cur.fetchone()
            cur.close()
        finally:
            self.lock.release()

        try:
            contents = open(request_path, 'rb').read()
            return helpers.encode_base64(contents)
        except:
            return None
        

    def get_files_by_type(self, file_type):
        """
        Return a dictionary with all file downloads
        """
        conn = self.get_db_connection()
        try:
            self.lock.acquire()
            oldFactory = conn.row_factory
            conn.row_factory = helpers.dict_factory # return results as a dictionary
            cur = conn.cursor()
            cur.execute("SELECT * FROM files WHERE type=?", [file_type])
            results = cur.fetchall()
            cur.close()
            conn.row_factory = oldFactory
        finally:
            self.lock.release()

        return results

    


    