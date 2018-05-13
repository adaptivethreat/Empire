import sys
import base64
import sqlite3
import datetime
import threading
import helpers
import json
from pydispatch import dispatcher

class Users():
    # This is a demo class for handling users
    # usercache represents the db
    def __init__(self, mainMenu, args):
        
        self.mainMenu = mainMenu

        self.conn = self.mainMenu.conn

        self.lock = threading.Lock()

        self.args = args

        self.users = {}


    def get_db_connection(self):
        """
        Returns a handle to the DB
        """
        self.lock.acquire()
        self.mainMenu.conn.row_factory = None 
        self.lock.release()
        return self.mainMenu.conn


    def add_new_user(self, sid, username):
        """
        Add new user to cache
        """
        lastlogon = helpers.get_datetime()
        conn = self.get_db_connection()
        try:
            self.lock.acquire()
            cur = conn.cursor()
	    cur.execute("INSERT INTO users (sid, username, lastlogon_time, authenticated) VALUES (?,?,?,?)", (sid, username, lastlogon, True))
            cur.close()

            self.users[sid] = {"username": username, "authenticated": True}
            #dispatch the event
            signal = json.dumps({
                'print':True,
                'message': "{} connected".format(username)
            })
            dispatcher.send(signal, sender="Users")
        finally:
            self.lock.release()
    
    def log_user_event(self, message):
        """
        Log a user event
        """

        signal = json.dumps({
            'print':False,
            'message':message
        })
        dispatcher.send(signal, sender="Users")

    def authenticate_user(self, sid, username, password):
        """
        Authenticate a user given their username and password
        """
	if sid in self.users:
            if password == self.args.shared_password:
                #change this to a database update
                self.update_lastlogon(sid)
		signal = json.dumps({
                    'print':True,
                    'message': "{} logged in".format(username)
                })
                dispatcher.send(signal, sender="Users")
                return True

            else:
                return False
        
        else:
            if password == self.args.shared_password:
                self.add_new_user(sid, username)
                return True

    def is_authenticated(self, sid):
        """
        Check if the given sid is authenticated
        """

        if sid in self.users:
            return self.users[sid]['authenticated']
        else:
            return False

    def deauthenticate_user(self, sid):
        """
        Change user state to unauthenticated in the database and the cache
        """
        conn = self.get_db_connection()

        try:
            self.lock.acquire()
            cur = conn.cursor()

            cur.execute("UPDATE users SET authenticated=? WHERE id=?", [False, sid])
            cur.close()

            username = self.get_user_from_sid(sid)
            signal = json.dumps({
                'print': True,
                'message': "{} logged out.".format(username)
            })
            dispatcher.send(signal, sender="Users")
        finally:
            self.lock.release()
            
            
        return True

    
    def update_lastlogon(self, sid):
        """
        Update the last logon timestamp for a user
        """
        lastlogon = helpers.get_datetime()
        conn = self.get_db_connection()

        try:
            self.lock.acquire()
            cur = conn.cursor()

            cur.execute("UPDATE users SET lastlogon_time=?, authenticated=? WHERE id=?", [lastlogon, True, sid])
            cur.close()

            self.users[sid]['authenticated'] = True
        finally:
            self.lock.release()

    def get_sid_from_user(self, username):
        """
        Obtain the corresponding sid, given a username
        """
        for key, values in self.users.iteritems():
            if values['username'] == username:
                return key

    def get_user_from_sid(self, sid):
        """
        Obtain the corresponding username, given a sid
        """
        if sid in self.users:
            return self.users[sid]['username']
   
    def get_users(self):
	return self.users

    def remove_user(self, sid):
        """
        Remove a user from the usercache 
        """
        try:
            del self.users[sid]
            self.deauthenticate_user(sid)
        except:
            pass
        
