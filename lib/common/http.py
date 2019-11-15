"""

HTTP related methods used by Empire.

Includes URI validation/checksums, as well as the base
http server (EmpireServer) and its modified request
handler (RequestHandler).

These are the first places URI requests are processed.

"""
from __future__ import absolute_import

from future import standard_library
standard_library.install_aliases()
from http.server import BaseHTTPRequestHandler
import http.server, threading, ssl, os, string, random
from pydispatch import dispatcher
import re
import json

# Empire imports
from . import encryption
from . import helpers


def default_page(path_to_html_file="empty"):
    if path_to_html_file == "empty":
        """
        Returns the default page for this server.
        """
        page = "<html><body><h1>It works!</h1>"
        page += "<p>This is the default web page for this server.</p>"
        page += "<p>The web server software is running but no content has been added, yet.</p>"
        page += "</body></html>"
        return page
    else:
        html = open(path_to_html_file, 'r').read()
        return html

###############################################################
#
# Host2lhost helper.
#
###############################################################

def host2lhost(s):
    """
    Return lhost for Empire's native listener from Host value
    """
    reg = r'(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)'
    res = re.findall( reg, s)
    return res[0] if len(res) == 1 else '0.0.0.0'

###############################################################
#
# Checksum helpers.
#
###############################################################

def checksum8(s):
    """
    Add up all character values and mods the total by 256.
    """
    return sum([ord(ch) for ch in s]) % 0x100


###############################################################
#
# HTTP servers and handlers.
#
###############################################################

class RequestHandler(BaseHTTPRequestHandler):
    """
    Main HTTP handler we're overwriting in order to modify the HTTPServer behavior.
    """

    # retrieve the server headers from the common config
    serverVersion = helpers.get_config('server_version')[0]

    # fake out our server headers base
    BaseHTTPRequestHandler.server_version = serverVersion
    BaseHTTPRequestHandler.sys_version = ""


    def do_GET(self):

        # get the requested path and the client IP
        resource = self.path
        clientIP = self.client_address[0]
        sessionID = None

        cookie = self.headers.getheader("Cookie")
        if cookie:
            # search for a SESSIONID value in the cookie
            parts = cookie.split(";")
            for part in parts:
                if "SESSIONID" in part:
                    # extract the sessionID value
                    name, sessionID = part.split("=", 1)

        # fire off an event for this GET (for logging)
        message = "[*] {resource} requested from {session_id} at {client_ip}".format(
            resource=resource,
            session_id=sessionID,
            client_ip=clientIP
        )

        signal = json.dumps({
            'print': True,
            'message': message
        })
        dispatcher.send(signal, sender="empire")

        # get the appropriate response from the agent handler
        (code, responsedata) = self.server.agents.process_get(self.server.server_port, clientIP, sessionID, resource)

        # write the response out
        self.send_response(code)
        self.end_headers()
        self.wfile.write(responsedata)
        self.wfile.flush()
        # self.wfile.close() # causes an error with HTTP comms

    def do_POST(self):

        resource = self.path
        clientIP = self.client_address[0]
        sessionID = None

        cookie = self.headers.getheader("Cookie")
        if cookie:
            # search for a SESSIONID value in the cookie
            parts = cookie.split(";")
            for part in parts:
                if "SESSIONID" in part:
                    # extract the sessionID value
                    name, sessionID = part.split("=", 1)

        # fire off an event for this POST (for logging)
        message = "[*] Post to {resource} from {session_id} at {client_ip}".format(
            resource=resource,
            session_id=sessionID,
            client_ip=clientIP
        )

        signal = json.dumps({
            'print': True,
            'message': message
        })
        dispatcher.send(signal, sender="empire")

        # read in the length of the POST data
        if self.headers.getheader('content-length'):
            length = int(self.headers.getheader('content-length'))
            postData = self.rfile.read(length)

            # get the appropriate response for this agent
            (code, responsedata) = self.server.agents.process_post(self.server.server_port, clientIP, sessionID, resource, postData)

            # write the response out
            self.send_response(code)
            self.end_headers()
            self.wfile.write(responsedata)
            self.wfile.flush()
        # self.wfile.close() # causes an error with HTTP comms

    # supress all the stupid default stdout/stderr output
    def log_message(*arg):
        pass


class EmpireServer(threading.Thread):
    """
    Version of a simple HTTP[S] Server with specifiable port and
    SSL cert. Defaults to HTTP is no cert is specified.

    Uses agents.RequestHandler handle inbound requests.
    """

    def __init__(self, handler, lhost='0.0.0.0', port=80, cert=''):

        # set to False if the listener doesn't successfully start
        self.success = True

        try:
            threading.Thread.__init__(self)
            self.server = None

            self.server = http.server.HTTPServer((lhost, int(port)), RequestHandler)

            # pass the agent handler object along for the RequestHandler
            self.server.agents = handler

            self.port = port
            self.serverType = "HTTP"

            # wrap it all up in SSL if a cert is specified
            if cert and cert != "":
                self.serverType = "HTTPS"
                cert = os.path.abspath(cert)

                self.server.socket = ssl.wrap_socket(self.server.socket, certfile=cert, server_side=True)

                message = "[*] Initializing HTTPS server on {port}".format(port=port)
            else:
                message = "[*] Initializing HTTP server on {port}".format(port=port)

            signal = json.dumps({
                'print': True,
                'message': message
            })
            dispatcher.send(signal, sender="empire")

        except Exception as e:
            self.success = False
            # shoot off an error if the listener doesn't stand up
            message = "[!] Error starting listener on port {}: {}".format(port, e)
            signal = json.dumps({
                'print': True,
                'message': message
            })
            dispatcher.send(signal, sender="empire")


    def base_server(self):
        return self.server


    def run(self):
        try: self.server.serve_forever()
        except: pass


    def shutdown(self):

        # shut down the server/socket
        self.server.shutdown()
        self.server.socket.close()
        self.server.server_close()
        self._Thread__stop()

        # make sure all the threads are killed
        for thread in threading.enumerate():
            if thread.isAlive():
                try:
                    thread._Thread__stop()
                except:
                    pass
