"""

Packet handling functionality for Empire.

Defines packet types, builds tasking packets and parses result packets.

Packet format:

RC4s = RC4 encrypted with the shared staging key
HMACs = SHA1 HMAC using the shared staging key
AESc = AES encrypted using the client's session key
HMACc = first 10 bytes of a SHA256 HMAC using the client's session key

    Routing Packet:
    +---------+-------------------+--------------------------+
    | RC4 IV  | RC4s(RoutingData) | AESc(client packet data) | ... 
    +---------+-------------------+--------------------------+
    |    4    |         16        |        RC4 length        |
    +---------+-------------------+--------------------------+
    
    RC4s(RoutingData):
    +-----------+------+------+-------+--------+
    | SessionID | Lang | Meta | Extra | Length |
    +-----------+------+------+-------+--------+
    |    8      |  1   |  1   |   2   |    4   |
    +-----------+------+------+-------+--------+

    SessionID = the sessionID that the packet is bound for
    Lang = indicates the language used
    Meta = indicates staging req/tasking req/result post/etc.
    Extra = reserved for future expansion


    AESc(client data)
    +--------+-----------------+-------+
    | AES IV | Enc Packet Data | HMACc |
    +--------+-----------------+-------+
    |   16   |   % 16 bytes    |  10   |
    +--------+-----------------+-------+

    Client data decrypted:
    +------+--------+--------------------+----------+---------+-----------+
    | Type | Length | total # of packets | packet # | task ID | task data |
    +------+--------+--------------------+--------------------+-----------+
    |  2   |   4    |         2          |    2     |    2    | <Length>  |
    +------+--------+--------------------+----------+---------+-----------+
    
    type = packet type
    total # of packets = number of total packets in the transmission
    Packet # = where the packet fits in the transmission
    Task ID = links the tasking to results for deconflict on server side
    

    Client *_SAVE packets have the sub format:

            [15 chars] - save prefix
            [5 chars]  - extension
            [X...]     - tasking data

"""

import struct
import base64
import os
import hashlib
import hmac
from Crypto import Random
from pydispatch import dispatcher

# Empire imports
import encryption

# 0         -> error
# 1-99      -> standard functionality
# 100-199   -> dynamic functionality
# 200-299   -> SMB functionality

PACKET_NAMES = {
    "ERROR" : 0,

    "TASK_SYSINFO"   : 1,
    "TASK_EXIT"   : 2,

    "TASK_SET_DELAY" : 10,
    "TASK_GET_DELAY" : 12,
    "TASK_SET_SERVERS" : 13,
    "TASK_ADD_SERVERS" : 14,
    "TASK_UPDATE_PROFILE" : 20,
    "TASK_SET_KILLDATE" : 30,
    "TASK_GET_KILLDATE" : 31,
    "TASK_SET_WORKING_HOURS" : 32,
    "TASK_GET_WORKING_HOURS" : 33,

    "TASK_SHELL" : 40,
    "TASK_DOWNLOAD" : 41,
    "TASK_UPLOAD" : 42,

    "TASK_GETJOBS" : 50,
    "TASK_STOPJOB" : 51,

    "TASK_GETDOWNLOADS" : 52,
    "TASK_STOPDOWNLOAD" : 53,

    "TASK_CMD_WAIT" : 100,
    "TASK_CMD_WAIT_SAVE" : 101,
    "TASK_CMD_JOB" : 110,
    "TASK_CMD_JOB_SAVE" : 111,

    "TASK_SCRIPT_IMPORT" : 120,
    "TASK_SCRIPT_COMMAND" : 121,
    "TASK_IMPORT_MODULE" : 122,
    "TASK_VIEW_MODULE" : 123,
    "TASK_REMOVE_MODULE" : 124,

    "TASK_SWITCH_LISTENER" : 130
}

# build a lookup table for IDS
PACKET_IDS = {}
for name, ID in PACKET_NAMES.items(): PACKET_IDS[ID] = name

LANGUAGE = {
    'NONE' : 0,
    'POWERSHELL' : 1,
    'PYTHON' : 2
}
LANGUAGE_IDS = {}
for name, ID in LANGUAGE.items(): LANGUAGE_IDS[ID] = name

META = {
    'NONE' : 0,
    'STAGE0' : 1,
    'STAGE1' : 2,
    'STAGE2' : 3,
    'TASKING_REQUEST' : 4,
    'RESULT_POST' : 5,
    'SERVER_RESPONSE' : 6
}
META_IDS = {}
for name, ID in META.items(): META_IDS[ID] = name

ADDITIONAL = {}
ADDITIONAL_IDS = {}
for name, ID in ADDITIONAL.items(): ADDITIONAL_IDS[ID] = name


def build_task_packet(taskName, data, resultID):
    """
    Build a task packet for an agent.

        [2 bytes] - type
        [2 bytes] - total # of packets
        [2 bytes] - packet #
        [2 bytes] - task/result ID
        [4 bytes] - length
        [X...]    - result data

        +------+--------------------+----------+---------+--------+-----------+
        | Type | total # of packets | packet # | task ID | Length | task data |
        +------+--------------------+--------------------+--------+-----------+
        |  2   |         2          |    2     |    2    |   4    | <Length>  |
        +------+--------------------+----------+---------+--------+-----------+
    """

    taskType = struct.pack('=H', PACKET_NAMES[taskName])
    totalPacket = struct.pack('=H', 1)
    packetNum = struct.pack('=H', 1)
    resultID = struct.pack('=H', resultID)
    length = struct.pack('=L',len(data))
    return taskType + totalPacket + packetNum + resultID + length + data.decode('utf-8').encode('utf-8',errors='ignore')


def parse_result_packet(packet, offset=0):
    """
    Parse a result packet-

        [2 bytes] - type
        [2 bytes] - total # of packets
        [2 bytes] - packet #
        [2 bytes] - task/result ID
        [4 bytes] - length
        [X...]    - result data

        +------+--------------------+----------+---------+--------+-----------+
        | Type | total # of packets | packet # | task ID | Length | task data |
        +------+--------------------+--------------------+--------+-----------+
        |  2   |         2          |    2     |    2    |   4    | <Length>  |
        +------+--------------------+----------+---------+--------+-----------+

    Returns a tuple with (responseName, length, data, remainingData)

    Returns a tuple with (responseName, totalPackets, packetNum, taskID, length, data, remainingData)
    """

    try:
        responseID = struct.unpack('=H', packet[0+offset:2+offset])[0]
        totalPacket = struct.unpack('=H', packet[2+offset:4+offset])[0]
        packetNum = struct.unpack('=H', packet[4+offset:6+offset])[0]
        taskID = struct.unpack('=H', packet[6+offset:8+offset])[0]
        length = struct.unpack('=L', packet[8+offset:12+offset])[0]
        if length != '0':
            data = base64.b64decode(packet[12+offset:12+offset+length])
        else:
            data = None
        remainingData = packet[12+offset+length:]
        return (PACKET_IDS[responseID], totalPacket, packetNum, taskID, length, data, remainingData)
    except Exception as e:
        dispatcher.send("[*] parse_result_packet(): exception: %s" % (e), sender='Packets')
        return (None, None, None, None, None, None, None)


def parse_result_packets(packets):
    """
    Parse a blob of one or more result packets
    """

    resultPackets = []

    # parse the first result packet
    (responseName, totalPacket, packetNum, taskID, length, data, remainingData) = parse_result_packet(packets)

    if responseName and responseName != '':
        resultPackets.append( (responseName, totalPacket, packetNum, taskID, length, data) )

    # iterate 12 (size of packet header) + length of the decoded
    offset = 12 + length
    while remainingData and remainingData != '':
        # parse any additional result packets
        # (responseName, length, data, remainingData) = parse_result_packet(packets, offset=offset)
        (responseName, totalPacket, packetNum, taskID, length, data, remainingData) = parse_result_packet(packets, offset=offset)
        if responseName and responseName != '':
            resultPackets.append( (responseName, totalPacket, packetNum, taskID, length, data) )
        offset += 12 + length

    return resultPackets


def parse_routing_packet(stagingKey, data):
    """
    Decodes the rc4 "routing packet" and parses raw agent data into:

        {sessionID : (language, meta, additional, [encData]), ...}


    Routing packet format:

        +---------+-------------------+--------------------------+
        | RC4 IV  | RC4s(RoutingData) | AESc(client packet data) | ... 
        +---------+-------------------+--------------------------+
        |    4    |         16        |        RC4 length        |
        +---------+-------------------+--------------------------+
        
        RC4s(RoutingData):
        +-----------+------+------+-------+--------+
        | SessionID | Lang | Meta | Extra | Length |
        +-----------+------+------+-------+--------+
        |    8      |  1   |  1   |   2   |    4   |
        +-----------+------+------+-------+--------+

    """

    if data:
        results = {}
        offset = 0

        # ensure we have at least the 20 bytes for a routing packet
        if len(data) >= 20:

            while True:

                if len(data) - offset < 20:
                    break

                RC4IV = data[0+offset:4+offset]
                RC4data = data[4+offset:20+offset]
                routingPacket = encryption.rc4(RC4IV+stagingKey, RC4data)
                sessionID = routingPacket[0:8]

                # B == 1 byte unsigned char, H == 2 byte unsigned short, L == 4 byte unsigned long
                (language, meta, additional, length) = struct.unpack("=BBHL", routingPacket[8:])
                if length < 0:
                    dispatcher.send('[*] parse_agent_data(): length in decoded rc4 packet is < 0', sender='Packets')
                    encData = None
                else:
                    encData = data[(20+offset):(20+offset+length)]

                results[sessionID] = (LANGUAGE_IDS.get(language, 'NONE'), META_IDS.get(meta, 'NONE'), ADDITIONAL_IDS.get(additional, 'NONE'), encData)

                # check if we're at the end of the packet processing
                remainingData = data[20+offset+length:]
                if not remainingData or remainingData == '':
                    break

                offset += 20 + length

            return results

        else:
            dispatcher.send("[*] parse_agent_data() data length incorrect: %s" % (len(data)), sender='Packets')
            return None

    else:
        dispatcher.send("[*] parse_agent_data() data is None", sender='Packets')
        return None


def build_routing_packet(stagingKey, sessionID, language, meta="NONE", additional="NONE", encData=''):
    """
    Takes the specified parameters for an RC4 "routing packet" and builds/returns
    an HMAC'ed RC4 "routing packet".

    packet format:

        Routing Packet:
        +---------+-------------------+--------------------------+
        | RC4 IV  | RC4s(RoutingData) | AESc(client packet data) | ... 
        +---------+-------------------+--------------------------+
        |    4    |         16        |        RC4 length        |
        +---------+-------------------+--------------------------+
        
        RC4s(RoutingData):
        +-----------+------+------+-------+--------+
        | SessionID | Lang | Meta | Extra | Length |
        +-----------+------+------+-------+--------+
        |    8      |  1   |  1   |   2   |    4   |
        +-----------+------+------+-------+--------+

    """

    # binary pack all of the passed config values as unsigned numbers
    #   B == 1 byte unsigned char, H == 2 byte unsigned short, L == 4 byte unsigned long
    data = sessionID + struct.pack("=BBHL", LANGUAGE.get(language.upper(), 0), META.get(meta.upper(), 0), ADDITIONAL.get(additional.upper(), 0), len(encData))

    # RC4IV = os.urandom(4)
    RC4IV = Random.new().read(4)
    stagingKey = str(stagingKey)
    key = RC4IV + stagingKey
    rc4EncData = encryption.rc4(key, data)

    # return an rc4 encyption of the routing packet, append an HMAC of the packet, then the actual encrypted data
    packet = RC4IV + rc4EncData + encData

    return packet


def resolve_id(PacketID):
    """
    Resolve a packet ID to its key.
    """
    try:
        return PACKET_IDS[int(PacketID)]
    except:
        return PACKET_IDS[0]
