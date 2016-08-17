"""

Packet handling functionality for Empire.

Defines packet types, generates/validates epoch counters,
builds tasking packets and parses result packets


    Packet format:

            [4 bytes] - type
            [4 bytes] - counter
            [4 bytes] - length
            [4 bytes] - task id 
            [X...]    - tasking data


    *_SAVE packets have the sub format:
            
            [15 chars] - save prefix
            [5 chars]  - extension
            [X...]     - tasking data

"""


import struct, time, base64


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

    "TASK_CMD_WAIT" : 100,
    "TASK_CMD_WAIT_SAVE" : 101,
    "TASK_CMD_JOB" : 110,
    "TASK_CMD_JOB_SAVE" : 111,
    
    "TASK_SCRIPT_IMPORT" : 120,
    "TASK_SCRIPT_COMMAND" : 121,

    "TASK_SMBWAIT" : 200,
    "TASK_SMBWAIT_SAVE" : 201,
    "TASK_SMBNOWAIT" : 210,
    "TASK_SMBNOWAIT_SAVE" : 211,
}

# build a lookup table for IDS
PACKET_IDS = {}
for name, ID in PACKET_NAMES.items(): PACKET_IDS[ID] = name


def get_counter():
    """
    Derives a 32-bit counter based on the epoch.
    """
    return int(time.time())


def validate_counter(counter):
    """
    Validates a counter ensuring it's in a sliding window.
    Window is +/- 12 hours (43200 seconds)
    """
    currentTime = int(time.time())
    return (currentTime-43200) <= counter <= (currentTime+43200)


def build_task_packet(taskName, data, resultID):
    """
    Build a task packet for an agent.

        [4 bytes] - type
        [4 bytes] - counter
        [4 bytes] - length
        [X...]    - tasking data
    """
    
    taskID = struct.pack('=L', PACKET_NAMES[taskName])
    counter = struct.pack('=L', get_counter())
    length = struct.pack('=L',len(data))
    #TODO this breaks if pk is > 2^32
    resultID = struct.pack('=L', resultID)

    return taskID + counter + length + resultID + data.decode('utf-8').encode('utf-8',errors='ignore')
   

def parse_result_packet(packet, offset=0):
    """
    Parse a result packet-

    Returns a tuple with (responseName, counter, length, data, remainingData)
    """
    try:
        responseID = struct.unpack('=L', packet[0+offset:4+offset])[0]
        counter = struct.unpack('=L', packet[4+offset:8+offset])[0]
        length = struct.unpack('=L', packet[8+offset:12+offset])[0]
        taskID = struct.unpack('=L', packet[12+offset:16+offset])[0]
        data = base64.b64decode(packet[16+offset:16+offset+length])
        #if isinstance(data, unicode):
        #    print "UNICODE DATA"
        #elif isinstance(data, str):
        #    print "ASCII / UTF8"
        remainingData = packet[16+offset+length:]
        return (PACKET_IDS[responseID], counter, length, taskID, data, remainingData)
    except:
        return (None, None, None, None, None, None)


def parse_result_packets(packets):
    """
    Parse a blob of one or more result packets
    """

    resultPackets = []

    # parse the first result packet
    (responseName, counter, length, taskID, data, remainingData) = parse_result_packet(packets)

    if responseName and responseName != '':
        resultPackets.append( (responseName, counter, length, taskID, data) )

    offset = 16 + length
    while (remainingData and remainingData != ""):
        # parse any additional result packets
        (responseName, counter, length, taskID, data, remainingData) = parse_result_packet(packets, offset=offset)

        if responseName and responseName != '':
            resultPackets.append( (responseName, counter, length, taskID, data) )

        offset += 16 + length

    return resultPackets


def resolve_id(ID):
    """
    Resolve a packet ID to its key.
    """
    return PACKET_IDS[int(ID)]
