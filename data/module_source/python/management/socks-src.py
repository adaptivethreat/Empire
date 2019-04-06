#!/usr/bin/env python
import argparse
import logging
import random
import select
import shlex
import signal
import socket
import ssl
import struct
import sys

MTYPE_NOOP = 0x00   # No-op. Used for keepalive messages
MTYPE_COPEN = 0x01  # Open Channel messages
MTYPE_CCLO = 0x02   # Close Channel messages
MTYPE_CADDR = 0x03  # Channel Address (remote endpoint address info)
MTYPE_DATA = 0x10   # Data messages


def recvall(s, size):
    data = ''
    while len(data) < size:
        d = s.recv(size - len(data))
        if not d:
            break
        data += d
    return data


def integer_generator(seed=random.randint(0, 0xffffffff)):
    while True:
        seed = (seed + 1) % 0xffffffff
        yield seed


class Message(object):
    """ Container class with (un)serialization methods """
    M_HDR_STRUCT = struct.Struct('!BII')  # Message Type | Channel ID | Payload Size

    def __init__(self, mtype=MTYPE_NOOP, channel=0, size=0):
        self.mtype = mtype
        self.channel = channel
        self.size = size

    def __str__(self):
        return '<Message type={} channel={}>'.format(self.mtype, self.channel)

    @classmethod
    def unpack(cls, data):
        if len(data) < cls.M_HDR_STRUCT.size:
            raise ValueError('Attempting to unpack a Message header from too little data')
        return Message(*cls.M_HDR_STRUCT.unpack(data[:cls.M_HDR_STRUCT.size])), data[cls.M_HDR_STRUCT.size:]

    def pack(self, data=''):
        self.size = len(data)
        return self.M_HDR_STRUCT.pack(self.mtype, self.channel, self.size) + data


class Channel(object):
    """ Container class with remote socket and channel id """
    def __init__(self):
        self.socket = None  # type: socket.socket
        self.channel_id = None
        self.remote_peer_addr = None
        self.local_peer_addr = None
        self.socks_handler = SocksHandler()
        self.logger = logging.getLogger(self.__class__.__name__)

    def __str__(self):
        return '<Channel id={} remote_addr={} local_addr={}>'.format(self.channel_id, self.remote_peer_addr, self.local_peer_addr)

    @property
    def connected(self):
        return isinstance(self.socket, socket.socket)

    def fileno(self):
        return self.socket.fileno()

    def close(self):
        self.logger.debug('Closing channel {}'.format(self))
        if self.connected:
            try:
                self.socket.shutdown(socket.SHUT_RDWR)
                self.socket.close()
            except Exception as e:
                self.logger.debug('Unable to close channel: {}'.format(e))
            self.socket = None


class Tunnel(object):
    """ Container class with connected transport socket, list of Channels, and methods for passing Messages """
    def __init__(self, transport_socket):
        self.channels = []  # List[Channel]
        self.transport_socket = transport_socket  # type: socket.socket
        self.logger = logging.getLogger(self.__class__.__name__)

    def send_message(self, msg, data=''):
        self.logger.debug('Sending {}'.format(msg))
        try:
            self.transport_socket.sendall(msg.pack(data))
        except (socket.error, TypeError) as e:
            self.logger.critical('Problem sending a message over transport: {}'.format(e))
            sys.exit(255)

    def recv_message(self):
        try:
            msg, _ = Message.unpack(recvall(self.transport_socket, Message.M_HDR_STRUCT.size))
        except socket.error as e:
            self.logger.critical('Problem receiving a message over transport: {}'.format(e))
            sys.exit(255)
        return msg, recvall(self.transport_socket, msg.size)

    def get_channel_by_id(self, channel_id):
        for c in self.channels:
            if c.channel_id == channel_id:
                return c
        raise KeyError('Invalid channel number "{}"'.format(channel_id))

    def open_channel(self, channel_id, remote=False):
        c = Channel()
        c.channel_id = channel_id
        self.channels.append(c)
        if remote:
            msg = Message(mtype=MTYPE_COPEN, channel=c.channel_id)
            self.send_message(msg)
        return c

    def close_channel(self, channel_id, remote=False):
        for c in self.channels:
            if c.channel_id == channel_id:
                c.close()
                self.channels.remove(c)
                self.logger.info('Closed channel: {}'.format(c))
                break
        if remote:
            msg = Message(mtype=MTYPE_CCLO, channel=channel_id)
            self.send_message(msg)
        return


class SocksHandler(object):
    SOCKS5_AUTH_METHODS = {
        0x00: 'No Authentication Required',
        0x01: 'GSSAPI',
        0x02: 'USERNAME/PASSWORD',
        0xFF: 'NO ACCEPTABLE METHODS'
    }

    def __init__(self):
        self.auth_handled = False
        self.request_handled = False
        self.logger = logging.getLogger(self.__class__.__name__)

    def handle(self, channel, data):
        # SOCKSv5 Auth message
        if not self.auth_handled:
            data = [ord(x) for x in data]

            # Expecting [VERSION | NMETHODS | METHODS] (VERSION must be 0x05)
            if len(data) < 2 or data[0] != 0x05 or len(data[2:]) != data[1]:
                return struct.pack('BB', 0x05, 0xFF)  # No Acceptable Auth Methods

            methods = [self.SOCKS5_AUTH_METHODS.get(x, hex(x)) for x in data[2:]]
            self.logger.debug('Received SOCKS auth request: {}'.format(', '.join(methods)))

            self.auth_handled = True
            return struct.pack('BB', 0x05, 0x00)  # No Auth Required

        elif not self.request_handled:
            if len(data) < 4 or ord(data[0]) != 0x05:
                return struct.pack('!BBBBIH', 0x05, 0x01, 0x00, 0x01, 0, 0)  # General SOCKS failure
            cmd = ord(data[1])
            rsv = ord(data[2])
            atyp = ord(data[3])
            if cmd not in [0x01, 0x02, 0x03]:
                return struct.pack('!BBBBIH', 0x05, 0x07, 0x00, 0x01, 0, 0)  # Command not supported
            if rsv != 0x00:
                return struct.pack('!BBBBIH', 0x05, 0x01, 0x00, 0x01, 0, 0)  # General SOCKS failure
            if atyp not in [0x01, 0x03, 0x04]:
                return struct.pack('!BBBBIH', 0x05, 0x08, 0x00, 0x01, 0, 0)  # Address type not supported

            if cmd == 0x01:  # CONNECT
                if atyp == 0x01:  # IPv4
                    if len(data) != 10:
                        return struct.pack('!BBBBIH', 0x05, 0x01, 0x00, 0x01, 0, 0)  # General SOCKS failure
                    host = socket.inet_ntop(socket.AF_INET, data[4:8])
                    port, = struct.unpack('!H', data[-2:])
                    af = socket.AF_INET
                elif atyp == 0x03:  # FQDN
                    size = ord(data[4])
                    if len(data[5:]) != size + 2:
                        return struct.pack('!BBBBIH', 0x05, 0x01, 0x00, 0x01, 0, 0)  # General SOCKS failure
                    host = data[5:5+size]
                    port, = struct.unpack('!H', data[-2:])
                    af = socket.AF_INET
                    atyp = 0x01
                elif atyp == 0x04:  # IPv6
                    if len(data) != 22:
                        return struct.pack('!BBBBIH', 0x05, 0x01, 0x00, 0x01, 0, 0)  # General SOCKS failure
                    host = socket.inet_ntop(socket.AF_INET6, data[5:21])
                    port, = struct.unpack('!H', data[-2:])
                    af = socket.AF_INET6
                else:
                    raise NotImplementedError('Failed to implement handler for atype={}'.format(hex(atyp)))

                self.logger.debug('Received SOCKSv5 CONNECT request for {}:{}'.format(host, port))

                try:
                    s = socket.socket(af)
                    s.settimeout(2)
                    s.connect((host, port))
                except socket.timeout:
                    return struct.pack('!BBBBIH', 0x05, 0x04, 0x00, 0x01, 0, 0)  # host unreachable
                except socket.error:
                    return struct.pack('!BBBBIH', 0x05, 0x05, 0x00, 0x01, 0, 0)  # connection refused
                except Exception:
                    return struct.pack('!BBBBIH', 0x05, 0x01, 0x00, 0x01, 0, 0)  # General SOCKS failure
                s.settimeout(None)
                channel.socket = s
                peer_host, peer_port = s.getpeername()[:2]
                channel.local_peer_addr = '{}[{}]:{}'.format(host, peer_host, port)

                local_host, local_port = s.getsockname()[:2]
                bind_addr = socket.inet_pton(af, local_host)
                bind_port = struct.pack('!H', local_port)

                ret = struct.pack('!BBBB', 0x05, 0x00, 0x00, atyp) + bind_addr + bind_port
                self.logger.info('Connected {}'.format(channel))
                self.request_handled = True
                return ret

            elif cmd == 0x02:  # BIND
                raise NotImplementedError('Need to implement BIND command')  # TODO

            elif cmd == 0x03:  # UDP ASSOCIATE
                raise NotImplementedError('Need to implement UDP ASSOCIATE command')  # TODO

            else:
                raise NotImplementedError('Failed to implemented handler for cmd={}'.format(hex(cmd)))


class SocksBase(object):
    def __init__(self, transport_addr=('', 443), socks_addr=('', 1080), keepalive=None, key=None, cert=None):
        self.tunnel = None  # type: Tunnel
        self.transport_addr = transport_addr
        self.socks_addr = socks_addr
        self.keepalive = keepalive
        self.socks_socket = None  # type: socket.socket
        self.next_channel_id = integer_generator()
        self.key = key
        self.cert = cert
        self.logger = logging.getLogger(self.__class__.__name__)

    def check_socks_protocol(self, c, data):
        return False

    def monitor_sockets(self):
        while True:
            # Check tunnel and peer connections
            sockets = [x for x in self.tunnel.channels if x.connected] + [self.tunnel.transport_socket]
            if self.socks_socket is not None:
                sockets.append(self.socks_socket)

            try:
                r, _, _ = select.select(sockets, [], [], self.keepalive)
            except select.error:
                continue

            if not r:
                msg = Message(mtype=MTYPE_NOOP)  # timeout, send keepalive
                self.tunnel.send_message(msg)
                continue

            if self.tunnel.transport_socket in r:
                try:
                    msg, data = self.tunnel.recv_message()
                except Exception as e:
                    self.logger.critical('Error receiving messages, exiting')
                    self.logger.debug('Error message: {}'.format(e))
                    self.tunnel.transport_socket.close()
                    return

                if msg.mtype == MTYPE_NOOP:
                    self.logger.debug('Received keepalive message, discarding')

                elif msg.mtype == MTYPE_COPEN:
                    c = self.tunnel.open_channel(msg.channel)
                    self.logger.debug('Received OpenChannel message, opened channel: {}'.format(c))

                elif msg.mtype == MTYPE_CCLO:
                    try:
                        c = self.tunnel.get_channel_by_id(msg.channel)
                        self.tunnel.close_channel(msg.channel)
                    except KeyError:
                        pass
                    else:
                        self.logger.info('Closed a channel: {}'.format(c))

                elif msg.mtype == MTYPE_CADDR:
                    try:
                        c = self.tunnel.get_channel_by_id(msg.channel)
                    except KeyError:
                        pass
                    else:
                        c.remote_peer_addr = data
                        self.logger.info('Channel connected remotely: {}'.format(c))

                elif msg.mtype == MTYPE_DATA:
                    try:
                        c = self.tunnel.get_channel_by_id(msg.channel)
                    except KeyError:
                        pass
                    else:
                        self.logger.debug('Received {} bytes from tunnel for {}'.format(len(data), c))
                        if not self.check_socks_protocol(c, data):
                            try:
                                c.socket.sendall(data)
                            except:
                                self.logger.debug('Problem sending data to channel {}'.format(c))
                                self.tunnel.close_channel(msg.channel, remote=True)

                else:
                    self.logger.warning('Received message of unknown type {}'.format(hex(msg.mtype)))

                continue

            if self.socks_socket is not None and self.socks_socket in r:
                s, addr = self.socks_socket.accept()
                addr = '{}:{}'.format(*addr)
                c = self.tunnel.open_channel(self.next_channel_id.next(), remote=True)
                c.local_peer_addr = addr
                c.socket = s
                self.logger.info('Created new channel: {}'.format(c))
                continue

            for c in r:
                try:
                    data = c.socket.recv(1024)
                except Exception as e:
                    self.logger.debug('Problem recving from {}: {}'.format(c, e))
                    self.tunnel.close_channel(c.channel_id, remote=True)
                    break
                if not data:
                    self.logger.debug('Received EOF from local socket, closing channel')
                    self.tunnel.close_channel(c.channel_id, remote=True)
                msg = Message(mtype=MTYPE_DATA, channel=c.channel_id)
                self.tunnel.send_message(msg, data=data)
                self.logger.debug('Sent {} bytes over tunnel: {}'.format(len(data), msg))

    def run(self):
        raise NotImplementedError('Subclasses should implement the run() method')


class SocksRelay(SocksBase):
    def check_socks_protocol(self, c, data):
        if not c.socks_handler.auth_handled:
            res = c.socks_handler.handle(c, data)
            if not c.socks_handler.auth_handled:
                self.logger.warning('SOCKS auth handler failed, expect channel close for {}'.format(c))
            msg = Message(mtype=MTYPE_DATA, channel=c.channel_id)
            self.tunnel.send_message(msg, data=res)
            return True
        elif not c.socks_handler.request_handled:
            res = c.socks_handler.handle(c, data)
            msg = Message(mtype=MTYPE_DATA, channel=c.channel_id)
            self.tunnel.send_message(msg, data=res)
            if not c.socks_handler.request_handled:
                self.logger.warning('SOCKS req handler failed, expect channel close for {}'.format(c))
            else:
                msg = Message(mtype=MTYPE_CADDR, channel=c.channel_id)
                self.tunnel.send_message(msg, data=c.local_peer_addr)
            return True
        else:
            return False

    def run(self):
        s = socket.socket()
        s = ssl.wrap_socket(s)
        self.logger.debug('Connecting to {}:{}'.format(*self.transport_addr))
        try:
            s.connect(self.transport_addr)
        except Exception as e:
            self.logger.error('Problem connecting to server: {}'.format(e))
        else:
            self.logger.info('Connected to {}:{}'.format(*self.transport_addr))
            self.tunnel = Tunnel(s)
            self.monitor_sockets()
        self.logger.warning('SOCKS relay is exiting')


def relay_main(tunnel_addr=''):
    tunnel_addr = (tunnel_addr.split(':')[0], int(tunnel_addr.split(':')[1]))
    relay = SocksRelay(transport_addr=tunnel_addr)
    relay.run()
    return


relay_main(tunnel_addr='${TUNNEL_ADDR}')
