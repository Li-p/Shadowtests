#!/usr/bin/python
# -*- encoding: utf-8 -*-
from __future__ import print_function

import argparse
import logging
import os
import socket
import struct
import sys

from shadowsocks.cryptor import Cryptor

sys.path.insert(0, os.path.dirname(__file__))

def bytes_to_hex(s):
    if type(s) == str:
        return s.encode('hex')
    else:
        return s.hex()


class ShadowTest(object):
    def __init__(self, server_addr, server_port, server_password, server_method, timeout=5):
        """
        Testing Class
        :param server_addr: shadowsocks server address. Can be either IP, domain name, or hostname
        :type server_addr: str
        :param server_port: shadowsocks server port
        :type server_port: int
        :param server_password: Pre-shared password
        :type server_password: str
        :param server_method: Encryption method
        :type server_method: str
        :param timeout: local socket timeout in seconds. 5 by default
        """
        self._addr = server_addr
        self._port = server_port
        self._pass = server_password
        self._method = server_method
        self._timeout = timeout
        self._fatalerror = False
        self.ip_result = ""


    def _craft_hankshake(self, port, ipv4=None, hostname=None, ipv6=None):
        """
        Craft hankshake packet for shadowsocks server. one of ipv4, hostname, and ipv6 must be specified
        the hankshake packet is essentially a Socks request but without the first 3 bytes
        +------+----------+----------+
        | ATYP | DST.ADDR | DST.PORT |
        +------+----------+----------+
        |  1   | Variable |    2     |
        +------+----------+----------+
        for more info see https://www.ietf.org/rfc/rfc1928.txt
        :param port: Dest. Port in int
        :param ipv4: Dest. ipv4 address in str
        :param hostname: Dest. hostname in str, must be less than 255 in length
        :return: hankshake packet in bytes
        """
        if ipv4:
            packet = b"\x01" + socket.inet_aton(ipv4) + struct.pack("!H", port)
            logging.debug("Handshake to %s:%d: %s", ipv4, port, bytes_to_hex(packet))
        elif hostname:
            packet = b"\x03" + chr(len(hostname)).encode() + hostname.encode() + struct.pack("!H", port)
            logging.debug("Handshake to %s:%d: 0x%s", hostname, port, bytes_to_hex(packet))
        elif ipv6:
            #TODO
            raise NotImplemented("IPv6 support is not implemented")
        return packet

    def connect_tcp(self):
        """
        Try to establish tcp connection to shadowsocks server then close it without sending any data
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((self._addr, self._port))
            sock.close()
        except socket.gaierror:
            logging.error("Fatal Error: unable to resolve name: " + self._addr)
            self._fatalerror = True
        except ConnectionRefusedError:
            logging.error("Connection to %s:%d is refused", self._addr, self._port)
            self._fatalerror = True


    def tcp_relay(self, port, payload, ipv4=None, ipv6=None, hostname=None):

        if ipv4:
            handshake = self._craft_hankshake(port, ipv4=ipv4)
        elif ipv6:
            handshake = self._craft_hankshake(port, ipv6=ipv6)
        elif hostname:
            handshake = self._craft_hankshake(port, hostname=hostname)
        else:
            raise ValueError("Unspecified destination")

        cryptor = Cryptor(self._pass, self._method)
        logging.debug("Cryptor created: method: %s key: %s IV: %s", cryptor.method, bytes_to_hex(cryptor.key), bytes_to_hex(cryptor.cipher_iv))
        handshake = cryptor.encrypt(handshake)
        payload = cryptor.encrypt(payload)

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((self._addr, self._port))
            sock.send(handshake)
            logging.debug("Raw data sent to Shadowsocks: %s", bytes_to_hex(handshake))
            sock.send(payload)
            logging.debug("Raw data sent to Shadowsocks: %s", bytes_to_hex(payload))
            resp = sock.recv(65500)
            logging.debug("Raw data received from Shadowsocks: %s", bytes_to_hex(resp))
        except socket.error:
            logging.error("Shadowsocks server closed the connection unexpctedly. Wrong password?")
            return b''
        except Exception as err:
            raise err

        decrypted_resp = cryptor.decrypt(resp)
        logging.debug("Decrypted: %s", bytes_to_hex(resp))
        return decrypted_resp


    def generate_204(self):
        """
        Try to access http://www.gstatic.com/generate_204 which is currently blocked by the GFW
        :return: True if remote server returns a http 204 response
        """
        if self._fatalerror:
            return False
        payload = b"GET /generate_204 HTTP/1.1\r\nHost: www.gstatic.com\r\n\r\n"
        resp_b = self.tcp_relay(80, payload, hostname="www.gstatic.com")
        resp = resp_b.decode('utf-8')
        return resp.startswith("HTTP/1.1 204 No Content")

    def icanhazip(self):
        """
        Try to access http://www.icanhazip.com/ which returns nothing but client's IP
        :return: that webpage's content, which will be shadowsocks server's IP
        """
        if self._fatalerror:
            return False
        payload = b"GET / HTTP/1.1\r\nHost: www.icanhazip.com\r\n\r\n"
        resp_b = self.tcp_relay(80, payload, hostname="www.icanhazip.com")
        resp = resp_b.decode('utf-8')
        if resp.startswith("HTTP/1.1 200"):
            self.ip_result = resp.strip().split('\n')[-1]
            return True

def main():
    parser = argparse.ArgumentParser(description="Test connectivity to a Shadowsocks server")
    parser.add_argument('addr', help="Shadowsocks Server's Address, IP or domain name", type=str)
    parser.add_argument('port', help="Shadowsocks Server's port", type=int)
    parser.add_argument("password", help="Pre-shared password", type=str)
    parser.add_argument("method", help="Encryption method", type=str)
    parser.add_argument("-v", "--verbose", help="Show debug info",action="store_true")
    parser.add_argument("-S", "--simple", help=
                        "Simple mode: print 1 if able to access Google's generate_204 site 0 if any error occurs",
                        action="store_true")
    args = parser.parse_args()

    if args.simple:
        logging.basicConfig(level=100)
        shadowtest = ShadowTest(args.addr, args.port, args.password, args.method)
        if shadowtest.generate_204():
            print(1)
        else:
            print(0)
        return

    logging.basicConfig(format="[%(asctime)s] %(message)s", level=logging.DEBUG if args.verbose else logging.INFO)
    logging.info("Shadowsocks Server: %s %d %s %s", args.addr, args.port, args.password, args.method)
    shadowtest = ShadowTest(args.addr, args.port, args.password, args.method)
    logging.info("Establishing connection to Shadowsocks server %s:%d", args.addr, args.port)
    if shadowtest.connect_tcp():
        logging.info("OK")

    logging.info("Accessing Google")
    if shadowtest.generate_204():
        logging.info("OK")
    else:
        logging.info("Unable to access Google's generate_204 page")

    logging.info("Accessing www.icanhazip.com")
    if shadowtest.icanhazip():
        logging.info("OK: %s", shadowtest.ip_result)


if __name__ == '__main__':
    main()