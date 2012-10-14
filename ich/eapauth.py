#coding: utf-8

import socket
from subprocess import call
from md5 import md5

from eapcode import EAPOL_code
from eappacket import build_ethernet_header, build_EAPOL, build_EAP
from eappacket import unpack_packet


class EAPAuth(object):
    def __init__(self, login_info):
        #: bind client to the EAP protocol
        self.client = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                                    socket.htons(EAPOL_code['ETHERTYPE_PAE']))
        self.client.bind((login_info['ethernet_interface'],
                          EAPOL_code['ETHERTYPE_PAE']))

        #: get local infomations
        self.mac_addr = self.client.getsockname()[4]
        self.ethernet_header = build_ethernet_header(self.mac_addr,
                                                EAPOL_code['PAE_GROUP_ADDR'],
                                                EAPOL_code['ETHERTYPE_PAE'])
        self.sent_logoff = False
        self.login_info = login_info
        self.version_info = '\x06\x07bjQ7SE8BZ3MqHhs3clMregcDY3Y=\x20\x20'

    def send_start(self):
        packet = self.ethernet_header + build_EAPOL('START')
        self.client.send(packet)

    def send_logoff(self):
        packet = self.ethernet_header + build_EAPOL('LOGOFF')
        self.client.send(packet)
        self.sent_logoff = True

    def send_identity(self, packet_id):
        # FIXME is version info needed and right?
        eap = build_EAP('RESPONSE', packet_id, 'IDENTITY',
                        self.version_info + self.login_info['username'])
        packet = self.ethernet_header + build_EAPOL('EAPPACKET', eap)
        self.client.send(packet)

    def send_md5_challenge(self, packet_id, md5value):
        # FIXME TESTING yeah, I just guess the crypt method in GDUT is
        #
        #                   md5(id + password + md5value)
        #
        #               but actually, it didn't get the right value when
        #               I manage to calculate by hand... I hope it's only
        #               because I made some mistakes... XD (and tired)
        #               anyway, leave it for debugging (or cracking...)
        origin = '%s%s%s' % (packet_id, self.login_info['password'], md5value)
        #: EAP-MD5 Value-Size(16) + EAP-MD5 Value
        digest = '\x10' + md5(origin).hexdigest()
        eap = build_EAP('RESPONSE', packet_id, 'MD5_CHALLENGE', digest)
        #: EAP-MD5 Value-Size(16) + EAP-MD5 Value + EAP-MD5 Extra Data
        packet = self.ethernet_header + build_EAPOL('EAPPACKET',
                    eap + self.login_info['username'])
        self.client.send(packet)

    def EAP_handler(self, packet):
        p = unpack_packet(packet)

        if p['type'] != 'EAPPACKET':
            print 'Got unknown EAPOL type %i.' % p['type']

        if p['eapol']['code'] == 'SUCCESS':
            print 'Got EAP success.'

            if self.login_info['dhcp_command']:
                print 'Obtaining IP address:'
                call([self.login_info['dhcp_command'],
                      self.login_info['ethernet_interface']])

        elif p['eapol']['code'] == 'FAILURE':
            if self.sent_logoff:
                print 'Logoff successfully!'
            else:
                print 'Got EAP failure.'
            exit(-1)

        elif p['eapol']['code'] == 'RESPONSE':
            print 'Got unknown EAP response'

        elif p['eapol']['code'] == 'REQUEST':
            req = p['eapol']['eap']
            if req['type'] == 'IDENTITY':
                print 'Got EAP request for identity.'
                self.send_identity(p['eapol']['id'])
                print 'Sending EAP response with identity [%s]' % (
                        self.login_info['username'])
            elif req['type'] == 'MD5_CHALLENGE':
                print 'Got EAP request for md5-challenge'
                self.send_md5_challenge(p['eapol']['id'],
                                        p['eapol']['eap']['data'])
                print 'Sending EAP response with password'
            else:
                print 'Got unknown EAP code (%i)' % p['eapol']['code']

    def run(self):
        try:
            self.send_start()
            while True:
                packet = self.client.recv(1600)
                self.EAP_handler(packet[14:])  # trim header
        except KeyboardInterrupt:
            print 'Interrupted by user'
            self.send_logoff()
        except socket.error, msg:
            print 'Connect error'
            print msg
            exit(-1)
