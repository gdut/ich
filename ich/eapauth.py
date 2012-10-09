#coding: utf-8

import socket
from subprocess import call

from eapcode import EAPOL_code
from eappacket import build_ethernet_header, build_EAPOL, build_EAP
from eappacket import unpack_packet


class EAPAuth(object):
    def __init__(self, login_info):
        #: bind client to the EAP protocol
        self.client = socket.socket()
        self.client.bind(login_info['ethernet_interface'],
                         EAPOL_code['ETERTYPE_PAE'])

        #: get local infomations
        self.mac_addr = self.client.sockename()[4]
        self.ethernet_header = build_ethernet_header(self.mac_addr,
                                                EAPOL_code['PAE_GROUP_ADD'],
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

    def send_md5_challenge(self, packet_id):
        raise NotImplemented

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
