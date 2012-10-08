#coding: utf-8

import socket
from struct import unpack
from subprocess import call

from eapcode import code
from eappacket import get_ethernet_header, get_EAPOL, get_EAP


class EAPAuth(object):
    def __init__(self, login_info):
        #: bind client to the EAP protocol
        self.client = socket.socket()
        self.client.bind((login_info['ethernet_interface'],
                          code['ETHERTYPE_PAE']))

        #: get local infomations
        self.mac_addr = self.client.sockename()[4]
        self.ethernet_header = get_ethernet_header(self.mac_addr,
                                                   code['PAE_GROUP_ADD'],
                                                   code['ETHERTYPE_PAE'])
        self.sent_logoff = False
        self.login_info = login_info
        # FIXME TEST i don't know what it is, maybe server side auth code?
        self.version_info = '\x06\x07bjQ7SE8BZ3MqHhs3clMregcDY3Y=\x20\x20'

    def send_start(self):
        packet = self.ethernet_header + get_EAPOL(code['EAPOL_START'])
        self.client.send(packet)

    def send_logoff(self):
        packet = self.ethernet_header + get_EAPOL(code['EAPOL_LOGOFF'])
        self.client.send(packet)
        self.sent_logoff = True

    def send_response_id(self, packet_id):
        '''For user identification'''
        eap = get_EAP(code['EAP_RESPONSE'], packet_id, code['EAP_TYPE_ID'],
                      self.version_info + self.login_info['username'])
        packet = get_EAPOL(code['EAPOL_EAPPACKET'], eap)
        self.client.send(self.ethernet_header + packet)

    def send_response_md5(self, packet_id, md5data):
        '''For md5 challenge'''

        # FIXME TEST do you mean the max len is 16?
        #            and how did the password hashed into md5?
        md5 = self.login_info['password'][0:16]
        md5 += '\x00' * (16 - len(md5))  # padding

        chap = []
        for i in xrange(0, 16):
            chap.append(chr(ord(md5[i]) ^ ord(md5data[i])))
        resp = chr(len(chap) + ''.join(chap) + self.login_info['username'])

        eap = get_EAP(code['EAP_RESPONSE'], packet_id, code['EAP_TYPE_MD5'],
                      resp)
        packet = self.ethernet_header + get_EAPOL(eap)
        try:
            self.client.send(packet)
        except socket.error, msg:
            print 'Connection error!'
            print msg
            exit(-1)

    def send_response_h3c(self, packet_id):
        '''For password validation'''
        resp = '%s%s%s' % (chr(len(self.login_info['password'])),
                           self.login['password'], self.login_info['username'])
        eap = get_EAP(code['EAP_RESPONSE'], packet_id, code['EAP_TYPE_H3C'],
                      resp)
        packet = self.ethernet_header + get_EAPOL(code['EAPOL_EAPPACKET'], eap)
        try:
            self.client.send(packet)
        except socket.error, msg:
            print 'Connection error!'
            print msg
            exit(-1)

    def show_login_message(self, msg):
        '''Show the login messages from the radius server
        (but i don't know which type is the authentication server of GDUT)'''

        # FIXME TEST code type (hope GDUT will use unicode only XD)
        try:
            print msg.decode('gbk')
        except UnicodeDecodeError:
            print msg

    def EAP_handler(self, packet):
        vers, type, eapol_len = unpack('!BBH', packet[:4])
        if type != code['EAPOL_EAPPACKET']:
            print 'Got unknown EAPOL type %i.' % type

        c, id, eap_len = unpack('!BBH', packet[4:8])
        if c == code['EAP_SUCCESS']:
            print 'Got EAP success.'

            if self.login_info['dhcp_command']:
                print 'Obtaining IP address:'
                call([self.login_info['dhcp_command'],
                      self.login_info['ethernet_interface']])

            if self.login_info['daemon']:
                self.daemonize()

        if c == code['EAP_FAILURE']:
            if self.sent_logoff:
                print 'Logoff successfully!'
            else:
                print 'Got EAP failure'
            exit(-1)

        if c == code['EAP_RESPONSE']:
            print 'Got unknown EAP response'

        if c == code['EAP_REQUEST']:
            req_type = unpack('!B', packet[8:9])[0]
            req_data = packet[9:4 + eap_len]
            if req_type == code['EAP_TYPE_ID']:
                print 'Got EAP request for indentity'
                self.send_response_id(id)
                print 'Sending EAP response with identity [%s]' % (
                        self.login_info['username'])

            elif req_type == code['EAP_TYPE_H3C']:
                print 'Got EAP request for allocation'
                self.send_response_h3c(id)
                print 'Sending EAP response with password'

            elif req_type == code['EAP_TYPE_MD5']:
                data_len = unpack('!B', req_data[0:1])[0]
                md5data = req_data[1: 1 + data_len]
                print 'Got EAP request for md5-challenge'
                self.send_response_md5(id, md5data)
                print 'Sending EAP response with password'

            # TODO yeah, maybe we will have to assume other code as SRP
            else:
                print 'Got unknown EAP code (%i)' % code

    def run(self):
        '''Run server'''
        try:
            self.send_start()
            while True:
                packet = self.client.recv(1600)
                self.EAP_handler(packet[14:])
        except KeyboardInterrupt:
            print 'Interrupted by user'
            self.send_logoff()
        except socket.error, msg:
            print 'Connect error'
            print msg
            exit(-1)

    def daemonize(self):
        pass
