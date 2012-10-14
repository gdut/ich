#coding: utf-8

'''
    eappacket.py
    ~~~~~~~~~~~~
    Build EAP packet.

    a packet contains:
        - EAP header:
            - destination address
            - source address
            - type (!H, is 0x888e here)

        - EAPOL (!BBH):
            - version
            - type
            - length (!H, actually is EAP's length)

        If EAPOL's type is EAPPAACKET (0), the EAPOL will
        also contains a EAP.

        - EAP (!BBH or !BBHB):
          if the EAP is to send FAILURE or SUCCESS, it will
          only contains:
            - code
            - id
            - length (!H)
          otherwise, the EAP should contains type and data:
            - code
            - id
            - length (!H)
            - type
            - data

    to summarize, a packet =
        header(dest, src, type)
         + EAPOL(version, type, length, [EAP(code, id, length, [type, data])])
'''

from struct import pack, unpack

from eapcode import EAPOL_code, EAPOL_type
from eapcode import EAP_packet_type, EAP_request_type


def find_key(value, d):
    '''find value's key from the dict'''
    for k, v in d.items():
        if v == value:
            return k
    return None


def build_ethernet_header(dest, src, header_type=None):
    header_type = header_type or EAPOL_code['ETHERTYPE_PAE']
    return dest + src + pack('!H', header_type)


def build_EAPOL(eapol_type, payload=None):
    payload = payload or ''
    return pack('!BBH', EAPOL_code['VERSION'], EAPOL_type[eapol_type],
                len(payload)) + payload


def build_EAP(code, id, eap_type, data=None):
    data = data or ''
    if code in ('SUCCESS', 'FAILURE'):
        return pack('!BBH', EAP_packet_type[code], id, 4)
    else:  # is a packet
        return pack('!BBHB', EAP_packet_type[code], id, 5 + len(data),
                    EAP_request_type[eap_type]) + data


def unpack_eap(packet, data_length):
    eap_type = unpack('!B', packet[0:1])[0]
    eap_type = find_key(eap_type, EAP_packet_type)
    # FIXME is really?
    eap_data = packet[1:4 + data_length]
    return dict(type=eap_type, data=eap_data)


def unpack_eappacket(packet):
    code, id, length = unpack('!BBH', packet)
    code = find_key(code, EAP_packet_type)
    if code == 'REQUEST':
        eap = unpack_eap(packet[4:], length)
    else:
        eap = None
    return dict(code=code, id=id, length=length, eap=eap)


def unpack_packet(packet):
    version, eapol_type, length = unpack('!BBH', packet[:4])

    eapol_type = find_key(eapol_type, EAPOL_type)
    if eapol_type == 'EAPPACKET':
        eapol = unpack_eappacket(packet[4:])
    else:
        eapol = None
    return dict(version=version, type=eapol_type, length=length, eapol=eapol)
