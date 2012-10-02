#coding: utf-8

'''For building EAP packet.'''

from struct import pack

from eapcode import code


def get_EAPOL(type, payload=''):
    return pack('!BBH', code['EAPOL_VERSION'], type, len(payload)) + payload


def get_EAP(c, id, type=0, data=''):
    if c in [code['EAP_SUCCESS'], code['EAP_FAILURE']]:
        return pack('!BBH', code, id, 4)
    else:
        return pack('!BBHB', code, id, 5 + len(data), type) + data


def get_ethernet_header(src, dest, type):
    return dest + src + pack('!H', type)
