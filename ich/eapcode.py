#coding: utf-8

'''
    eapcode.py
    ~~~~~~~~~~
    EAP status code
'''

# EAP request packet type
# 1       Identity
# 2       Notification
# 3       Nak (Response only)
# 4       MD5-Challenge
# 5       One Time Password (OTP)
# 6       Generic Token Card (GTC)
# 20      Secure Remote Password SHA1 part 2 EAP
# 254     Expanded Types
# 255     Experimental use
EAP_request_type = {
        'IDENTITY': 1,
        'MD5_CHALLENGE': 4,
        'H3C': 7,
        'SRP_PART2': 20  # Secure Remote Password SHA1 part 2 EAP
}

EAP_packet_type = {
        'REQUEST': 1,
        'RESPONSE': 2,
        'SUCCESS': 3,
        'FAILURE': 4,
        'MESSAGE': 10,
}

EAPOL_type = {
        'EAPPACKET': 0,
        'START': 1,
        'LOGOFF': 2,
        'KEY': 3,
        'ASF': 4
}

EAPOL_code = {
        'VERSION': 1,  # 802.1X-2001

        'ETHERTYPE_PAE': 0x888e,  # 802.1X
        # FIXME it's seem that the remote server addr in GDUT
        #       is 00:0f:e2:22:b6:94
        'PAE_GROUP_ADDR': '\x01\x80\xc2\x00\x00\x03',  # remote server addr
        'BROADCAST_ADDR': '\xff\xff\xff\xff\xff\xff'
}
