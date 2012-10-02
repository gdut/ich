#coding: utf-8

code = {
        'ETHERTYPE_TYPE': 0x888e,
        'PAE_GROUP_ADDR': '\x01\x80\xc2\x00\x00\x03',
        'BROADCAST_ADDR': '\xff\xff\xff\xff\xff\xff',

        'EAPOL_VERSION': 1,
        'EAPOL_PACKET': 0,

        #: packet info for EAPOL_EAPPACKET
        'EAPOL_START': 1,
        'EAPOL_LOGOFF': 2,
        'EAPOL_KEY': 3,
        'EAPOL_ASF': 4,
        'EAP_REQUEST': 1,
        'EAP_RESPONSE': 2,
        'EAP_SUCCESS': 3,
        'EAP_FAILURE': 4,

        # packet info followed after EAP_RESPONSE
        # FIXME TEST ok, in the eapauth, actually it's followed
        #            after EAP_REQUEST rather EAP_RESPONSE
        # 1       Identity
        # 2       Notification
        # 3       Nak (Response only)
        # 4       MD5-Challenge
        # 5       One Time Password (OTP)
        # 6       Generic Token Card (GTC)
        # 254     Expanded Types
        # 255     Experimental use
        'EAP_TYPE_ID': 1,  # identity
        'EAP_TYPE_MD5': 4,  # md5 challenge
        # FIXME TEST is it 7 in GDUT?
        'EAP_TYPE_H3C': 7  # h3c eap packet
}
