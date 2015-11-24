#!/usr/bin/env python

import unittest
import base64
import pyDes
import hmac
import hashlib
import json
from sermepa import orderSecret, signPayload


class Generator_Test(unittest.TestCase):

    # back2back data taken from PHP example

    json = (
        '{'
        '"DS_MERCHANT_AMOUNT":"145",'
        '"DS_MERCHANT_ORDER":"1447961844",'
        '"DS_MERCHANT_MERCHANTCODE":"999008881",'
        '"DS_MERCHANT_CURRENCY":"978",'
        '"DS_MERCHANT_TRANSACTIONTYPE":"0",'
        '"DS_MERCHANT_TERMINAL":"871",'
        '"DS_MERCHANT_MERCHANTURL":"",'
        '"DS_MERCHANT_URLOK":"",'
        '"DS_MERCHANT_URLKO":""'
        '}'
    )
    encodedPayload = (
        "eyJEU19NRVJDSEFOVF9BTU9VTlQiOiIxNDUiLCJEU19NRVJDSEFOVF9PUkRFUiI6IjE0NDc5N"
        "jE4NDQiLCJEU19NRVJDSEFOVF9NRVJDSEFOVENPREUiOiI5OTkwMDg4ODEiLCJEU19NRVJDSE"
        "FOVF9DVVJSRU5DWSI6Ijk3OCIsIkRTX01FUkNIQU5UX1RSQU5TQUNUSU9OVFlQRSI6IjAiLCJ"
        "EU19NRVJDSEFOVF9URVJNSU5BTCI6Ijg3MSIsIkRTX01FUkNIQU5UX01FUkNIQU5UVVJMIjoi"
        "IiwiRFNfTUVSQ0hBTlRfVVJMT0siOiIiLCJEU19NRVJDSEFOVF9VUkxLTyI6IiJ9"
        )
    merchantOrder = b"1447961844"
    merchantkey = b'Mk9m98IfEblmPfrpsawt7BmxObt98Jev'
    secret= b'38t5Zm5RjlVHNycd8Nutcg=='
    signature = b'Ejse86yr96Xbr1mf6UvQLoTPwwTyFiLXM+2uT09i9nY='


    def test_encodePayload(self):
        self.assertEqual(
            base64.b64encode(self.json),
            self.encodedPayload)

    def test_generateSecret(self):
        secret = orderSecret(self.merchantkey, self.merchantOrder)

        self.assertEqual(self.secret, secret)

    def test_signPayload(self):   
        signature = signPayload(self.secret, self.encodedPayload)

        self.assertMultiLineEqual(signature, self.signature)



class NotificationReceiver_Test(unittest.TestCase):

    # back2back data taken from PHP example

    encodeddata = b'eyJEc19PcmRlciI6ICI2NjYifQ=='
    data = (
        '{'
            '"Ds_Order": "666"'
        '}'
        )
    merchantkey = b'Mk9m98IfEblmPfrpsawt7BmxObt98Jev'
    secret = '1uGRHjGaVgg='
    signature = b"BskiXgq875tls56oClRVg72-ppcLpOSW0JUY9riQEKs="

    def test_payloadDecoding(self):
        # TODO: Should be urlsafe_b64decode, provide an input which differs
        decodedData = base64.b64decode(self.encodeddata)
        self.assertEqual(decodedData, self.data)

    def test_obtainOrder(self):
        order = json.loads(self.data)['Ds_Order']
        self.assertEqual(order, '666')

    def test_generateSecret(self):
        secret= orderSecret(self.merchantkey, "666")
        self.assertEqual(self.secret, secret)

    def test_computeKey(self):
        signature = signPayload(self.secret, self.encodeddata, urlsafe=True)
        self.assertMultiLineEqual(self.signature, signature)


unittest.TestCase.__str__ = unittest.TestCase.id

if __name__ == '__main__':
    import sys
    code = unittest.maini()
    sys.exit(code)




