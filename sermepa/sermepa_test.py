#!/usr/bin/env python2
# -*- coding: utf-8 -*-

import unittest

import base64
import json
import re
from sermepa import orderSecret, signPayload, decodeSignedData, SignatureError, encodeSignedData

try:
    import config
except ImportError:
    config = None


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
        "eyJEU19NRVJDSEFOVF9BTU9VTlQiOiIxNDUiLCJEU19NRVJDSEFOVF9PUkRFUiI6I"
        "jE0NDc5NjE4NDQiLCJEU19NRVJDSEFOVF9NRVJDSEFOVENPREUiOiI5OTkwMDg4OD"
        "EiLCJEU19NRVJDSEFOVF9DVVJSRU5DWSI6Ijk3OCIsIkRTX01FUkNIQU5UX1RSQU5"
        "TQUNUSU9OVFlQRSI6IjAiLCJEU19NRVJDSEFOVF9URVJNSU5BTCI6Ijg3MSIsIkRT"
        "X01FUkNIQU5UX01FUkNIQU5UVVJMIjoiIiwiRFNfTUVSQ0hBTlRfVVJMT0siOiIiL"
        "CJEU19NRVJDSEFOVF9VUkxLTyI6IiJ9"
        )
    merchantOrder = b"1447961844"
    merchantkey = b'Mk9m98IfEblmPfrpsawt7BmxObt98Jev'
    secret= b'38t5Zm5RjlVHNycd8Nutcg=='
    signature = b'Ejse86yr96Xbr1mf6UvQLoTPwwTyFiLXM+2uT09i9nY='
    signatureversion = 'HMAC_SHA256_V1'


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

class GeneratorFull_Test(Generator_Test):

    data = dict(
        Ds_Merchant_MerchantCode = 'the_sermepa_user',
        Ds_Merchant_Order = '1447961844',
        Ds_Merchant_Amount = '10000',
        Ds_Merchant_ProductDescription = 'the_name_of_the_product',
        Ds_Merchant_Titular = 'the_owner_of_the_account',
        Ds_Merchant_MerchantName = 'the_merchant_name',
        Ds_Merchant_MerchantURL = 'the_url_to_be_notified_at',
        Ds_Merchant_UrlOK = 'the_url_for_success',
        Ds_Merchant_UrlKO = 'the_url_for_failure',
        Ds_Merchant_ConsumerLanguage = '001',
        Ds_Merchant_Terminal = '1',
        Ds_Merchant_SumTotal = '10000',
        Ds_Merchant_TransactionType = '0',
        Ds_Merchant_MerchantData = 'COBRAMENT QUOTA SOCI',
        )
    json = json.dumps(data, sort_keys=True)
    encodedPayload = (
        "eyJEc19NZXJjaGFudF9BbW91bnQiOiAiMTAwMDAiLCAiRHNfTWVyY2hhbnRfQ29uc"
        "3VtZXJMYW5ndWFnZSI6ICIwMDEiLCAiRHNfTWVyY2hhbnRfTWVyY2hhbnRDb2RlIj"
        "ogInRoZV9zZXJtZXBhX3VzZXIiLCAiRHNfTWVyY2hhbnRfTWVyY2hhbnREYXRhIjo"
        "gIkNPQlJBTUVOVCBRVU9UQSBTT0NJIiwgIkRzX01lcmNoYW50X01lcmNoYW50TmFt"
        "ZSI6ICJ0aGVfbWVyY2hhbnRfbmFtZSIsICJEc19NZXJjaGFudF9NZXJjaGFudFVST"
        "CI6ICJ0aGVfdXJsX3RvX2JlX25vdGlmaWVkX2F0IiwgIkRzX01lcmNoYW50X09yZG"
        "VyIjogIjE0NDc5NjE4NDQiLCAiRHNfTWVyY2hhbnRfUHJvZHVjdERlc2NyaXB0aW9"
        "uIjogInRoZV9uYW1lX29mX3RoZV9wcm9kdWN0IiwgIkRzX01lcmNoYW50X1N1bVRv"
        "dGFsIjogIjEwMDAwIiwgIkRzX01lcmNoYW50X1Rlcm1pbmFsIjogIjEiLCAiRHNfT"
        "WVyY2hhbnRfVGl0dWxhciI6ICJ0aGVfb3duZXJfb2ZfdGhlX2FjY291bnQiLCAiRH"
        "NfTWVyY2hhbnRfVHJhbnNhY3Rpb25UeXBlIjogIjAiLCAiRHNfTWVyY2hhbnRfVXJ"
        "sS08iOiAidGhlX3VybF9mb3JfZmFpbHVyZSIsICJEc19NZXJjaGFudF9VcmxPSyI6"
        "ICJ0aGVfdXJsX2Zvcl9zdWNjZXNzIn0="
        )
    signature = "eg0L/kTPyflwoOV0djlsCB/K4Uw5+balc7dyMkUjBIE="

    def setUp(self):
        self.maxDiff = None

    def test_encodeSignedData_whenAllOk(self):
        result = encodeSignedData(
            self.merchantkey,
            **self.data
            )
        self.assertEqual(result, dict(
            Ds_SignatureVersion = 'HMAC_SHA256_V1',
            Ds_Signature = self.signature,
            Ds_MerchantParameters =  self.encodedPayload,
            ))

    def test_encodeSignedData_whenNoOrder(self):
        data = dict(self.data)
        del data['Ds_Merchant_Order']
        with self.assertRaises(KeyError):
            encodeSignedData(
                self.merchantkey,
                **data
                )

    def test_encodeSignedData_whenNoOrder(self):
        data = dict(self.data)
        data['BadData'] = "value"
        with self.assertRaises(ValueError):
            encodeSignedData(
                self.merchantkey,
                **data
                )

    @unittest.skipIf(not config, "Requires a config.py file")
    @unittest.skipIf(config and 'redsystest' not in config.__dict__,
        "redsystest dictionary missing in config.py")
    def test_sendingPost_testing(self):

        data = dict(
            Ds_Merchant_Amount = "10000",
            Ds_Merchant_ConsumerLanguage = "003",
            Ds_Merchant_Currency = "978",
            Ds_Merchant_MerchantCode = config.redsystest['merchantcode'],
            Ds_Merchant_MerchantData = "COBRAMENT QUOTA SOCI",
            Ds_Merchant_MerchantName = "SOM ENERGIA, SCCL",
            Ds_Merchant_MerchantURL = "https://testing.somenergia.coop:5001/pagament/notificacio",
            Ds_Merchant_Order = "20167db2f375",
            Ds_Merchant_ProductDescription = "Alta de soci SOMENERGIA",
            Ds_Merchant_SumTotal = "10000",
            Ds_Merchant_Terminal = "1",
            Ds_Merchant_Titular = "SOM ENERGIA, SCCL",
            Ds_Merchant_TransactionType = "0",
            Ds_Merchant_UrlKO = "https://www.somenergia.coop/es/pago-cancelado",
            Ds_Merchant_UrlOK = "https://www.somenergia.coop/es/pago-realizado",
            )
        import requests
        r = requests.post('https://sis-t.redsys.es:25443/sis/realizarPago',
            data = encodeSignedData(
                config.redsystest['merchantkey'],
                **data
                )
            )

        self.assertEqual(r.status_code, 200)
        self.assertNotIn('RSisException', r.text)
        self.assertFalse(re.match('SIS[0-9]', r.text))

    def test_sendingPost_testing_invalidSignature(self):

        data = dict(
            Ds_Merchant_Amount = "10000",
            Ds_Merchant_ConsumerLanguage = "003",
            Ds_Merchant_Currency = "978",
            Ds_Merchant_MerchantCode = "999008881", # testing user
            Ds_Merchant_MerchantData = "COBRAMENT QUOTA SOCI",
            Ds_Merchant_MerchantName = "SOM ENERGIA, SCCL",
            Ds_Merchant_MerchantURL = "https://testing.somenergia.coop:5001/pagament/notificacio",
            Ds_Merchant_Order = "20167db2f375",
            Ds_Merchant_ProductDescription = "Alta de soci SOMENERGIA",
            Ds_Merchant_SumTotal = "10000",
            Ds_Merchant_Terminal = "1",
            Ds_Merchant_Titular = "SOM ENERGIA, SCCL",
            Ds_Merchant_TransactionType = "0",
            Ds_Merchant_UrlKO = "https://www.somenergia.coop/es/pago-cancelado",
            Ds_Merchant_UrlOK = "https://www.somenergia.coop/es/pago-realizado",
            )
        import requests
        r = requests.post('https://sis-t.redsys.es:25443/sis/realizarPago',
            data = encodeSignedData(
                'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', # bad key
                **data
                )
            )

        self.assertEqual(r.status_code, 200)
        self.assertIn('RSisException', r.text)
        self.assertIn('<!--SIS0042:-->', r.text)

    def test_sendingPost_testingFails_invalidUser(self):

        data = dict(
            Ds_Merchant_Amount = "10000",
            Ds_Merchant_ConsumerLanguage = "003",
            Ds_Merchant_Currency = "978",
            Ds_Merchant_MerchantCode = "999999999", # bad user
            Ds_Merchant_MerchantData = "COBRAMENT QUOTA SOCI",
            Ds_Merchant_MerchantName = "SOM ENERGIA, SCCL",
            Ds_Merchant_MerchantURL = "https://testing.somenergia.coop:5001/pagament/notificacio",
            Ds_Merchant_Order = "20167db2f375",
            Ds_Merchant_ProductDescription = "Alta de soci SOMENERGIA",
            Ds_Merchant_SumTotal = "10000",
            Ds_Merchant_Terminal = "1",
            Ds_Merchant_Titular = "SOM ENERGIA, SCCL",
            Ds_Merchant_TransactionType = "0",
            Ds_Merchant_UrlKO = "https://www.somenergia.coop/es/pago-cancelado",
            Ds_Merchant_UrlOK = "https://www.somenergia.coop/es/pago-realizado",
            )
        import requests
        r = requests.post('https://sis-t.redsys.es:25443/sis/realizarPago',
            data = encodeSignedData(
                'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
                **data
                )
            )

        self.assertEqual(r.status_code, 200)
        self.assertIn('RSisException', r.text)
        self.assertIn('<!--SIS0026:-->', r.text)

    @unittest.skipIf(not config, "Requires a config.py file")
    @unittest.skipIf(config and 'redsys' not in config.__dict__,
        "redsys dictionary missing in config.py")
    def test_sendingPost_production(self):

        data = dict(
            Ds_Merchant_Amount = "10000",
            Ds_Merchant_ConsumerLanguage = "003",
            Ds_Merchant_Currency = "978",
            Ds_Merchant_MerchantCode = config.redsys['merchantcode'],
            Ds_Merchant_MerchantData = "COBRAMENT QUOTA SOCI",
            Ds_Merchant_MerchantName = "SOM ENERGIA, SCCL",
            Ds_Merchant_MerchantURL = "https://testing.somenergia.coop:5001/pagament/notificacio",
            Ds_Merchant_Order = "201671121375",
            Ds_Merchant_ProductDescription = "Alta de soci SOMENERGIA",
            Ds_Merchant_SumTotal = "10000",
            Ds_Merchant_Terminal = "1",
            Ds_Merchant_Titular = "SOM ENERGIA, SCCL",
            Ds_Merchant_TransactionType = "0",
            Ds_Merchant_UrlKO = "https://www.somenergia.coop/es/pago-cancelado",
            Ds_Merchant_UrlOK = "https://www.somenergia.coop/es/pago-realizado",
            )
        import requests
        r = requests.post('https://sis.redsys.es/sis/realizarPago',
            data = encodeSignedData(
#                'sq7HjrUOBfKmC576ILgskD5srU870gJ7', # Clave para tests
                config.redsys['merchantkey'],
                **data
                )
            )
        self.assertEqual(r.status_code, 200)
        self.assertNotIn('RSisException', r.text)
        self.assertFalse(re.match('SIS[0-9]', r.text))



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
    orderid = '666'
    signatureversion = 'HMAC_SHA256_V1'

    def test_payloadDecoding(self):
        # TODO: Should be urlsafe_b64decode, provide an input which differs
        decodedData = base64.b64decode(self.encodeddata)
        self.assertEqual(decodedData, self.data)

    def test_obtainOrder(self):
        # TODO: It could be DS_ORDER as well
        order = json.loads(self.data)['Ds_Order']
        self.assertEqual(order, self.orderid)

    def test_generateSecret(self):
        secret = orderSecret(self.merchantkey, self.orderid)
        self.assertEqual(self.secret, secret)

    def test_computeKey(self):
        signature = signPayload(self.secret, self.encodeddata, urlsafe=True)
        self.assertMultiLineEqual(self.signature, signature)


    def test_decodeSignedData_whenAllOk(self):
        data = decodeSignedData(
            self.merchantkey,
            Ds_MerchantParameters = self.encodeddata,
            Ds_Signature = self.signature,
            Ds_SignatureVersion = self.signatureversion,
            )
        self.assertEqual(data, dict(
            Ds_Order = '666',
            ))

    def test_decodeSignedData_badVersion(self):
        with self.assertRaises(SignatureError) as cm:
            decodeSignedData(
                self.merchantkey,
                Ds_MerchantParameters = self.encodeddata,
                Ds_Signature = self.signature,
                Ds_SignatureVersion = 'bad',
                )
        msg = cm.exception.args[0]
        self.assertEqual(msg, 'Unsupported signature version')

    def test_decodeSignedData_nonBase64Data(self):
        with self.assertRaises(SignatureError) as cm:
            decodeSignedData(
                self.merchantkey,
                Ds_MerchantParameters = '3ww',
                Ds_Signature = self.signature,
                Ds_SignatureVersion = self.signatureversion,
                )
        msg = cm.exception.args[0]
        self.assertEqual(msg, 'Unable to decode base 64')


    def test_decodeSignedData_badJson(self):
        json_data = "{bad json}"
        with self.assertRaises(SignatureError) as cm:
            decodeSignedData(
                self.merchantkey,
                Ds_MerchantParameters = base64.urlsafe_b64encode(json_data),
                Ds_Signature = self.signature,
                Ds_SignatureVersion = self.signatureversion,
                )
        msg = cm.exception.args[0]
        self.assertEqual(msg, 'Bad JSON format')

    def test_decodeSignedData_misingOrder(self):
        json_data = '{}'
        with self.assertRaises(SignatureError) as cm:
            decodeSignedData(
                self.merchantkey,
                Ds_MerchantParameters = base64.urlsafe_b64encode(json_data),
                Ds_Signature = self.signature,
                Ds_SignatureVersion = self.signatureversion,
                )
        msg = cm.exception.args[0]
        self.assertEqual(msg, 'Missing Ds_Order attribute')

    def test_decodeSignedData_badSignature(self):
        json_data = '{"Ds_Order":"777"}'
        with self.assertRaises(SignatureError) as cm:
            decodeSignedData(
                self.merchantkey,
                Ds_MerchantParameters = base64.urlsafe_b64encode(json_data),
                Ds_Signature = self.signature,
                Ds_SignatureVersion = self.signatureversion,
                )
        msg = cm.exception.args[0]
        self.assertEqual(msg, 'Bad signature')

    def test_decodeSignedData_badParam(self):
        json_data = '{"Ds_Order":"666", "Bad":"value"}'
        base64_data = base64.urlsafe_b64encode(json_data)
        signature = signPayload(self.secret, base64_data, urlsafe=True)
        with self.assertRaises(SignatureError) as cm:
            decodeSignedData(
                self.merchantkey,
                Ds_MerchantParameters = base64_data,
                Ds_Signature = signature,
                Ds_SignatureVersion = self.signatureversion,
                )
        msg = cm.exception.args[0]
        self.assertEqual(msg, "Bad parameter 'Bad'")

    def test_decodeSignedData_upperCaseOrder(self):
        json_data = '{"DS_ORDER":"666"}'
        base64_data = base64.urlsafe_b64encode(json_data)
        signature = signPayload(self.secret, base64_data, urlsafe=True)
        data = decodeSignedData(
            self.merchantkey,
            Ds_MerchantParameters = base64_data,
            Ds_Signature = signature,
            Ds_SignatureVersion = self.signatureversion,
            )
        self.assertEqual(data, dict(
            Ds_Order = '666',
            ))


unittest.TestCase.__str__ = unittest.TestCase.id

if __name__ == '__main__':
    import sys
    code = unittest.main()
    sys.exit(code)




