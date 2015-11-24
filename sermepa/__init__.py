# -*- coding: utf-8 -*-

"""
    Sermepa client classes
    ~~~~~~~~~~~~~~~~~~~~~~

    Basic client for the Sermepa credit card paying services.

"""

import hashlib
import base64
import hmac
import json
import pyDes

DATA = [
    'Ds_Merchant_Amount',
    'Ds_Merchant_Currency',
    'Ds_Merchant_Order',
    'Ds_Merchant_ProductDescription',
    'Ds_Merchant_Titular',
    'Ds_Merchant_MerchantCode',
    'Ds_Merchant_MerchantURL',
    'Ds_Merchant_UrlOK',
    'Ds_Merchant_UrlKO',
    'Ds_Merchant_MerchantName',
    'Ds_Merchant_ConsumerLanguage',
    'Ds_Merchant_Terminal',
    'Ds_Merchant_SumTotal',
    'Ds_Merchant_TransactionType',
    'Ds_Merchant_MerchantData',
    'Ds_Merchant_DateFrecuency',
    'Ds_Merchant_ChargeExpiryDate',
    'Ds_Merchant_AuthorisationCode',
    'Ds_Merchant_TransactionDate',
]

LANG_MAP = {
  '001': 'es_ES',
  '002': 'en_US',
  '003': 'ca_ES',
  '004': 'fr_FR',
  '005': 'de_DE',
  '006': 'nl_NL',
  '007': 'it_IT',
  '008': 'sv_SE',
  '009': 'pt_PT',
  '010': 'ca_ES', # valencia
  '011': 'pl_PL',
  '012': 'gl_ES',
  '013': 'eu_ES',
  '208': 'da_DK',
}


def orderSecret(key, order):
    """
    Given the order identifier and the merchant key,
    provide a secret key to sign the order.
    Expects the merchant key in base64 format.
    Returns the secret key in base64 format.
    """

    decodedkey = base64.b64decode(key)
    k = pyDes.triple_des(
        decodedkey,
        pyDes.CBC,
        b"\0\0\0\0\0\0\0\0",
        pad='\0',
        )
    secret = k.encrypt(order)
    return base64.b64encode(secret)

def signPayload(secret, data, urlsafe=False):
    """
    Given the order specific secret key,
    and the data to sign, obtains a signature.
    Expects the order key in base64 format.
    Returns the signature in base64 format,
    urlsafe if specified (for notification).
    """

    result = hmac.new(
        base64.b64decode(secret),
        data,
        digestmod = hashlib.sha256
        ).digest()
    encoder = base64.urlsafe_b64encode if urlsafe else base64.b64encode
    return encoder(result)

class SignatureError(Exception): pass

def decodeSignedData(
        merchantKey,
        Ds_MerchantParameters,
        Ds_Signature,
        Ds_SignatureVersion,
        ):

    def error(message):
        raise SignatureError(message)

    if Ds_SignatureVersion != 'HMAC_SHA256_V1':
        error('Unsupported signature version')

    try:
        json_data = base64.urlsafe_b64decode(Ds_MerchantParameters)
    except:
        error('Unable to decode base 64')

    try:
        data = json.loads(json_data)
    except ValueError:
        error('Bad JSON format')

    try:
        # TODO: It could be 'DS_ORDER' as well
        orderid = data['Ds_Order']
    except KeyError:
        error('Missing Ds_Order attribute')

    orderkey = orderSecret(merchantKey, orderid.encode('utf-8'))
    signature = signPayload(orderkey, Ds_MerchantParameters, urlsafe = True)

    if signature != Ds_Signature:
        error("Bad signature")

    return data

 
    


class Client(object):
    """Client"""

    def __init__(self, business_code, priv_key,
                 endpoint_url='https://sis.redsys.es/sis/realizarPago'):
        # init params
        for param in DATA:
            setattr(self, param, None)
        self.endpoint = endpoint_url
        self.priv_key = priv_key
        self.Ds_Merchant_MerchantCode = business_code

    def get_pay_form_data(self, transaction_params):
        """Pay call"""
        for param in transaction_params:
            if param not in DATA:
                raise ValueError(u"The received parameter %s is not allowed."
                                 % param)
            setattr(self, param, transaction_params[param])

        subdata = {
            'Ds_Merchant_Amount': int(self.Ds_Merchant_Amount * 100),
            'Ds_Merchant_Currency': self.Ds_Merchant_Currency or 978, # EUR
            'Ds_Merchant_Order': self.Ds_Merchant_Order[:12],
            'Ds_Merchant_ProductDescription':
                self.Ds_Merchant_ProductDescription[:125],
            'Ds_Merchant_Titular': self.Ds_Merchant_Titular[:60],
            'Ds_Merchant_MerchantCode': self.Ds_Merchant_MerchantCode[:9],
            'Ds_Merchant_MerchantURL': self.Ds_Merchant_MerchantURL[:250],
            'Ds_Merchant_UrlOK': self.Ds_Merchant_UrlOK[:250],
            'Ds_Merchant_UrlKO': self.Ds_Merchant_UrlKO[:250],
            'Ds_Merchant_MerchantName': self.Ds_Merchant_MerchantName[:25],
            'Ds_Merchant_ConsumerLanguage': self.Ds_Merchant_ConsumerLanguage,
            'Ds_Merchant_Terminal': self.Ds_Merchant_Terminal or '1',
            'Ds_Merchant_SumTotal': int(self.Ds_Merchant_SumTotal * 100),
            'Ds_Merchant_TransactionType': self.Ds_Merchant_TransactionType \
                or '0',
            'Ds_Merchant_MerchantData': self.Ds_Merchant_MerchantData[:1024],
            'Ds_Merchant_DateFrecuency': self.Ds_Merchant_DateFrecuency,
            'Ds_Merchant_ChargeExpiryDate':
                (self.Ds_Merchant_ChargeExpiryDate and
                 self.Ds_Merchant_ChargeExpiryDate[:10] or None),
            'Ds_Merchant_AuthorisationCode': self.Ds_Merchant_AuthorisationCode,
            'Ds_Merchant_TransactionDate': self.Ds_Merchant_TransactionDate,
        }

        params_json = json.dumps(subdata)
        b64params = base64.b64encode(params_json)
        secret = orderSecret(self.priv_key, subdata['Ds_Merchant_Order'])
        self.Ds_Signature = signPayload(secret, b64params)

        data = {
            'Ds_SignatureVersion': 'HMAC_SHA256_V1',
            'Ds_Signature': self.Ds_Signature,
            'Ds_MerchantParameters':  b64params,
        }
        return data


class TestClient(Client):
    """Test Client

    N. Tarja: 4548812049400004
    Caduca: 12/12
    CCV: 123
    CIP: 123456
    """

    def __init__(self, business_code, priv_key):
        super(TestClient, self).__init__(business_code, priv_key,
              'https://sis-t.redsys.es:25443/sis/realizarPago')

