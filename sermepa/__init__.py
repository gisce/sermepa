# -*- coding: utf-8 -*-

"""
    Sermepa client classes
    ~~~~~~~~~~~~~~~~~~~~~~

    Basic client for the Sermepa credit card paying services.

"""

import hashlib

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
    'Ds_Merchant_MerchantSignature',
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


class Client(object):
    """Client"""

    def __init__(self, business_code, priv_key,
                 endpoint_url='https://sis.sermepa.es/sis/realizarPago'):
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
        signature = (str(int(self.Ds_Merchant_Amount * 100)) +
                     str(self.Ds_Merchant_Order) +
                     str(self.Ds_Merchant_MerchantCode) +
                     str(self.Ds_Merchant_Currency or '978') +
                     str(self.Ds_Merchant_TransactionType) +
                     str(self.Ds_Merchant_MerchantURL) +
                     str(self.priv_key))

        self.Ds_Merchant_MerchantSignature = \
            hashlib.sha1(signature).hexdigest().upper()
        data = {
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
            'Ds_Merchant_MerchantSignature': self.Ds_Merchant_MerchantSignature,
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
              'https://sis-t.sermepa.es:25443/sis/realizarPago')

