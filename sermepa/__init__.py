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
MANDATORY_DATA = [
    'Ds_Merchant_MerchantCode', # 9/N. Obligatorio. Código FUC asignado al comercio.
    'Ds_Merchant_Terminal', # 3/N. Obligatorio. Número de terminal que le asignará su banco. Tres se considera su longitud máxima
    'Ds_Merchant_TransactionType', # 1/N Obligatorio. para el comercio para indicar qué tipo de transacción es.
    'Ds_Merchant_Amount', # 12/N. Obligatorio. Para Euros las dos últimas posiciones se consideran decimales.
    'Ds_Merchant_Currency', # 4/N. Obligatorio. Se debe enviar el código numérico de la moneda según el ISO-4217
        # Ejemplo: 978 euros, 840 dólares, 826 libras, 392 yenes... 4 se considera su longitud máxima
    'Ds_Merchant_Order', # 4/N+8/AN. Obligatorio. Numero de pedido. [0-9]{4}[a-zA-z0-9]{0,8}
    'Ds_Merchant_MerchantURL', # 250/AN Obligatorio si el comercio tiene notificación “online”.  URL del comercio que recibirá un post con los datos de la transacción.
    'Ds_Merchant_SumTotal', # 12/N. Obligatorio. La suma total de los importes de las cuotas. Las dos últimas posiciones se consideran decimales.
]

OPTIONAL_DATA = [
    'Ds_Merchant_ProductDescription', # 125/AN Opcional. Este campo se mostrará al titular en la pantalla de confirmación de la compra.
    'Ds_Merchant_Titular', # 60/A-N Opcional. Este campo se mostrará al titular en la pantalla de confirmación de la compra.  Nombre y apellidos del titular
    'Ds_Merchant_UrlOK', # 250/AN Opcional. si se envía será utilizado como URLOK ignorando el configurado en el módulo de administración en caso de tenerlo.
    'Ds_Merchant_UrlKO', # 250/AN Opcional. si se envía será utilizado como URLKO ignorando el configurado en el módulo de administración en caso de tenerlo
    'Ds_Merchant_MerchantName', # 25/A-N Opcional. será el nombre del comercio que aparecerá en el ticket del cliente.
    'Ds_Merchant_ConsumerLanguage', # 3/N. Opcional. El Valor 0, si es desconocido.
    'Ds_Merchant_MerchantData', # 1024 /AN Opcional. Datos recibidos por el comerciante en la respuesta online.
    'Ds_Merchant_DateFrecuency', # 5/N Frecuencia en días para las transacciones recurrentes y recurrentes diferidas (obligatorio para recurrentes)
    'Ds_Merchant_ChargeExpiryDate', # 10/AN Formato yyyy-MM-dd fecha límite para las transacciones Recurrentes (Obligatorio para recurrentes y recurrentes diferidas )
    'Ds_Merchant_AuthorisationCode', # 6/N Opcional. Representa el código de autorización necesario para identificar una transacción recurrente sucesiva en las devoluciones de operaciones recurrentes sucesivas. Obligatorio en devoluciones de operaciones recurrentes.
    'Ds_Merchant_TransactionDate', # 10/AN Opcional. Formato yyyy-mm-dd. Representa la fecha de la cuota sucesiva, necesaria para identificar la transacción en las devoluciones.  Obligatorio en las devoluciones de cuotas sucesivas y de cuotas sucesivas diferidas.
]
DATA = MANDATORY_DATA + OPTIONAL_DATA


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

transactionTypes = [
    ('0', 'Autorización'),
    ('1', 'Preautorización'),
    ('2', 'Confirmación de preautorización'),
    ('3', 'Devolución Automática'),
    ('5', 'Transacción Recurrente'),
    ('6', 'Transacción Sucesiva'),
    ('7', 'Pre-autenticación'),
    ('8', 'Confirmación de pre-autenticación'),
    ('9', 'Anulación de Preautorización'),
    ('O', 'Autorización en diferido'),
    ('P', 'onfirmación de autorización en diferido'),
    ('Q', 'Anulación de autorización en diferido'),
    ('R', 'Cuota inicial diferido'),
    ('S', 'Cuota sucesiva diferido'),
]


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

_notification_fields = [
    'Ds_Order',
    # TODO: More!
    ]
_notification_fields_upper = dict(
    (key.upper(), key)
    for key in _notification_fields
    )

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
        orderid = data['Ds_Order']
    except KeyError:
        try:
            orderid = data['DS_ORDER']
        except KeyError:
            error('Missing Ds_Order attribute')

    orderkey = orderSecret(merchantKey, orderid.encode('utf-8'))
    signature = signPayload(orderkey, Ds_MerchantParameters, urlsafe = True)

    if signature != Ds_Signature:
        error("Bad signature")

    for key in data :
        if key in _notification_fields_upper:
            camell = _notification_fields_upper[key]
            data[camell]=data[key]
            del data[key]
            continue

        if key not in _notification_fields:
            error("Bad parameter '{}'".format(key))

    return data

def encodeSignedData(merchantKey, **kwds):
    params_json = json.dumps(kwds, sort_keys=True)
    b64params = base64.b64encode(params_json)
    secret = orderSecret(merchantKey, kwds['Ds_Merchant_Order'])
    signature = signPayload(secret, b64params)

    for param in kwds:
        if param not in DATA:
            raise ValueError(u"The received parameter %s is not allowed."
                             % param)

    return dict(
        Ds_SignatureVersion = 'HMAC_SHA256_V1',
        Ds_Signature = signature,
        Ds_MerchantParameters = b64params,
        )
    


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

        return encodeSignedData(self.priv_key, **{
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
            })


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

