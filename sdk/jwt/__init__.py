import time

from jose import jwt

from . import utils


def encode_jwt(claims, version=1):
    """
    Create a JWT.

    :param claims: dictionary of claims to place in JWT.
    :param version: key version to use when signing JWT.
    :return: a JWT in the form of 'claims.signature'
    """
    if not isinstance(claims, dict):
        raise ValueError("Claims dictionary invalid.")

    claims['v'] = version
    claims['t'] = int(time.time())

    encode_key, alg = utils.encode_keys(version)

    jwt_string = jwt.encode(claims, encode_key, alg)
    jwt_string = jwt_string.decode('ascii')

    return jwt_string


def decode_jwt(jwt_string, version=1):
    """
    Decode a JWT.

    :param jwt_string: a JWT in the form of 'claims.signature'.
    :param version: key version to use when signing JWT.
    :return: dictionary of claims from the JWT.
    """

    if not jwt_string:
        raise ValueError("No JWT string provided.")

    decode_key, alg = utils.decode_keys(version)
    decoded = jwt.decode(jwt_string, decode_key, algorithms=alg)
    return decoded
