from sdk import sdk_settings


PRIVATE_KEY_HEADER = '-----BEGIN EC PRIVATE KEY-----' 
PRIVATE_KEY_FOOTER = '-----END EC PRIVATE KEY-----'
PUBLIC_KEY_HEADER = '-----BEGIN PUBLIC KEY-----'
PUBLIC_KEY_FOOTER = '-----END PUBLIC KEY-----'


def encode_keys(version):
    """
    Helper function to concatinate and return the proper encode key.

    :returns: Tuple of encode key and algorithm for the requested version.
    """
    if not sdk_settings.API_V1_ECDSA_PRIVATE:
        raise ValueError

    api_v1_ecdsa_private = PRIVATE_KEY_HEADER + \
    '\n' + sdk_settings.API_V1_ECDSA_PRIVATE + \
    '\n' + PRIVATE_KEY_FOOTER

    encode = {
        1: (api_v1_ecdsa_private, "ES256"),
    }
    return encode.get(version, (None, None))


def decode_keys(version):
    """
    Helper function to concatinate and return the proper decode key.

    :returns: Tuple of the decode key and algorithm for the requested version.
    """
    if not sdk_settings.API_V1_ECDSA_PUBLIC:
        raise ValueError

    api_v1_ecdsa_public = PUBLIC_KEY_HEADER + \
    '\n' + sdk_settings.API_V1_ECDSA_PUBLIC + \
    '\n' + PUBLIC_KEY_FOOTER

    decode = {
        1: (api_v1_ecdsa_public, "ES256"),
    }
    return decode.get(version, (None, None))
