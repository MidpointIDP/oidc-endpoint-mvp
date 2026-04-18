import base64
import json
import logging
import typing
import urllib.parse
import jwt
import jwt.algorithms
import requests

_logger: logging.Logger = logging.getLogger(__name__)
_logger.setLevel(logging.DEBUG)


def _create_lambda_function_response(status_code: int,
                                     jsonable_body: dict[str, typing.Any] | None,
                                     headers: dict[str, typing.Any] = None) -> dict[str, typing.Any]:

    return_headers: dict[str, typing.Any] = {}

    # Include any passed headers
    if headers:
        return_headers.update(headers)

    # Ensure we have our required headers even if they got passed
    return_headers.update(
        {
            'Content-Type'  : 'application/json',
        }
    )

    return_struct = {
        'statusCode'    : status_code,
        'headers'       : return_headers,
    }

    if jsonable_body:
        return_struct['body'] = json.dumps(jsonable_body)

    return return_struct


def oauth_callback_entry_point(event, _context):
    _logger.info("Invoked")

    body: str = event['body']

    _logger.info(f"Got request body: {body}")

    # Let's b64 decode as they say
    decode_body: str = base64.b64decode(body).decode('utf-8')
    _logger.info(f"Base64 decoded body: {decode_body}")

    # parse_qs returns lists of strings because headers can be duplicated, but we ignore that and
    #   take the first assuming no dupes
    parsed_dict_from_body: dict[str, str] = {k: v[0] for k, v in urllib.parse.parse_qs(decode_body).items()}

    # return _create_lambda_function_response(
    #     200,
    #     parsed_dict_from_body,
    # )

    id_token: str = parsed_dict_from_body['credential']

    # 1. Get Google's Public Keys (JWKS)
    jwks_url = "https://www.googleapis.com/oauth2/v3/certs"
    response = requests.get(jwks_url)
    jwks = response.json()

    # 2. Extract Key ID (kid) from token header
    unverified_header = jwt.get_unverified_header(id_token)
    kid = unverified_header['kid']

    # 3. Find the matching key
    key_data = next(k for k in jwks['keys'] if k['kid'] == kid)
    # So we can check state against original request -- but won't

    # Now we take the code and exchange it for ID/access tokens

    # Fake that out and return signed JWT ID and access tokens
    return _create_lambda_function_response(
        200,
        {
            "decoded_token": jwt.decode(
                id_token,
                jwt.algorithms.RSAAlgorithm.from_jwk(key_data),
                algorithms=["RS256"],
                audience="263659947191-e0sr8qg2pmofgb15h5lc1ihu7bhni26j.apps.googleusercontent.com"
            )
        },
    )
