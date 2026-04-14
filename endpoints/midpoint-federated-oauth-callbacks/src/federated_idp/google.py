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

    token="eyJhbGciOiJSUzI1NiIsImtpZCI6ImIzZDk1Yjk1ZmE0OGQxODBiODVmZmU4MDgyZmNmYTIxNzRiMDQ2NjciLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJhenAiOiIyNjM2NTk5NDcxOTEtZTBzcjhxZzJwbW9mZ2IxNWg1bGMxaWh1N2JobmkyNmouYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJhdWQiOiIyNjM2NTk5NDcxOTEtZTBzcjhxZzJwbW9mZ2IxNWg1bGMxaWh1N2JobmkyNmouYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJzdWIiOiIxMDE1MzU0NTA4Njk1NjMzMjAxNjEiLCJoZCI6InNpeGJ1Y2tzc29sdXRpb25zLmNvbSIsImVtYWlsIjoidGVycnkub3R0QHNpeGJ1Y2tzc29sdXRpb25zLmNvbSIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJuYmYiOjE3NzYxNjg5NDgsIm5hbWUiOiJUZXJyeSBPdHQiLCJwaWN0dXJlIjoiaHR0cHM6Ly9saDMuZ29vZ2xldXNlcmNvbnRlbnQuY29tL2EvQUNnOG9jSnN1amFnYUxHODB3UE9XaUFObl9BOFhwSktrbXpLT1MzY0x2SHVvaFF6dHFjeHhocz1zOTYtYyIsImdpdmVuX25hbWUiOiJUZXJyeSIsImZhbWlseV9uYW1lIjoiT3R0IiwiaWF0IjoxNzc2MTY5MjQ4LCJleHAiOjE3NzYxNzI4NDgsImp0aSI6ImRkYTljNmIwNzJmM2RmMzVhMjliMDhmMGRmMDg3YTRmNzc3ZDE0NzIifQ.GcPdDYyiTQ4xJ_wdNRg2hZGIiLJZZ_nzskFNg3Bapow8lipMuXaXgX44CFeDs7CH71YfYWON1jOY5Ab1V0DkUH_7ScdYaC2Q_opOQEf5sBQPvqWUZvNqE-_Qeck9WOr7QXBAJS7R70UaIRqS3eGNAoKbw61CcIVdfgALbdtyeX2pNkHYecWMwak2bFsUXB1l-DHo0hjPcKJaTNZcvgGGsuaXt8KSC-A_5j8el9-Kw0mNXtZq5c7H7gDNK9qKv16KXG2dDFcYeQHDWPeaPkmyycX_lsaQgDcEaGEXcm97jcJR--QfJG2NSVmAjfGJAxOPNjPDcVdOXlHe3jOM5KpQFw"

    # 1. Get Google's Public Keys (JWKS)
    jwks_url = "https://www.googleapis.com/oauth2/v3/certs"
    response = requests.get(jwks_url)
    jwks = response.json()

    # 2. Extract Key ID (kid) from token header
    unverified_header = jwt.get_unverified_header(token)
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
                token,
                jwt.algorithms.RSAAlgorithm.from_jwk(key_data),
                algorithms=["RS256"],
                audience="263659947191-e0sr8qg2pmofgb15h5lc1ihu7bhni26j.apps.googleusercontent.com"
            )
        },
    )
