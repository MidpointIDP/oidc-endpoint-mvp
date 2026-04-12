import json
import logging
import typing

import authlib      # https://docs.authlib.org/en/stable/basic/intro.html


_logger: logging.Logger = logging.Logger(__name__)
_logger.setLevel(logging.DEBUG)

_required_query_params: list[str] = [
    # Core security
    'nonce',
    'redirect_uri',
    'response_type',
    'state',

    # PKCE
    'code_challenge',
    'code_challenge_method',

    # Privacy?Session Mgmt
    'scope',
]

def _all_keys_in_dict(dict: dict[str, typing.Any], required_keys: list[str]) -> bool:
    return all(key in dict for key in required_keys)


def _create_lambda_function_response(status_code: int, jsonable_body:
                                     dict[str, typing.Any]) -> dict[str, typing.Any]:

    return {
        'statusCode'    : status_code,
        'headers'       : {
            'Content-Type'  : 'application/json',
        },
        'body'          : json.dumps(jsonable_body)
    }


def entry_point(event, _context):
    _logger.info("Invoked")

    # Make sure all required query string parameters were passed
    if 'queryStringParameters' not in event or not _all_keys_in_dict(event['queryStringParameters'],
                                                                     _required_query_params):
        return _create_lambda_function_response(
            400,
            {'error': 'Not all required OIDC parameters are present'}
        )

    return _create_lambda_function_response(200, {'event': event})
