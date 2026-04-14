import json
import logging
import typing
import uuid

import authlib      # https://docs.authlib.org/en/stable/basic/intro.html
import urllib.parse

_logger: logging.Logger = logging.getLogger(__name__)
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

    # Privacy, Session Mgmt
    'scope',
]

def _all_keys_in_dict(dict: dict[str, typing.Any], required_keys: list[str]) -> bool:
    return all(key in dict for key in required_keys)


def _create_lambda_function_response(status_code: int,
                                     jsonable_body: dict[str, typing.Any] | None,
                                     headers: dict[str, typing.Any] = None) -> dict[str, typing.Any | None]:

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
    else:
        return_struct['body'] = None

    return return_struct


def entry_point(event, _context):
    _logger.info("Invoked")

    # Make sure all required query string parameters were passed
    if 'queryStringParameters' not in event or not _all_keys_in_dict(event['queryStringParameters'],
                                                                     _required_query_params):
        return _create_lambda_function_response(
            400,
            {'error': 'Not all required OIDC parameters are present'}
        )

    _logger.info("All required parameters existed")

    # Create a SRP session ID and store all the client oauth params under it in the DB
    srp_session_id: str = str(uuid.uuid4())

    json_body = {
        'srp_start_url': f"https://mlwzxk0fi1.execute-api.us-east-2.amazonaws.com/srp_handshake/{srp_session_id}",
    }

    lambda_response = _create_lambda_function_response(
        200,
        json_body,
    )

    return lambda_response


    # TODO: Store login start state in Dynamo so we can associate it after SRP

    # # Generate a code and bounce them to callback URL with it
    # code: str = str(uuid.uuid4())
    #
    # # Store the code in the DB as we'll be seeing it when they hit the token endpoint
    #
    # redirect_url_params: dict[str, str] = {
    #     "code"      : code,
    #     "state"     : event['queryStringParameters']['state'],
    # }
    #
    #
    # lambda_response = _create_lambda_function_response(
    #     302,
    #     None,
    #     headers={'Location': redirect_url},
    # )
    #
    # _logger.debug(json.dumps(lambda_response))
    #
    # return lambda_response