import json
import logging
import typing


_logger: logging.Logger = logging.getLogger(__name__)
_logger.setLevel(logging.DEBUG)

_required_query_params: list[str] = [
    'state',
    'code',
]


def _all_keys_in_dict(dict: dict[str, typing.Any], required_keys: list[str]) -> bool:
    return all(key in dict for key in required_keys)


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


def entry_point(event, _context):
    _logger.info("Invoked")

    # Make sure all required query string parameters were passed
    if 'queryStringParameters' not in event or not _all_keys_in_dict(event['queryStringParameters'],
                                                                     _required_query_params):
        return _create_lambda_function_response(
            400,
            {'error': 'Not all required OIDC parameters to callback are present'}
        )


    # So we can check state against original request -- but won't

    # Now we take the code and exchange it for ID/access tokens

    # Fake that out and return signed JWT ID and access tokens

