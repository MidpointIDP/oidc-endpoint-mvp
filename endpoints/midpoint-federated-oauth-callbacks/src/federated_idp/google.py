import json
import logging
import typing
import uuid
import authlib.jose
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

    _logger.debug(f"Got request body: {body}")
    try:
        parsed_body: dict[str, str] = json.loads(body)
    except json.decoder.JSONDecodeError:
        return _create_lambda_function_response(
            400,
            {
                "error": "Body sent to callback is not a valid JSON object",
            }
        )

    if not isinstance(parsed_body, dict) or len(parsed_body) != 1 or 'id_token' not in parsed_body:
        return _create_lambda_function_response(
            400,
            {
                "error": "JSON body needs to be a dict with exactly one key 'id_token'",
            }
        )

    id_token: str = parsed_body['id_token']

    # 1. Get Google's Public Keys (JWKS)
    jwks_url = "https://www.googleapis.com/oauth2/v3/certs"
    response = requests.get(jwks_url)
    jwks = response.json()

    # Now we take the code and exchange it for ID/access tokens
    try:
        validated_claims: dict[str, typing.Any] = jwt.decode(
            id_token,
            jwt.algorithms.RSAAlgorithm.from_jwk(key_data),
            algorithms=["RS256"],
            audience="263659947191-e0sr8qg2pmofgb15h5lc1ihu7bhni26j.apps.googleusercontent.com"
        )
    except jwt.InvalidTokenError:
        _logger.warning(f"Invalid token passed in body, rejecting login: {id_token}")
        return _create_lambda_function_response(
            401,
            {
                "error": "Provided token failed signature check",
            }
        )

    _logger.info("ID token is valid with claims:")
    _logger.info(validated_claims)

    assigned_session_id: str = str(uuid.uuid4())
    _logger.info(f"Assigned session ID: {assigned_session_id}")

    cookie_value: str = f"session_id={assigned_session_id}; HttpOnly; Secure; SameSite=None; Path=/; Max-Age=3600"

    return _create_lambda_function_response(
        200,
        {
            "login_status"                      : "SUCCESS",
        },

        # Hide the cookie from JS, all JS knows is API calls start working, can't see why
        headers={
            "Set-Cookie"                        : cookie_value,
            "Access-Control-Allow-Credentials"  : "true",
            "Access-Control-Allow-Origin"       : "https://midpoint-ui-oidc.pages.dev/sign_up"
        }
    )
