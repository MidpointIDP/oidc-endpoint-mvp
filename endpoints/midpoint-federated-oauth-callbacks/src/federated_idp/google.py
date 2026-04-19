import json
import logging
import typing
import uuid
import joserfc
import joserfc.jwk
import joserfc.jwt

_logger: logging.Logger = logging.getLogger(__name__)
_logger.setLevel(logging.DEBUG)

# 1. Get Google's Public Keys (JWKS)
_jwks = json.loads(
    """
    {
        "keys": [
            {
                "kid": "b3d95b95fa48d180b85ffe8082fcfa2174b04667",
                "e": "AQAB",
                "n": "3IUHipekMrYRlTvWbITRG64jOsCgvS0nGU85dmynPXY8o4nosgPtL_CCK3-f-EpoVGW1yFBhPUWf1xp6B6UIehsDdlko_Ey3gi_l5fDMWf-e2MOqFf6-4qCbGZdXarOws6eqQAcq_tSzLSPelqvbXnm1hKy-6iW2_6ql2lMQfb119-_ApUXizAHid7CnCa-XXDWdN3ke-uYciKeJ0d6tQn79N5h_HofB43XXk9wuu3_MOKiQaD-OfXGsWSGRG1fyvyGt8dfPJXqcMscWhg2pJIMlIoRPNopSMu8Pbl2K0SbFqG4UyhfnJz3Kgdo1depkKV5xcSfgEkSMIFXUUFN_hw",
                "kty": "RSA",
                "use": "sig",
                "alg": "RS256"
            },
            {
                "e": "AQAB",
                "kid": "647014f9a4a4cbbb6e9aa1f9e30ee6cc70da742a",
                "alg": "RS256",
                "n": "wHjOqznUAbRNkltSyRKrUL1h0ITVFcRC34f-lnSjZHxlitPx5k77gUjSOcLPhDgmIJ37K25Ix0EdH3J5z6Diypte80ezobcbXruZOZV8a5pZM7dn94i3sf0_CTGN2vemG5ZfdqBliQRYoaMBTTx6sPn7WQ3RhhUwkIe5kc_sHbW2pGfJ6A2AfHM7aGhrhAcdaHmPUq7jwbF2bwOEoX3stOMVNBA2xpf9CIdflMKt8AX9uHTYjJNRpNr8qH8i5_KnQpPHG0zCROYQ7vFuL9lW_AULVOLRw4M-iM6Ea_oUwlAYIMO2rPSahLExAj-VW6ptqMHGIOJVfWuQgKGBalomqw",
                "kty": "RSA",
                "use": "sig"
            }
        ]
    }
    """
)

_key_set: joserfc.jwk.KeySet = joserfc.jwk.KeySet.import_key_set(_jwks)

_claims_registry: joserfc.jwt.JWTClaimsRegistry = joserfc.jwt.JWTClaimsRegistry(
    iss={
        "essential": True,
        "value": "https://accounts.google.com"
    },

    aud={
        "essential": True,
        "values": ["263659947191-e0sr8qg2pmofgb15h5lc1ihu7bhni26j.apps.googleusercontent.com", ]
    },
)


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

    # Now we take the code and exchange it for ID/access tokens
    try:
        decoded_token: joserfc.jwt.Token = joserfc.jwt.decode( id_token, _key_set, algorithms=["RS256"] )
        # _logger.debug("Got past decode")

        # Deep validate -- checks nbf, exp, iss, aud, throws exception if failed
        token_claims: dict[str, typing.Any] = decoded_token.claims

        # _logger.debug("extracted claims")

        # _logger.debug("Calling validate")
        _claims_registry.validate(token_claims)
        # _logger.debug("Back from validate")

    except Exception as e:
        _logger.warning(f"Got exception while validating id_token: {e}")
        _logger.warning(f"Invalid token passed in body, rejecting login: {id_token}")
        return _create_lambda_function_response(
            401,
            {
                "error": "Provided token failed signature check",
            }
        )

    _logger.info("ID token passed both signature validation and claims validation with claims:")
    _logger.info(token_claims)

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
