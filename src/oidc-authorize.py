import json
import logging

_logger: logging.Logger = logging.Logger(__name__)
_logger.setLevel(logging.DEBUG)


def oidc_authorize_endpoint(event, _context):
    _logger.info("Invoked")
    _logger.debug(json.dumps(event, indent=4, sort_keys=True))

    return {
        'statusCode'    : 200,
        'headers' : {
            'Content-Type' : 'application/json',
        },
        'body'          : json.dumps({'event': json.dumps(event)})
    }


if __name__ == "__main__":
    print("Hello World")
