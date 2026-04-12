import json
import logging

_logger: logging.Logger = logging.Logger(__name__)
_logger.setLevel(logging.DEBUG)


def entry_point(event, _context):
    _logger.info("Invoked")

    return {
        'statusCode'    : 200,
        'headers'       : {
            'Content-Type'  : 'application/json',
        },
        'body'          : json.dumps({'event': event})
    }
