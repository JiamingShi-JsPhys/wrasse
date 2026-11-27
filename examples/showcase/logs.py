import logging
log = logging.getLogger(__name__)

def warn(token):
    log.warning("auth failed for %s", token)
