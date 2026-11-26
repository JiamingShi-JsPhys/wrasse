import logging
log = logging.getLogger(__name__)

def warn(user_id, before, after):
    log.warning("compaction for %s: %d -> %d tokens", user_id, before, after)
