import logging

logger = logging.getLogger(__name__)


def handler(request):
    user = request.query_params.get('user', '').replace('\n', '').replace('\r', '')
    logger.info('login attempt: %s', user)
    return {'ok': True}
