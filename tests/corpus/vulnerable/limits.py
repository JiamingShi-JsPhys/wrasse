from flask_limiter import Limiter

limiter = Limiter(key_func=lambda: request.remote_addr)
