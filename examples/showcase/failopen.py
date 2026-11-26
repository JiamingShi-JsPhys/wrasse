def is_authorized(user, resource):
    try:
        return acl.allows(user, resource)
    except Exception:
        return True
