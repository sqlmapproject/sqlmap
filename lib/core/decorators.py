# Reference: http://code.activestate.com/recipes/325205-cache-decorator-in-python-24/
def cachedmethod(f, cache={}):
    def _(*args, **kwargs):
        key = (f, tuple(args), frozenset(kwargs.items()))
        if key not in cache:
            cache[key] = f(*args, **kwargs)
        return cache[key]
    return _
