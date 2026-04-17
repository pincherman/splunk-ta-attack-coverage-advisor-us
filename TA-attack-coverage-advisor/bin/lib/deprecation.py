def deprecated(*args, **kwargs):
    def _decorate(obj):
        return obj
    return _decorate
