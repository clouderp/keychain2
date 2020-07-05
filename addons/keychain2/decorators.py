# -*- coding: utf-8 -*-

from functools import wraps


def delegated(fun):

    @wraps(fun)
    def wrapper(self, *args, **kwargs):
        return getattr(
            self,
            ('%s%s'
             % (self.namespace,
                fun.__name__)))(*args, **kwargs)
    return wrapper
