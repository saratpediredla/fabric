#!/usr/bin/env python
# encoding: utf-8
"""
core_plugin_decs.py

Created by Christian Vest Hansen on 2008-11-30.
Copyright (c) 2008 Unwire. All rights reserved.
"""

from util import *

def _new_call_chain_decorator(operation, *op_args, **op_kwargs):
    if getattr(operation, 'connects', False):
        e = "Operation %s requires a connection and cannot be chained."
        raise TypeError(e % operation)
    def decorator(command):
        chain = command._call_chain = getattr(
                command, '_call_chain', deque())
        chain.appendleft(lambda: operation(*op_args, **op_kwargs))
        return command
    return decorator

def plugin_main(fab):
    @fab.decorator
    def hosts(*hosts):
        "Tags function object with desired fab_hosts to run on."
        def decorator(fn):
            fn.hosts = hosts
            return fn
        return decorator

    @fab.decorator
    def roles(*roles):
        "Tags function object with desired fab_hosts to run on."
        def decorator(fn):
            fn.roles = roles
            return fn
        return decorator

    @fab.decorator
    def mode(mode):
        "Tags function object with desired fab_mode to run in."
        def decorator(fn):
            fn.mode = mode
            return fn
        return decorator

    @fab.decorator
    def requires(*args, **kwargs):
        """
        Calls `require` with the supplied arguments prior to executing the
        decorated command.
        """
        require = fab.operations['require']
        return _new_call_chain_decorator(require, *args, **kwargs)

    @fab.decorator
    def depends(*args, **kwargs):
        """
        Calls `invoke` with the supplied arguments prior to executing the
        decorated command.
        """
        invoke = fab.operations['invoke']
        return _new_call_chain_decorator(invoke, *args, **kwargs)
