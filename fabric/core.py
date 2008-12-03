#!/usr/bin/env python -i

# Fabric - Pythonic remote deployment tool.
# Copyright (C) 2008  Christian Vest Hansen
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

import datetime
import os.path
import re
import readline
import signal
import subprocess
import sys
import time
import types
from collections import deque
from functools import wraps

import core_plugin_decs
import core_plugin_ops
import core_plugin_cmds
from interop import get_username, partition, get_home_directory
from util import *
from netio import HostConnection

DEFAULT_ENV = {
    'fab_version': version,
    'fab_author': author,
    'fab_mode': 'broad',
    'fab_submode': 'serial',
    'fab_port': 22,
    'fab_user': get_username(),
    'fab_password': None,
    'fab_sudo_prompt': 'sudo password:',
    'fab_pkey': None,
    'fab_key_filename': None,
    'fab_new_host_key': 'accept',
    'fab_shell': '/bin/bash -l -c',
    'fab_timestamp': datetime.datetime.utcnow().strftime('%F_%H-%M-%S'),
    'fab_print_real_sudo': False,
    'fab_fail': 'abort',
    'fab_quiet': False,
}

class Configuration(dict):
    """
    A variable dictionary extended to be updated by being called with keyword
    arguments. It also provides item access via dynamic attribute lookup.
    """
    def __getattr__(self, key):
        return self[key]
    def __setattr__(self, key, value):
        self[key] = value
    def __setitem__(self, key, value):
        if isinstance(value, types.StringTypes):
            value = (value % self)
        dict.__setitem__(self, key, value)
    def __call__(self, **kwargs):
        for k, v in kwargs.items():
            self.__setitem__(k, v)
    def getAny(self, *names):
        for name in names:
            value = self.get(name)
            if value:
                return value

def RegistryDecorator(registry, on_obj=None):
    def registering_decorator(first_arg=None):
        if callable(first_arg):
            name = first_arg.__name__
            registry[name] = first_arg
            if on_obj and not hasattr(on_obj, name):
                setattr(on_obj, name, first_arg)
            return first_arg
        else:
            def sub_decorator(f):
                registry[first_arg] = f
                if on_obj and not hasattr(on_obj, first_arg):
                    setattr(on_obj, first_arg, f)
                return f
            return sub_decorator
    return registering_decorator

class Fabric(object):
    def __init__(self):
        self.env = Configuration(**DEFAULT_ENV)
        self.connections = []
        self.commands = {}
        self.operations = {}
        self.decorators = {}
        self.loaded_fabfiles = set()
        self.executed_commands = set()
        self.command = RegistryDecorator(self.commands)
        self.operation = RegistryDecorator(self.operations)
        self.decorator = RegistryDecorator(self.decorators, self)
    def to_namespace(self):
        namespace = dict(config=self.env)
        for ns in (self.commands, self.operations, self.decorators):
            namespace.update(ns)
        return namespace
    def connects(self, op_fn):
        @wraps(op_fn)
        def wrapper(*args, **kwargs):
            # If broad, run per host.
            if self.env['fab_local_mode'] == 'broad':
                # If serial, run on each host in order
                if self.env['fab_submode'] == 'serial':
                    return _run_serially(self, op_fn, *args, **kwargs)
                # If parallel, create per-host threads
                elif self.env['fab_submode'] == 'parallel':
                    return _run_parallel(self, op_fn, *args, **kwargs)
            # If deep, no need to multiplex here, just run for the current host
            # (set farther up the stack)
            elif self.env['fab_local_mode'] == 'deep':
                # host_conn is stored in global ENV only if we're in deep mode.
                host_conn = self.env['fab_host_conn']
                env = host_conn.get_env()
                env['fab_current_operation'] = op_fn.__name__
                host = env['fab_host']
                client = host_conn.client
                return _try_run_operation(
                    op_fn, host, client, env, *args, **kwargs)
        # Mark this operation as requiring a connection
        wrapper.connects = True
        return wrapper
    def load_default_settings(self):
        "Load user-default fabric settings from ~/.fabric"
        cfg = get_home_directory() + "/.fabric"
        if os.path.exists(cfg):
            comments = lambda s: s and not s.startswith("#")
            settings = filter(comments, open(cfg, 'r'))
            settings = [(k.strip(), v.strip()) for k, _, v in
                [partition(s, '=') for s in settings]]
            self.env.update(settings)
    def load_fabfile(self, filename, **kwargs):
        if not os.path.exists(filename):
            fail(kwargs, "Load failed:\n" + indent(
                "File not found: " + filename), self.env)
            return
        if filename in self.loaded_fabfiles:
            return
        self.loaded_fabfiles.add(filename)
        captured = {}
        execfile(filename, self.to_namespace(), captured)
        for name, obj in captured.items():
            if not name.startswith('_') and isinstance(obj, types.FunctionType):
                self.commands[name] = obj
            if not name.startswith('_'):
                __builtins__[name] = obj
    def validate_commands(self, cmds):
        if not cmds:
            print("No commands given.")
            if 'list' in self.commands:
                self.commands['list']()
        else:
            for cmd in cmds:
                if not cmd[0] in self.commands:
                    print("No such command: %s" % cmd[0])
                    sys.exit(1)
    def disconnect(self):
        map(HostConnection.disconnect, self.connections)
        self.connections = []
    def connect(self):
        """Populate Fabric.connections with HostConnection instances as per
        current fab_local_hosts."""
        signal.signal(signal.SIGINT, lambda: self.disconnect() and sys.exit(0))
        def_port = self.env['fab_port']
        username = self.env['fab_user']
        fab_hosts = self.env['fab_local_hosts']
        user_envs = {}
        host_connections_by_user = {}
        # grok fab_hosts into who connects to where
        for host in fab_hosts:
            if '@' in host:
                user, _, host_and_port = partition(host, '@')
            else:
                user, host_and_port = None, host
            hostname, _, port = partition(host_and_port, ':')
            user = user or username
            port = int(port or def_port)
            if user is not '' and user not in user_envs:
                user_envs[user] = {'fab_user': user}
            conn = HostConnection(hostname, port, user_envs[user], self.env)
            if user not in host_connections_by_user:
                host_connections_by_user[user] = [conn]
            else:
                host_connections_by_user[user].append(conn)
        # Print and establish connections
        for user, host_connections in host_connections_by_user.iteritems():
            user_env = dict(self.env)
            user_env.update(user_envs[user])
            print(lazy_format(
                "Logging into the following hosts as $(fab_user):", user_env))
            for conn in host_connections:
                print(indent(str(conn)))
            for conn in host_connections:
                conn.connect()
            self.connections += host_connections
    def execute_commands(self, cmds):
        for cmd, args, kwargs in cmds:
            self.execute_command(cmd, args, kwargs)
    def execute_command(self, cmd, args, kwargs, skip_executed=False):
        # Setup
        command = self.commands[cmd]
        if args is not None:
            args = map(lambda a: lazy_format(a, self.env), args)
        if kwargs is not None:
            kwargs = dict(zip(kwargs.keys(), map(
                lambda v: lazy_format(v, self.env), kwargs.values())))
        # Don't run remembered invokations again if skip_executed.
        if skip_executed and self.has_executed(command, args, kwargs):
            args_msg = (args or kwargs) and (" with %r, %r" % (args, kwargs)) or ""
            print("Skipping %s (already invoked%s)." % (cmd, args_msg))
            return
        self.remember_executed(command, args, kwargs)
        # Invoke eventual chained calls prior to the command.
        if self.env.get('fab_cur_command'):
            print("Chaining %s..." % cmd)
        else:
            print("Running %s..." % cmd)
        self.env['fab_cur_command'] = cmd
        call_chain = getattr(command, '_call_chain', None)
        if call_chain:
            for chained in call_chain:
                chained()
            if self.env['fab_cur_command'] != cmd:
                print("Back in %s..." % cmd)
                self.env['fab_cur_command'] = cmd
        # Determine target host and execute command.
        self.execute_at_target(command, args, kwargs)
        # Done
        self.env['fab_cur_command'] = None
    def has_executed(self, command, args, kwargs):
        return (command, args_hash(args, kwargs)) in self.executed_commands
    def remember_executed(self, command, args, kwargs):
        try:
            self.executed_commands.add((command, args_hash(args, kwargs)))
        except TypeError:
            print "Warning: could not remember execution (unhashable arguments)."
    def execute_at_target(self, command, args, kwargs):
        mode = self.env['fab_local_mode'] = getattr(command, 'mode',
            self.env['fab_mode'])
        hosts = self.env['fab_local_hosts'] = set(getattr(
            command, 'hosts', self.env.get('fab_hosts') or []))
        roles = getattr(command, 'roles', [])
        for role in roles:
            role = lazy_format(role, self.env)
            role_hosts = self.env.get(role)
            map(hosts.add, role_hosts)
        if mode in ('rolling', 'fanout'):
            print("Warning: The 'rolling' and 'fanout' fab_modes are " +
                  "deprecated.\n   Use 'broad' and 'deep' instead.")
            mode = self.env['fab_local_mode'] = 'broad'
        # Fix args vs. kwargs in certain functions
        args, kwargs = _retrofit_args(args, kwargs, command)
        # Run command once, with each operation running once per host.
        if mode == 'broad':
            command(*args, **kwargs)
        # Run entire command once per host.
        elif mode == 'deep':
            # Determine whether we need to connect for this command, do so if so
            if _needs_connect(command):
                _check_fab_hosts()
                self.connect()
            # Gracefully handle local-only commands
            if self.connections:
                for host_conn in self.connections:
                    self.env['fab_host_conn'] = host_conn
                    self.env['fab_host'] = host_conn.host_local_env['fab_host']
                    command(*args, **kwargs)
            else:
                command(*args, **kwargs)
        else:
            fail({'fail':'abort'}, "Unknown fab_mode: '$(fab_mode)'", self.env)
        # Disconnect (to clear things up for next command)
        # TODO: be intelligent, persist connections for hosts
        # that will be used again this session.
        self.disconnect()
    def check_hosts(self):
        "Check that we have a fab_hosts variable, and prompt if it's missing."
        if not self.env.get('fab_local_hosts'):
            prompt('fab_input_hosts',
                'Please specify host or hosts to connect to (comma-separated)')
            hosts = self.env['fab_input_hosts']
            hosts = [x.strip() for x in hosts.split(',')]
            self.env['fab_local_hosts'] = hosts

def _retrofit_args(args, kwargs, command):
    not_enough_positionals = len(args) > command.func_code.co_argcount
    variadic = (command.func_code.co_flags & 4) == 4
    has_kwargs = (command.func_code.co_flags & 8) == 8
    if not variadic and not_enough_positionals:
        if has_kwargs:
            nkwargs = dict()
            nkwargs.update(kwargs)
            nkwargs.update([(x, x) for x in args])
            return ([], nkwargs)
        else:
            msg = "Cannot apply %s to arguments (%s, %s)" % (
                command.func_name, args, kwargs)
            fail({}, msg, {'fab_fail':'abort'})
    else:
        return (args, kwargs) # A.O.K.
        
    

#
# Per-operation execution strategies for "broad" mode.
#
def _run_parallel(fab, fn, *args, **kwargs):
    """
    A strategy that executes on all hosts in parallel.
    
    THIS STRATEGY IS CURRENTLY BROKEN!
    
    """
    err_msg = "The $(fab_current_operation) operation failed on $(fab_host)"
    threads = []
    if not fab.connections:
        fab.check_hosts()
        fab.connect()
    for host_conn in fab.connections:
        env = host_conn.get_env()
        env['fab_current_operation'] = fn.__name__
        host = env['fab_host']
        client = host_conn.client
        def functor():
            _try_run_operation(fn, host, client, env, *args, **kwargs)
        thread = threading.Thread(None, functor)
        thread.setDaemon(True)
        threads.append(thread)
    map(threading.Thread.start, threads)
    map(threading.Thread.join, threads)

def _run_serially(fab, fn, *args, **kwargs):
    """One-at-a-time fail-fast strategy."""
    err_msg = "The $(fab_current_operation) operation failed on $(fab_host)"
    # Capture the first output in case someone really wants captured output
    # while running in broad mode.
    result = None
    if not fab.connections:
        fab.check_hosts()
        fab.connect()
    for host_conn in fab.connections:
        env = host_conn.get_env()
        env['fab_current_operation'] = fn.__name__
        host = env['fab_host']
        client = host_conn.client
        res = _try_run_operation(fn, host, client, env, *args, **kwargs)
        if not result:
            result = res
    return result

def _try_run_operation(fn, host, client, env, *args, **kwargs):
    """
    Used to attempt the execution of an operation, and handle any failures 
    appropriately.
    """
    err_msg = "The $(fab_current_operation) operation failed on $(fab_host)"
    result = False
    try:
        result = fn(host, client, env, *args, **kwargs)
    except SystemExit:
        raise
    except BaseException, e:
        fail(kwargs, err_msg + ':\n' + indent(str(e)), env)
    # Check for split output + return code (tuple)
    if isinstance(result, tuple):
        output, success = result
    # If not a tuple, assume just a pass/fail boolean.
    else:
        output = ""
        success = result
    if not success:
        fail(kwargs, err_msg + '.', env)
    # Return any captured output (will execute if fail != abort)
    return output

def _pick_fabfile():
    "Figure out what the fabfile is called."
    guesses = ['fabfile', 'Fabfile', 'fabfile.py', 'Fabfile.py']
    options = filter(os.path.exists, guesses)
    if options:
        return options[0]
    else:
        return guesses[0] # load() will barf for us...

def parse_args(args, env={}):
    cmds = []
    for cmd in args:
        cmd_args = []
        cmd_kwargs = {}
        if ':' in cmd:
            cmd, cmd_str_args = cmd.split(':', 1)
            for cmd_arg_kv in cmd_str_args.split(','):
                k, _, v = partition(cmd_arg_kv, '=')
                if v:
                    cmd_kwargs[k] = (v % env) or k
                else:
                    cmd_args.append(k)
        cmds.append((cmd, cmd_args, cmd_kwargs))
    return cmds

def _needs_connect(command):
    for operation in command.func_code.co_names:
        if getattr(OPERATIONS.get(operation), 'connects', False):
            return True

def main():
    args = sys.argv[1:]
    fab = Fabric()
    try:
        try:
            print("Fabric v. %s." % version)
            fab.load_default_settings()
            core_plugin_decs.plugin_main(fab)
            core_plugin_ops.plugin_main(fab)
            core_plugin_cmds.plugin_main(fab)
            fabfile = _pick_fabfile()
            fab.load_fabfile(fabfile, fail='warn')
            commands = parse_args(args, fab.env)
            fab.validate_commands(commands)
            fab.execute_commands(commands)
        finally:
            fab.disconnect()
        print("Done.")
    except SystemExit:
        # a number of internal functions might raise this one.
        raise
    except KeyboardInterrupt:
        print("Stopped.")
        sys.exit(1)
    except:
        sys.excepthook(*sys.exc_info())
        # we might leave stale threads if we don't explicitly exit()
        sys.exit(1)
    sys.exit(0)

