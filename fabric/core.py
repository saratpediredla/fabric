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
import getpass
import os
import os.path
import re
import readline
import signal
import socket
import subprocess
import sys
import threading
import time
import types
from collections import deque
from functools import wraps

import core_plugin
from interop import get_username, partition, get_home_directory
from util import *

# Paramiko
try:
    import paramiko as ssh
except ImportError:
    print("Error: paramiko is a required module. Please install it:")
    print("  $ sudo easy_install paramiko")
    sys.exit(1)

__version__ = '0.0.9'
__author__ = 'Christian Vest Hansen'
__author_email__ = 'karmazilla@gmail.com'
__url__ = 'http://www.nongnu.org/fab/'
__license__ = 'GPL-2'
__about__ = '''\
   Fabric v. %(fab_version)s, Copyright (C) 2008 %(fab_author)s.
   Fabric comes with ABSOLUTELY NO WARRANTY.
   This is free software, and you are welcome to redistribute it
   under certain conditions. Please reference full license for details.
'''

DEFAULT_ENV = {
    'fab_version': __version__,
    'fab_author': __author__,
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

def RegistryDecorator(registry):
    def registering_decorator(first_arg=None):
        if callable(first_arg):
            registry[first_arg.__name__] = first_arg
            return first_arg
        else:
            def sub_decorator(f):
                registry[first_arg] = f
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
        self.decorator = RegistryDecorator(self.decorators)
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
                    return _run_serially(op_fn, *args, **kwargs)
                # If parallel, create per-host threads
                elif self.env['fab_submode'] == 'parallel':
                    return _run_parallel(op_fn, *args, **kwargs)
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


#
# Helper decorators for use in fabfiles:
#

@decorator
def hosts(*hosts):
    "Tags function object with desired fab_hosts to run on."
    def decorator(fn):
        fn.hosts = hosts
        return fn
    return decorator

@decorator
def roles(*roles):
    "Tags function object with desired fab_hosts to run on."
    def decorator(fn):
        fn.roles = roles
        return fn
    return decorator

@decorator
def mode(mode):
    "Tags function object with desired fab_mode to run in."
    def decorator(fn):
        fn.mode = mode
        return fn
    return decorator

@decorator
def requires(*args, **kwargs):
    """
    Calls `require` with the supplied arguments prior to executing the
    decorated command.
    """
    return _new_call_chain_decorator(require, *args, **kwargs)

@decorator
def depends(*args, **kwargs):
    """
    Calls `invoke` with the supplied arguments prior to executing the
    decorated command.
    """
    return _new_call_chain_decorator(invoke, *args, **kwargs)

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

#
# Standard Fabric commands:
#
@mode("broad")
@command("help")
def _help(**kwargs):
    """
    Display Fabric usage help, or help for a given command.
    
    You can provide help with a parameter and get more detailed help for a
    specific command. For instance, to learn more about the list command, you
    could run `fab help:list`.
    
    If you are developing your own fabfile, then you might also be interested
    in learning more about operations. You can do this by running help with the
    `op` parameter set to the name of the operation you would like to learn
    more about. For instance, to learn more about the `run` operation, you
    could run `fab help:op=run`.

    Fabric also exposes some utility decorators for use with your own commands.
    Run help with the `dec` parameter set to the name of a decorator to learn
    more about it.
    
    """
    if kwargs:
        for k, v in kwargs.items():
            if k in COMMANDS:
                _print_help_for_in(k, COMMANDS)
            elif k in OPERATIONS:
                _print_help_for_in(k, OPERATIONS)
            elif k in ['op', 'operation']:
                _print_help_for_in(kwargs[k], OPERATIONS)
            elif k in ['dec', 'decorator']:
                _print_help_for_in(kwargs[k], DECORATORS)
            else:
                _print_help_for(k, None)
    else:
        print("""
    Fabric is a simple pythonic remote deployment tool.
    
    Type `fab list` to get a list of available commands.
    Type `fab help:help` to get more information on how to use the built in
    help.
    
    """)

@command("about")
def _print_about(**kwargs):
    "Display Fabric version, warranty and license information"
    print(__about__ % ENV)

@mode("broad")
@command("list")
def _list_commands(**kwargs):
    """
    Display a list of commands with descriptions.
    
    By default, the list command prints a list of available commands, with a
    short description (if one is available). However, the list command can also
    print a list of available operations if you provide it with the `ops` or
    `operations` parameters, or it can print a list of available decorators if
    provided with the `dec` or `decorators` parameters.
    """
    if kwargs:
        for k, v in kwargs.items():
            if k in ['cmds', 'commands']:
                print("Available commands are:")
                _list_objs(COMMANDS)
            elif k in ['ops', 'operations']:
                print("Available operations are:")
                _list_objs(OPERATIONS)
            elif k in ['dec', 'decorators']:
                print("Available decorators are:")
                _list_objs(DECORATORS)
            else:
                print("Don't know how to list '%s'." % k)
                print("Try one of these instead:")
                print(indent('\n'.join([
                    'cmds', 'commands',
                    'ops', 'operations',
                    'dec', 'decorators',
                ])))
                sys.exit(1)
    else:
        print("Available commands are:")
        _list_objs(COMMANDS)

@mode("broad")
@command("let")
def _let(**kwargs):
    """
    Set a Fabric variable.
    
    Example:
    
        $fab let:fab_user=billy,other_var=other_value
    """
    for k, v in kwargs.items():
        if isinstance(v, basestring):
            v = (v % ENV)
        ENV[k] = v

@mode("broad")
@command("shell")
def _shell(**kwargs):
    """
    Start an interactive shell connection to the specified hosts.
    
    Optionally takes a list of hostnames as arguments, if Fabric is, by
    the time this command runs, not already connected to one or more
    hosts. If you provide hostnames and Fabric is already connected, then
    Fabric will, depending on `fab_fail`, complain and abort.
    
    The `fab_fail` variable can be overwritten with the `set` command, or
    by specifying an additional `fail` argument.
    
    Examples:
    
        $fab shell
        $fab shell:localhost,127.0.0.1
        $fab shell:localhost,127.0.0.1,fail=warn
    
    """
    # expect every arg w/o a value to be a hostname
    hosts = filter(lambda k: not kwargs[k], kwargs.keys())
    if hosts:
        if CONNECTIONS:
            fail(kwargs, "Already connected to predefined fab_hosts.", ENV)
        set(fab_hosts = hosts)
    def lines():
        try:
            while True:
                yield raw_input("fab> ")
        except EOFError:
            # user pressed ctrl-d
            print
    for line in lines():
        if line == 'exit':
            break
        elif line.startswith('sudo '):
            sudo(line[5:], fail='warn')
        else:
            run(line, fail='warn')

#
# Per-operation execution strategies for "broad" mode.
#
def _run_parallel(fn, *args, **kwargs):
    """
    A strategy that executes on all hosts in parallel.
    
    THIS STRATEGY IS CURRENTLY BROKEN!
    
    """
    err_msg = "The $(fab_current_operation) operation failed on $(fab_host)"
    threads = []
    if not CONNECTIONS:
        _check_fab_hosts()
        _connect()
    for host_conn in CONNECTIONS:
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

def _run_serially(fn, *args, **kwargs):
    """One-at-a-time fail-fast strategy."""
    err_msg = "The $(fab_current_operation) operation failed on $(fab_host)"
    # Capture the first output in case someone really wants captured output
    # while running in broad mode.
    result = None
    if not CONNECTIONS:
        _check_fab_hosts()
        _connect()
    for host_conn in CONNECTIONS:
        env = host_conn.get_env()
        env['fab_current_operation'] = fn.__name__
        host = env['fab_host']
        client = host_conn.client
        res = _try_run_operation(fn, host, client, env, *args, **kwargs)
        if not result:
            result = res
    return result

#
# Internal plumbing:
#

class RegexpValidator(object):
    def __init__(self, pattern):
        self.regexp = re.compile(pattern)
    def __call__(self, value):
        regexp = self.regexp
        if value is None or not regexp.match(value):
            raise ValueError("Malformed value %r. Must match r'%s'." %
                    (value, regexp.pattern))
        return value

class HostConnection(object):
    """
    A connection to an SSH host - wraps an SSHClient.
    
    Instances of this class populate the CONNECTIONS list.
    """
    def __init__(self, hostname, port, global_env, user_local_env):
        self.global_env = global_env
        self.user_local_env = user_local_env
        self.host_local_env = {
            'fab_host': hostname,
            'fab_port': port,
        }
        self.client = None
    def __eq__(self, other):
        return hash(self) == hash(other)
    def __hash__(self):
        return hash(tuple(sorted(self.host_local_env.items())))
    def get_env(self):
        "Create a new environment that is the union of local and global envs."
        env = dict(self.global_env)
        env.update(self.user_local_env)
        env.update(self.host_local_env)
        return env
    def connect(self):
        env = self.get_env()
        new_host_key = env['fab_new_host_key']
        client = ssh.SSHClient()
        client.load_system_host_keys()
        if new_host_key == 'accept':
            client.set_missing_host_key_policy(ssh.AutoAddPolicy())
        try:
            self._do_connect(client, env)
        except (ssh.AuthenticationException, ssh.SSHException):
            PASS_PROMPT = \
                "Password for $(fab_user)@$(fab_host)$(fab_passprompt_suffix)"
            if 'fab_password' in env and env['fab_password']:
                env['fab_passprompt_suffix'] = " [Enter for previous]: "
            else:
                env['fab_passprompt_suffix'] = ": "
            connected = False
            password = None
            while not connected:
                try:
                    password = getpass.getpass(lazy_format(PASS_PROMPT, env))
                    env['fab_password'] = password
                    self._do_connect(client, env)
                    connected = True
                except ssh.AuthenticationException:
                    print("Bad password.")
                    env['fab_passprompt_suffix'] = ": "
                except (EOFError, TypeError):
                    # ctrl-D or ctrl-C on password prompt
                    print
                    sys.exit(0)
            self.host_local_env['fab_password'] = password
            self.user_local_env['fab_password'] = password
        self.client = client
    def disconnect(self):
        if self.client:
            self.client.close()
    def _do_connect(self, client, env):
        host = env['fab_host']
        port = env['fab_port']
        username = env['fab_user']
        password = env['fab_password']
        pkey = env['fab_pkey']
        key_filename = env['fab_key_filename']
        try:
            client.connect(host, port, username, password, pkey, key_filename,
                timeout=10)
        except socket.timeout:
            print('Error: timed out trying to connect to %s' % host)
            sys.exit(1)
        except socket.gaierror:
            print('Error: name lookup failed for %s' % host)
            sys.exit(1)
    def __str__(self):
        return self.host_local_env['fab_host']

def _print_help_for(name, doc):
    "Output a pretty-printed help text for the given name & doc"
    default_help_msg = '* No help-text found.'
    msg = doc or default_help_msg
    lines = msg.splitlines()
    # remove leading blank lines
    while lines and lines[0].strip() == '':
        lines = lines[1:]
    # remove trailing blank lines
    while lines and lines[-1].strip() == '':
        lines = lines[:-1]
    if lines:
        msg = '\n'.join(lines)
        if not msg.startswith('    '):
            msg = indent(msg)
        print("Help for '%s':\n%s" % (name, msg))
    else:
        print("No help message found for '%s'." % name)

def _print_help_for_in(name, dictionary):
    "Print a pretty help text for the named function in the dict."
    if name in dictionary:
        _print_help_for(name, dictionary[name].__doc__)
    else:
        _print_help_for(name, None)

def _list_objs(objs):
    max_name_len = reduce(lambda a, b: max(a, len(b)), objs.keys(), 0)
    cmds = objs.items()
    cmds.sort(lambda x, y: cmp(x[0], y[0]))
    for name, fn in cmds:
        print '  ', name.ljust(max_name_len),
        if fn.__doc__:
            print ':', filter(None, fn.__doc__.splitlines())[0].strip()
        else:
            print

def _check_fab_hosts():
    "Check that we have a fab_hosts variable, and prompt if it's missing."
    if not ENV.get('fab_local_hosts'):
        prompt('fab_input_hosts',
            'Please specify host or hosts to connect to (comma-separated)')
        hosts = ENV['fab_input_hosts']
        hosts = [x.strip() for x in hosts.split(',')]
        ENV['fab_local_hosts'] = hosts
    
def _connect():
    """Populate CONNECTIONS with HostConnection instances as per current
    fab_local_hosts."""
    signal.signal(signal.SIGINT, lambda: _disconnect() and sys.exit(0))
    global CONNECTIONS
    def_port = ENV['fab_port']
    username = ENV['fab_user']
    fab_hosts = ENV['fab_local_hosts']
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
        conn = HostConnection(hostname, port, ENV, user_envs[user])
        if user not in host_connections_by_user:
            host_connections_by_user[user] = [conn]
        else:
            host_connections_by_user[user].append(conn)
    
    # Print and establish connections
    for user, host_connections in host_connections_by_user.iteritems():
        user_env = dict(ENV)
        user_env.update(user_envs[user])
        print(lazy_format("Logging into the following hosts as $(fab_user):",
            user_env))
        for conn in host_connections:
            print(indent(str(conn)))
        for conn in host_connections:
            conn.connect()
        CONNECTIONS += host_connections

def _disconnect():
    "Disconnect all clients."
    global CONNECTIONS
    map(HostConnection.disconnect, CONNECTIONS)
    CONNECTIONS = []

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

def _start_outputter(prefix, chan, env, stderr=False, capture=None):
    def outputter(prefix, chan, env, stderr, capture):
        # Read one "packet" at a time, which lets us get less-than-a-line
        # chunks of text, such as sudo prompts. However, we still print
        # them to the user one line at a time. (We also eat sudo prompts.)
        leftovers = ""
        while True:
            out = None
            if not stderr:
                out = chan.recv(65535)
            else:
                out = chan.recv_stderr(65535)
            if out is not None:
                # Capture if necessary
                if capture is not None:
                    capture += out

                # Handle any password prompts
                initial_prompt = re.findall(r'^%s$' % env['fab_sudo_prompt'],
                    out, re.I|re.M)
                again_prompt = re.findall(r'^Sorry, try again', out, re.I|re.M)
                if initial_prompt or again_prompt:
                    # First, get or prompt for password
                    PASS_PROMPT = ("Password for $(fab_user)@" +
                        "$(fab_host)$(fab_passprompt_suffix)")
                    old_password = env.get('fab_password')
                    if old_password:
                        # Just set up prompt in case we're at an again prompt
                        env['fab_passprompt_suffix'] = " [Enter for previous]: "
                    else:
                        # Set prompt, then ask for a password
                        env['fab_passprompt_suffix'] = ": "
                        # Get pass, and make sure we communicate it back to the
                        # global ENV since that was obviously empty.
                        ENV['fab_password'] = env['fab_password'] = \
                            getpass.getpass(lazy_format(PASS_PROMPT, env))
                    # Re-prompt -- whatever we supplied last time (the
                    # current value of env['fab_password']) was incorrect.
                    # Don't overwrite ENV because it might not be empty.
                    if again_prompt:
                        env['fab_password'] = \
                            getpass.getpass(lazy_format(PASS_PROMPT, env))
                    # Either way, we have a password now, so send it.
                    chan.sendall(env['fab_password']+'\n')
                    out = ""

                # Deal with line breaks, printing all lines and storing the
                # leftovers, if any.
                if '\n' in out:
                    parts = out.split('\n')
                    line = leftovers + parts.pop(0)
                    leftovers = parts.pop()
                    while parts or line:
                        if not env['fab_quiet']:
                            sys.stdout.write("%s: %s\n" % (prefix, line)),
                            sys.stdout.flush()
                        if parts:
                            line = parts.pop(0)
                        else:
                            line = ""
                # If no line breaks, just keep adding to leftovers
                else:
                    leftovers += out

    thread = threading.Thread(None, outputter, prefix,
        (prefix, chan, env, stderr, capture))
    thread.setDaemon(True)
    thread.start()
    return thread

def _pick_fabfile():
    "Figure out what the fabfile is called."
    guesses = ['fabfile', 'Fabfile', 'fabfile.py', 'Fabfile.py']
    options = filter(os.path.exists, guesses)
    if options:
        return options[0]
    else:
        return guesses[0] # load() will barf for us...

def _load_default_settings():
    "Load user-default fabric settings from ~/.fabric"
    cfg = get_home_directory() + "/.fabric"
    if os.path.exists(cfg):
        comments = lambda s: s and not s.startswith("#")
        settings = filter(comments, open(cfg, 'r'))
        settings = [(k.strip(), v.strip()) for k, _, v in
            [partition(s, '=') for s in settings]]
        ENV.update(settings)

def _parse_args(args):
    cmds = []
    for cmd in args:
        cmd_args = []
        cmd_kwargs = {}
        if ':' in cmd:
            cmd, cmd_str_args = cmd.split(':', 1)
            for cmd_arg_kv in cmd_str_args.split(','):
                k, _, v = partition(cmd_arg_kv, '=')
                if v:
                    cmd_kwargs[k] = (v % ENV) or k
                else:
                    cmd_args.append(k)
        cmds.append((cmd, cmd_args, cmd_kwargs))
    return cmds

def _validate_commands(cmds):
    if not cmds:
        print("No commands given.")
        _list_commands()
    else:
        for cmd in cmds:
            if not cmd[0] in COMMANDS:
                print("No such command: %s" % cmd[0])
                sys.exit(1)

def _execute_commands(cmds):
    for cmd, args, kwargs in cmds:
        _execute_command(cmd, args, kwargs)

def _execute_command(cmd, args, kwargs, skip_executed=False):
    # Setup
    command = COMMANDS[cmd]
    if args is not None:
        args = map(lazy_format, args)
    if kwargs is not None:
        kwargs = dict(zip(kwargs.keys(), map(lazy_format, kwargs.values())))
    # Remember executed commands. Don't run them again if skip_executed.
    if skip_executed and _has_executed(command, args, kwargs):
        args_msg = (args or kwargs) and (" with %r, %r" % (args, kwargs)) or ""
        print("Skipping %s (already invoked%s)." % (cmd, args_msg))
        return
    _remember_executed(command, args, kwargs)
    # Invoke eventual chained calls prior to the command.
    if ENV.get('fab_cur_command'):
        print("Chaining %s..." % cmd)
    else:
        print("Running %s..." % cmd)
    ENV['fab_cur_command'] = cmd
    call_chain = getattr(command, '_call_chain', None)
    if call_chain:
        for chained in call_chain:
            chained()
        if ENV['fab_cur_command'] != cmd:
            print("Back in %s..." % cmd)
            ENV['fab_cur_command'] = cmd
    # Determine target host and execute command.
    _execute_at_target(command, args, kwargs)
    # Done
    ENV['fab_cur_command'] = None

def _has_executed(command, args, kwargs):
    return (command, _args_hash(args, kwargs)) in _EXECUTED_COMMANDS

def _remember_executed(command, args, kwargs):
    try:
        _EXECUTED_COMMANDS.add((command, _args_hash(args, kwargs)))
    except TypeError:
        print "Warning: could not remember execution (unhashable arguments)."

def _args_hash(args, kwargs):
    if not args or kwargs:
        return None
    return hash(tuple(sorted(args + kwargs.items())))

def _execute_at_target(command, args, kwargs):
    mode = ENV['fab_local_mode'] = getattr(command, 'mode', ENV['fab_mode'])
    hosts = ENV['fab_local_hosts'] = set(getattr(
        command, 'hosts', ENV.get('fab_hosts') or []))
    roles = getattr(command, 'roles', [])
    for role in roles:
        role = lazy_format(role, ENV)
        role_hosts = ENV.get(role)
        map(hosts.add, role_hosts)
    if mode in ('rolling', 'fanout'):
        print("Warning: The 'rolling' and 'fanout' fab_modes are " +
              "deprecated.\n   Use 'broad' and 'deep' instead.")
        mode = ENV['fab_local_mode'] = 'broad'
    # Run command once, with each operation running once per host.
    if mode == 'broad':
        command(*args, **kwargs)
    # Run entire command once per host.
    elif mode == 'deep':
        # Determine whether we need to connect for this command, do so if so
        if _needs_connect(command):
            _check_fab_hosts()
            _connect()
        # Gracefully handle local-only commands
        if CONNECTIONS:
            for host_conn in CONNECTIONS:
                ENV['fab_host_conn'] = host_conn
                ENV['fab_host'] = host_conn.host_local_env['fab_host']
                command(*args, **kwargs)
        else:
            command(*args, **kwargs)
    else:
        fail({'fail':'abort'}, "Unknown fab_mode: '$(fab_mode)'", ENV)
    # Disconnect (to clear things up for next command)
    # TODO: be intelligent, persist connections for hosts
    # that will be used again this session.
    _disconnect()

def _needs_connect(command):
    for operation in command.func_code.co_names:
        if getattr(OPERATIONS.get(operation), 'connects', False):
            return True

def main():
    args = sys.argv[1:]
    try:
        try:
            print("Fabric v. %(fab_version)s." % ENV)
            _load_default_settings()
            fabfile = _pick_fabfile()
            load(fabfile, fail='warn')
            commands = _parse_args(args)
            _validate_commands(commands)
            _execute_commands(commands)
        finally:
            _disconnect()
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


