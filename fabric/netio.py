#!/usr/bin/env python
# encoding: utf-8
"""
netio.py

Created by Christian Vest Hansen on 2008-12-02.
Copyright (c) 2008 Unwire. All rights reserved.
"""

import getpass
import os
import socket
import sys
import threading

from util import *

# Paramiko
try:
    import paramiko as ssh
except ImportError:
    print("Error: paramiko is a required module. Please install it:")
    print("  $ sudo easy_install paramiko")
    sys.exit(1)


class HostConnection(object):
    """
    A connection to an SSH host - wraps an SSHClient.
    
    Instances of this class populate the Fabric.connections list.
    """
    def __init__(self, hostname, port, user_local_env, global_env):
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

def start_outputter(prefix, chan, local_env, global_env, stderr=False, capture=None):
    def outputter(prefix, chan, local_env, global_env, stderr, capture):
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
                initial_prompt = re.findall(
                    r'^%s$' % local_env['fab_sudo_prompt'], out, re.I|re.M)
                again_prompt = re.findall(r'^Sorry, try again', out, re.I|re.M)
                if initial_prompt or again_prompt:
                    # First, get or prompt for password
                    PASS_PROMPT = ("Password for $(fab_user)@" +
                        "$(fab_host)$(fab_passprompt_suffix)")
                    old_password = env.get('fab_password')
                    if old_password:
                        # Just set up prompt in case we're at an again prompt
                        local_env['fab_passprompt_suffix'] = " [Enter for previous]: "
                    else:
                        # Set prompt, then ask for a password
                        local_env['fab_passprompt_suffix'] = ": "
                        # Get pass, and make sure we communicate it back to the
                        # fab.env since that was obviously empty.
                        global_env['fab_password'] = local_env['fab_password'] = \
                            getpass.getpass(lazy_format(PASS_PROMPT, local_env))
                    # Re-prompt -- whatever we supplied last time (the
                    # current value of env['fab_password']) was incorrect.
                    # Don't overwrite fab.env because it might not be empty.
                    if again_prompt:
                        local_env['fab_password'] = \
                            getpass.getpass(lazy_format(PASS_PROMPT, local_env))
                    # Either way, we have a password now, so send it.
                    chan.sendall(local_env['fab_password']+'\n')
                    out = ""

                # Deal with line breaks, printing all lines and storing the
                # leftovers, if any.
                if '\n' in out:
                    parts = out.split('\n')
                    line = leftovers + parts.pop(0)
                    leftovers = parts.pop()
                    while parts or line:
                        if not local_env['fab_quiet']:
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
        (prefix, chan, local_env, global_env, stderr, capture))
    thread.setDaemon(True)
    thread.start()
    return thread


