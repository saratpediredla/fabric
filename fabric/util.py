#!/usr/bin/env python
# encoding: utf-8
"""
util.py
Basic Fabric utility functins.

Copyright (C) 2008  Christian Vest Hansen

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License along
with this program; if not, write to the Free Software Foundation, Inc.,
51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
"""

import re

_LAZY_FORMAT_SUBSTITUTER = re.compile(r'(\\?)(\$\((?P<var>[\w-]+?)\))')

def lazy_format(string, env):
    "Do recursive string substitution of ENV vars - both lazy and eager."
    if string is None:
        return None
    env = dict([(k, str(v)) for k, v in env.items()])
    string = string.replace('%', '%%')
    def replacer_fn(match):
        escape = match.group(1)
        if escape == '\\':
            return match.group(2)
        var = match.group('var')
        if var in env:
            return escape + _lazy_format(env[var] % env, env)
        else:
            return match.group(0)
    return re.sub(_LAZY_FORMAT_SUBSTITUTER, replacer_fn, string % env)

def escape_bash_specialchars(txt):
    return txt.replace('$', "\\$")

def indent(text, level=4):
    "Indent all lines in text with 'level' number of spaces, default 4."
    return '\n'.join(((' ' * level) + line for line in text.splitlines()))

def fail(kwargs, msg, env):
    # Get failure code
    codes = {
        'ignore': (1, ''),
        'warn': (2, 'Warning: '),
        'abort': (3, 'Error: '),
    }
    code, msg_prefix = codes[env['fab_fail']]
    if 'fail' in kwargs:
        code, msg_prefix = codes[kwargs['fail']]
    # If warn or above, print message
    if code > 1:
        print(msg_prefix + lazy_format(msg, env))
        # If abort, also exit
        if code > 2:
            sys.exit(1)

def confirm_proceed(exec_type, host, kwargs, env):
    if 'confirm' in kwargs:
        infotuple = (exec_type, host, lazy_format(kwargs['confirm']), env)
        question = "Confirm %s for host %s: %s [yN] " % infotuple
        answer = raw_input(question)
        return answer and answer in 'yY'
    return True



