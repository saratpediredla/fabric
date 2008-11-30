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
