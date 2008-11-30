#!/usr/bin/env python
# encoding: utf-8
"""
interop.py
Interoperability helpers for various OSes and versions of Python.

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

import sys
import os.path

is_win32 = sys.platform in ['win32', 'cygwin']

# Cross-platform current username
def get_username():
    if is_win32:
        import win32api
        #import win32security # why did we import these in the first place?
        #import win32profile
        return win32api.GetUserName()
    else:
        import pwd
        return pwd.getpwuid(os.getuid())[0]

# Find cross-platform home directory of current user
def get_home_directory():
    if is_win32:
        from win32com.shell.shell import SHGetSpecialFolderPath
        from win32com.shell.shellcon import CSIDL_PROFILE
        return SHGetSpecialFolderPath(0,CSIDL_PROFILE)
    else:
        return os.path.expanduser("~")

# Python 2.4 does not have str.partition
if hasattr(str, 'partition'):
    partition = str.partition
else:
    def partition(txt, sep):
        idx = txt.find(sep)
        if idx == -1:
            return txt, '', ''
        else:
            return (txt[:idx], sep, txt[idx + len(sep):])
