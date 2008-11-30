#!/usr/bin/env python
# encoding: utf-8
"""
core_plugin_cmds.py

Created by Christian Vest Hansen on 2008-11-30.
Copyright (c) 2008 Unwire. All rights reserved.
"""

from util import *

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

def plugin_main(fab):
    @fab.mode("broad")
    @fab.command("help")
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
                if k in fab.commands:
                    _print_help_for_in(k, fab.commands)
                elif k in fab.operations:
                    _print_help_for_in(k, fab.operations)
                elif k in ['op', 'operation']:
                    _print_help_for_in(kwargs[k], fab.operations)
                elif k in ['dec', 'decorator']:
                    _print_help_for_in(kwargs[k], fab.decorators)
                else:
                    _print_help_for(k, None)
        else:
            print("""
        Fabric is a simple pythonic remote deployment tool.
    
        Type `fab list` to get a list of available commands.
        Type `fab help:help` to get more information on how to use the built in
        help.
    
        """)

    @fab.command("about")
    def _print_about(**kwargs):
        "Display Fabric version, warranty and license information"
        print(__about__ % fab.env)

    @fab.mode("broad")
    @fab.command("list")
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
                    _list_objs(fab.commands)
                elif k in ['ops', 'operations']:
                    print("Available operations are:")
                    _list_objs(fab.operations)
                elif k in ['dec', 'decorators']:
                    print("Available decorators are:")
                    _list_objs(fab.decorators)
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
            _list_objs(fab.commands)

    @fab.mode("broad")
    @fab.command("let")
    def _let(**kwargs):
        """
        Set a Fabric variable.
    
        Example:
    
            $fab let:fab_user=billy,other_var=other_value
        """
        for k, v in kwargs.items():
            if isinstance(v, basestring):
                v = (v % fab.env)
            fab.env[k] = v

    @fab.mode("broad")
    @fab.command("shell")
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
            if fab.connections:
                fail(kwargs, "Already connected to predefined fab_hosts.", fab.env)
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
