#!/usr/bin/env python
# encoding: utf-8
"""
core_plugin_ops.py

Created by Christian Vest Hansen on 2008-11-30.
Copyright (c) 2008 Unwire. All rights reserved.
"""

from util import *

def plugin_main(fab):
    @fab.operation
    def require(*varnames, **kwargs):
        """
        Make sure that certain environment variables are available.
    
        The `varnames` parameters are one or more strings that names the variables
        to check for.
    
        Two other optional kwargs are supported:
    
         * `used_for` is a string that gets injected into, and then printed, as
           something like this string: `"This variable is used for %s"`.
         * `provided_by` is a list of strings that name commands which the user
           can run in order to satisfy the requirement, or references to the
           actual command functions them selves.
    
        If the required variables are not found in the current environment, then 
        the operation is stopped and Fabric halts.
    
        Examples:

            # One variable name
            require('project_name',
                used_for='finding the target deployment dir.',
                provided_by=['staging', 'production'],
            )
    
            # Multiple variable names
            require('project_name', 'install_dir', provided_by=[stg, prod])

        """
        if all([var in ENV for var in varnames]):
            return
        if len(varnames) == 1:
            vars_msg = "a %r variable." % varnames[0]
        else:
            vars_msg = "the variables %s." % ", ".join(
                    ["%r" % vn for vn in varnames])
        print(
            ("The '%(fab_cur_command)s' command requires " + vars_msg) % fab.env
        )
        if 'used_for' in kwargs:
            print("This variable is used for %s" % lazy_format(
                kwargs['used_for']), fab.env)
        if 'provided_by' in kwargs:
            print("Get the variable by running one of these commands:")
            to_s = lambda obj: getattr(obj, '__name__', str(obj))
            provided_by = [to_s(obj) for obj in kwargs['provided_by']]
            print('\t' + ('\n\t'.join(provided_by)))
        sys.exit(1)

    @fab.operation
    def prompt(varname, msg, validate=None, default=None):
        """
        Display a prompt to the user and store the input in the given variable.
        If the variable already exists, then it is not prompted for again. (Unless
        it doesn't validate, see below.)
    
        The `validate` parameter is a callable that raises an exception on invalid
        inputs and returns the input for storage in `ENV`.
    
        It may process the input and convert it to a different type, as in the
        second example below.
    
        If `validate` is instead given as a string, it will be used as a regular
        expression against which the input must match.
    
        If validation fails, the exception message will be printed and prompt will
        be called repeatedly until a valid value is given.
    
        Example:
    
            # Simplest form:
            prompt('environment', 'Please specify target environment')
        
            # With default:
            prompt('dish', 'Specify favorite dish', default='spam & eggs')
        
            # With validation, i.e. require integer input:
            prompt('nice', 'Please specify process nice level', validate=int)
        
            # With validation against a regular expression:
            prompt('release', 'Please supply a release name',
                    validate=r'^\w+-\d+(\.\d+)?$')
    
        """
        value = None
        if varname in fab.env and fab.env[varname] is not None:
            value = fab.env[varname]
    
        if callable(default):
            default = default()
        if isinstance(validate, types.StringTypes):
            validate = RegexpValidator(validate)
    
        try:
            default_str = default and (" [%s]" % str(default).strip()) or ""
            prompt_msg = lazy_format("%s%s: " % (msg.strip(), default_str), fab.env)
        
            while True:
                value = value or raw_input(prompt_msg) or default
                if callable(validate):
                    try:
                        value = validate(value)
                    except Exception, e:
                        value = None
                        print e.message
                if value:
                    break
        
            set(**{varname: value})
        except (KeyboardInterrupt, EOFError):
            print
            raise KeyboardInterrupt

    @fab.operation
    @fab.connects
    def put(host, client, env, localpath, remotepath, **kwargs):
        """
        Upload a file to the current hosts.
    
        The `localpath` parameter is the relative or absolute path to the file on
        your localhost that you wish to upload to the `fab_hosts`.
        The `remotepath` parameter is the destination path on the individual
        `fab_hosts`, and relative paths are relative to the fab_user's home
        directory.
    
        May take an additional `fail` keyword argument with one of these values:
    
         * ignore - do nothing on failure
         * warn - print warning on failure
         * abort - terminate fabric on failure
    
        Example:
    
            put('bin/project.zip', '/tmp/project.zip')
    
        """
        localpath = lazy_format(localpath, env)
        remotepath = lazy_format(remotepath, env)
        if not os.path.exists(localpath):
            return False
        ftp = client.open_sftp()
        print("[%s] put: %s -> %s" % (host, localpath, remotepath))
        ftp.put(localpath, remotepath)
        return True

    @fab.operation
    @fab.connects
    def download(host, client, env, remotepath, localpath, **kwargs):
        """
        Download a file from the remote hosts.
    
        The `remotepath` parameter is the relative or absolute path to the files
        to download from the `fab_hosts`. The `localpath` parameter will be
        suffixed with the individual hostname from which they were downloaded, and
        the downloaded files will then be stored in those respective paths.
    
        May take an additional `fail` keyword argument with one of these values:
    
         * ignore - do nothing on failure
         * warn - print warning on failure
         * abort - terminate fabric on failure
    
        Example:
    
            set(fab_hosts=['node1.cluster.com', 'node2.cluster.com'])
            download('/var/log/server.log', 'server.log')
    
        The above code will produce two files on your local system, called
        `server.log.node1.cluster.com` and `server.log.node2.cluster.com`
        respectively.
    
        """
        ftp = client.open_sftp()
        localpath = lazy_format(localpath, env) + '.' + host
        remotepath = lazy_format(remotepath, env)
        print("[%s] download: %s <- %s" % (host, localpath, remotepath))
        ftp.get(remotepath, localpath)
        return True

    @fab.operation
    @fab.connects
    def run(host, client, env, cmd, **kwargs):
        """
        Run a shell command on the current fab_hosts.
    
        The provided command is executed with the permissions of fab_user, and the
        exact execution environ is determined by the `fab_shell` variable.
    
        May take an additional `fail` keyword argument with one of these values:
    
         * ignore - do nothing on failure
         * warn - print warning on failure
         * abort - terminate fabric on failure
    
        Example:
    
            run("ls")
    
        """
        cmd = lazy_format(cmd, env)
        real_cmd = env['fab_shell'] + ' "' + cmd.replace('"', '\\"') + '"'
        real_cmd = escape_bash_specialchars(real_cmd)
        if not confirm_proceed('run', host, kwargs, fab.env):
            return False
        if not env['fab_quiet']:
            print("[%s] run: %s" % (host, cmd))
        chan = client._transport.open_session()
        chan.exec_command(real_cmd)
        capture = []

        out_th = _start_outputter("[%s] out" % host, chan, env, capture=capture)
        err_th = _start_outputter("[%s] err" % host, chan, env, stderr=True)
        status = chan.recv_exit_status()
        chan.close()

        return ("".join(capture).strip(), status == 0)

    @fab.operation
    @fab.connects
    def sudo(host, client, env, cmd, **kwargs):
        """
        Run a sudo (root privileged) command on the current hosts.
    
        The provided command is executed with root permissions, provided that
        `fab_user` is in the sudoers file in the remote host. The exact execution
        environ is determined by the `fab_shell` variable - the `sudo` part is
        injected into this variable.
    
        You can have the command run as a user other than root by setting the
        `user` keyword argument to the intended username or uid.
    
        May take an additional `fail` keyword argument with one of these values:
    
         * ignore - do nothing on failure
         * warn - print warning on failure
         * abort - terminate fabric on failure
    
        Examples:
    
            sudo("install_script.py")
            sudo("httpd restart", user='apache')
    
        """
        cmd = lazy_format(cmd, env)
        if "user" in kwargs:
            user = lazy_format(kwargs['user'], env)
            sudo_cmd = "sudo -S -p '%s' -u " + user + " "
        else:
            sudo_cmd = "sudo -S -p '%s' "
        sudo_cmd = sudo_cmd % env['fab_sudo_prompt']
        real_cmd = env['fab_shell'] + ' "' + cmd.replace('"', '\\"') + '"'
        real_cmd = sudo_cmd + ' ' + real_cmd
        real_cmd = escape_bash_specialchars(real_cmd)
        cmd = env['fab_print_real_sudo'] and real_cmd or cmd
        if not confirm_proceed('sudo', host, kwargs, env):
            return False # TODO: should we return False in fail??
        if not env['fab_quiet']:
            print("[%s] sudo: %s" % (host, cmd))
        chan = client._transport.open_session()
        chan.exec_command(real_cmd)
        capture = []

        out_th = _start_outputter("[%s] out" % host, chan, env, capture=capture)
        err_th = _start_outputter("[%s] err" % host, chan, env, stderr=True)
        status = chan.recv_exit_status()
        chan.close()

        return ("".join(capture).strip(), status == 0)

    @fab.operation
    def local(cmd, **kwargs):
        """
        Run a command locally.
    
        This operation is essentially `os.system()` except that variables are
        expanded prior to running.
    
        May take an additional `fail` keyword argument with one of these values:
    
         * ignore - do nothing on failure
         * warn - print warning on failure
         * abort - terminate fabric on failure
    
        Example:
    
            local("make clean dist", fail='abort')
    
        """
        # we don't need escape_bash_specialchars for local execution
        final_cmd = lazy_format(cmd, fab.env)
        print("[localhost] run: " + final_cmd)
        retcode = subprocess.call(final_cmd, shell=True)
        if retcode != 0:
            fail(kwargs, "Local command failed:\n" + indent(final_cmd), fab.env)

    @fab.operation
    def local_per_host(cmd, **kwargs):
        """
        Run a command locally, for every defined host.
    
        Like the `local()` operation, this is pretty similar to `os.system()`, but
        with this operation, the command is executed (and have its variables
        expanded) for each host in `fab_hosts`.
    
        May take an additional `fail` keyword argument with one of these values:
    
         * ignore - do nothing on failure
         * warn - print warning on failure
         * abort - terminate fabric on failure
    
        Example:
    
            local_per_host("scp -i login.key stuff.zip $(fab_host):stuff.zip")
    
        """
        con_envs = [con.get_env() for con in fab.connections]
        if not con_envs:
            # we might not have connected yet
            for hostname in fab.env['fab_local_hosts']:
                env = dict(fab.env)
                env['fab_host'] = hostname
                con_envs.append(env)
        for env in con_envs:
            final_cmd = lazy_format(cmd, env)
            print(lazy_format("[localhost/$(fab_host)] run: " + final_cmd, env))
            retcode = subprocess.call(final_cmd, shell=True)
            if retcode != 0:
                fail(kwargs, "Local command failed:\n" + indent(final_cmd), env)

    @fab.operation
    def load(filename, **kwargs):
        """
        Load up the given fabfile.
    
        This loads the fabfile specified by the `filename` parameter into fabric
        and makes its commands and other functions available in the scope of the 
        current fabfile.
    
        If the file has already been loaded it will not be loaded again.
    
        May take an additional `fail` keyword argument with one of these values:
    
         * ignore - do nothing on failure
         * warn - print warning on failure
         * abort - terminate fabric on failure
    
        Example:
    
            load("conf/production-settings.py")
    
        """
        fab.load_fabfile(filename, **kwargs)

    @fab.operation
    def upload_project(**kwargs):
        """
        Uploads the current project directory to the connected hosts.
    
        This is a higher-level convenience operation that basically 'tar' up the
        directory that contains your fabfile (presumably it is your project
        directory), uploads it to the `fab_hosts` and 'untar' it.
    
        This operation expects the tar command-line utility to be available on your
        local machine, and it also expects your system to have a `/tmp` directory
        that is writeable.
    
        Unless something fails half-way through, this operation will make sure to
        delete the temporary files it creates.
    
        """
        tar_file = "/tmp/fab.%(fab_timestamp)s.tar" % fab.env
        cwd_name = os.getcwd().split(os.sep)[-1]
        tgz_name = cwd_name + ".tar.gz"
        local("tar -czf %s ." % tar_file, **kwargs)
        put(tar_file, cwd_name + ".tar.gz", **kwargs)
        local("rm -f " + tar_file, **kwargs)
        run("tar -xzf " + tgz_name, **kwargs)
        run("rm -f " + tgz_name, **kwargs)

    @fab.operation
    def abort(msg):
        "Simple way for users to have their commands abort the process."
        print(lazy_format('[$(fab_host)] Error: %s' % msg, fab.env))
        sys.exit(1)

    @fab.operation
    def invoke(*commands):
        """
        Invokes the supplied command only if it has not yet been run (with the
        given arguments, if any).
    
        The arguments in `commands` should be either command references or tuples
        of (command, kwargs) where kwargs is a dict of keyword arguments that will
        be applied when the command is run.
    
        A command reference can be a callable or a string with the command name.
        """
        for item in commands:
            if isinstance(item, tuple):
                if len(item) == 3:
                    cmd, args, kwargs = item
                else:
                    cmd, args = item
                    kwargs = {}
            else:
                cmd, args, kwargs = item, [], {}
            if isinstance(cmd, basestring):
                cmd = fab.commands[item]
            _execute_command(cmd.__name__, args, kwargs, skip_executed=True)


