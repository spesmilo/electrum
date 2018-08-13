from __future__ import absolute_import, division, print_function

from code import InteractiveConsole

from electroncash import commands, version
from electroncash.commands import known_commands


class ECConsole(InteractiveConsole):
    """`interact` must be run on a background thread, because it blocks waiting for input.
    """
    def __init__(self, context):
        variables = {
            "config": "FIXME",
            "context": context.getApplicationContext(),
            "network": "FIXME",
            "wallet": "FIXME",
        }
        cmds = commands.Commands(variables["config"], variables["wallet"],
                                 variables["network"])
        namespace = dict(variables)
        namespace.update({name: CommandWrapper(cmds, name) for name in known_commands})
        namespace.update(help=Help(variables))
        InteractiveConsole.__init__(self, locals=namespace)

    def interact(self, banner=None):
        if banner is None:
            banner = (f"Electron Cash {version.PACKAGE_VERSION}\n"
                      f"Type 'help' for available commands and variables.")
        try:
            InteractiveConsole.interact(self, banner)
        except SystemExit:
            pass


class CommandWrapper:
    def __init__(self, cmds, name):
        self.cmds = cmds
        self.name = name

    def __call__(self, *args, **kwargs):
        return self.cmds._run(self.name, *args, **kwargs)


class Help:
    def __init__(self, variables):
        self.variables = variables

    def __repr__(self):
        return self.help()

    def __call__(self, *args):
        print(self.help(*args))

    def help(self, name_or_wrapper=None):
        if name_or_wrapper is None:
            return("Commands:\n" +
                   "\n".join(f"  {cmd}" for name, cmd in sorted(known_commands.items())) +
                   "\nType help(<command>) for more details.\n" +
                   "The following variables are also available: " +
                   ", ".join(sorted(self.variables)))
        else:
            if isinstance(name_or_wrapper, CommandWrapper):
                cmd = known_commands[name_or_wrapper.name]
            else:
                cmd = known_commands[name_or_wrapper]
            return f"{cmd}\n{cmd.description}"
