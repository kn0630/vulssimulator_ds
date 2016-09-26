#! /usr/bin/env python

# Standard libraries
import sys


# project libraries
from lib import core
from lib import simulate


def parse_args(str_to_parse=None):
    """
    Parse the command line args
    """
    cmd = ""
    if len(sys.argv) > 1:
        cmd = sys.argv[1]

    return cmd


class Script(core.ScriptContext):

    def __init__(self, command_to_run):
        self.command_to_run = command_to_run
        self.available_commands = {
            'simulate':
            {
                'help': 'Simulate and Output Deep Security\'s coverage for high urgency vulnerability reported by Vuls',
                'cmd': simulate.run_script,
            },
        }

        if not self.command_to_run in list(self.available_commands.keys()):
            self.print_help()
        else:
            # run a specific command
            self.available_commands[self.command_to_run]['cmd'](sys.argv[1:])

    def print_help(self):
        """
        Print the command line syntax available to the user
        """
        print(
            "usage: python vulssimulator_ds.py [COMMAND]\n   For more help on a specific command, type \"python vulssimulator_ds.py [COMMAND] --help\"\n\n   Available commands:\n")
        for cmd, data in list(self.available_commands.items()):
            print("   {}\n      > {}".format(cmd, data['help']))
        print("")


def main():
    """
    Run the script from the command line
    """
    context = Script(parse_args())

if __name__ == '__main__':
    main()
