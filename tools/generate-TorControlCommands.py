#!/usr/bin/env python3

import re

output = """
    // generated by %s
""" % __file__

commands = []
command_types = []
with open('../tor/src/feature/control/control_cmd.c') as fp:
    m = re.search(r'control_cmd_def_t CONTROL_COMMANDS\[]\s*=\s*{\n*([^}]+)}', fp.read(), re.MULTILINE)
    control_cmd_def_t = m.group(1).rstrip()
    for type, command in re.findall(r'.*(MULTLINE|OBSOLETE|ONE_LINE)\(([a-zA-Z0-9_]+).*', control_cmd_def_t):
        commands.append(command.upper())
        command_types.append([type, command.upper()])

for type, command in command_types:
    if type == 'OBSOLETE':
        output += '    @Deprecated\n'

    if type == 'MULTLINE':
        output += '    public static final String %s = "+%s";\n' % (command, command)
    else:
        output += '    public static final String %s = "%s";\n' % (command, command)


print(output)
