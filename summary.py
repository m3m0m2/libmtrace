#!/usr/bin/python3
#
# Copyright (C) 2023, Mauro Meneghin <m3m0m2 @ gmail.com>
#
# Process the output the libmtrace reporting a summary
#
# Warning: work in progress!

import fileinput
import re

inBackTrace = False
currentBackTrace = ''
currentMethod = ''
allocSize = ''
backtraces = {}

mallocs = {}

for line in fileinput.input():
    if inBackTrace:
        if line == '\n':
            print("New Line")
            if not currentBackTrace in backtraces:
                backtraces[currentBackTrace] = {'count': 0, 'malloc': list(),
                        'free': list(), 'realloc': list(), 'calloc': list()}
            backtraces[currentBackTrace]['count'] += 1
            backtraces[currentBackTrace][currentMethod].append(allocSize)

            inBackTrace = False
            currentBackTrace = ''
            currentMethod = ''
            allocSize = ''
        else:
            currentBackTrace += line
    else:
        match = re.search(r"^malloc\((\d*)\) = (.*)$", line)
        if match:
            currentMethod = 'malloc'
            allocSize = match.group(1)
            print("matched malloc {0} {1}".format(match.group(1), match.group(2)))
            mallocs[match.group(2)] = match.group(1)
            inBackTrace = True
            continue
        match = re.search(r"^free\((.*)\)$", line)
        if match:
            currentMethod = 'free'
            if match.group(1) == '(nil)':
                allocSize = 'null'
            elif match.group(1) in mallocs:
                allocSize = mallocs[match.group(1)]
            else:
                allocSize = '???'
            print("matched free {0}".format(match.group(1)))
            mallocs[match.group(1)] = '***ALREADY_FREED**'
            inBackTrace = True
            continue
        match = re.search(r"^realloc\((.*), (\d*)\) = (.*)$", line)
        if match:
            currentMethod = 'realloc'
            allocSize = match.group(2)
            print("matched remalloc {0} {1}".format(match.group(1), match.group(2)))
            mallocs[match.group(3)] = match.group(2)
            if match.group(1) != match.group(3):
                mallocs[match.group(1)] = '***ALREADY_REALLOCED***'
            inBackTrace = True
            continue
        match = re.search(r"^calloc\((\d*), (\d*)\) = (.*)$", line)
        if match:
            currentMethod = 'calloc'
            allocSize = str(int(match.group(1)) * int(match.group(2)))
            print("matched calloc {0} {1} {2}".format(match.group(1),
                match.group(2), match.group(3)))
            mallocs[match.group(3)] = allocSize
            inBackTrace = True
            continue


#for backtrace in backtraces:
for backtrace in dict(sorted(backtraces.items(), key=lambda item: item[1]['count'])):
    print("backtrace: {0}".format(backtrace))
    stats = backtraces[backtrace]
    print("stats:")
    print("calls: {0}".format(stats['count']))
    for method in ('malloc', 'free', 'realloc', 'calloc'):
        if len(stats[method]) > 0:
            print("{0}: {1}".format(method, stats[method]))
    print()



