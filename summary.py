#!/usr/bin/python3
#
# Copyright (C) 2023, Mauro Meneghin <m3m0m2 @ gmail.com>
#
# Process the output the libmtrace reporting a summary
#
# Warning: work in progress!

import fileinput
import re
import sys
import subprocess
from enum import Enum

symbol_resolve_cmd = 'c++filt'
symbols_map = {}

def resolve_symbol(symbol):
    if not symbol in symbols_map:
        symbols_map[symbol] = subprocess.check_output([symbol_resolve_cmd, symbol]) \
                .decode(sys.stdout.encoding).rstrip()
    return symbols_map[symbol]

# line format (PATH can include +):
# PATH(SYMBOL+OFFSET)[ADDRESS]
class BacktraceLine:
    def __init__(self, line):
        fields = re.split('\(|\)|\[|\]', line)
        assert(len(fields) == 5)
        symfields = fields[1].split('+')
        assert(len(symfields) == 2)

        self.path = fields[0]
        self.symbol = symfields[0]
        self.offset = symfields[1]
        self.address = fields[3]

    # TODO: a range could be useful for offset and address
    def match(self, pattern):
        if len(pattern.path) != 0 and not re.search(pattern.path, self.path):
            return False
        if len(pattern.symbol) != 0 and not re.search(pattern.symbol, self.symbol):
            return False
        if len(pattern.offset) != 0 and int(self.offset, 16) != int(pattern.offset, 16):
            return False
        if len(pattern.address) != 0 and not self.address == pattern.address:
            return False
        return True

    def toString(self):
        readable_symbol = resolve_symbol(self.symbol)
        return '{0}({1}+{2})[{3}]'.format(self.path, readable_symbol, self.offset, self.address)

# TODO: filters could be extended
backtrace_filter_out=BacktraceLine('libmtrace.so(+)[]')

def error(line):
    print(line)
    sys.exit(1)

class ParsingStatus(Enum):
    READY=0
    THREAD=1
    METHOD=2
    BACKTRACE_START=3
    BACKTRACE=4
    BACKTRACE_END=5

backtraces = {}
mallocs = {}

def parse():
    print("# Parsing")
    status = ParsingStatus.READY
    thread_id = None
    method = None
    allocSize = 0
    currentBackTrace = ''

    for line in fileinput.input():
        line = line.rstrip()
        if status == ParsingStatus.READY:
            thread_id = None
            method = None
            allocSize = 0
            currentBackTrace = ''
            status = ParsingStatus.THREAD
        elif len(line) == 0 or line[0] == ' ' or line[0] == '-':
            continue
        elif status == ParsingStatus.THREAD:
            assert(line.startswith('# Thread: '))
            m = re.findall(r'\d+', line)
            if len(m) < 1:
                sys.exit(1)
            thread_id = m[0]
            status = ParsingStatus.METHOD
        elif status == ParsingStatus.METHOD:
            status = ParsingStatus.BACKTRACE_START
            match = re.search(r"^malloc\((\d*)\) = (.*)$", line)
            if match:
                method = 'malloc'
                allocSize = match.group(1)
                print("matched malloc {0} {1}".format(match.group(1), match.group(2)))
                mallocs[match.group(2)] = match.group(1)
                continue
            match = re.search(r"^free\((.*)\)$", line)
            if match:
                method = 'free'
                if match.group(1) == '(nil)':
                    allocSize = 'null'
                elif match.group(1) in mallocs:
                    allocSize = mallocs[match.group(1)]
                else:
                    allocSize = '???'
                print("matched free {0}".format(match.group(1)))
                mallocs[match.group(1)] = '***ALREADY_FREED**'
                continue
            match = re.search(r"^realloc\((.*), (\d*)\) = (.*)$", line)
            if match:
                method = 'realloc'
                allocSize = match.group(2)
                print("matched remalloc {0} {1}".format(match.group(1), match.group(2)))
                mallocs[match.group(3)] = match.group(2)
                if match.group(1) != match.group(3):
                    mallocs[match.group(1)] = '***ALREADY_REALLOCED***'
                continue
            match = re.search(r"^calloc\((\d*), (\d*)\) = (.*)$", line)
            if match:
                method = 'calloc'
                allocSize = str(int(match.group(1)) * int(match.group(2)))
                print("matched calloc {0} {1} {2}".format(match.group(1),
                    match.group(2), match.group(3)))
                mallocs[match.group(3)] = allocSize
                continue
            error('Unexpected line {0}: '.format(line))
        elif status == ParsingStatus.BACKTRACE_START:
            assert(line == '[')
            currentBackTrace = ''
            status = ParsingStatus.BACKTRACE
        elif status == ParsingStatus.BACKTRACE:
            if line == ']':
                if not currentBackTrace in backtraces:
                    backtraces[currentBackTrace] = {'count': 0, 'malloc': list(),
                            'free': list(), 'realloc': list(), 'calloc': list()}
                backtraces[currentBackTrace]['count'] += 1
                backtraces[currentBackTrace][method].append(allocSize)
                status = ParsingStatus.READY
            else:
                bt = BacktraceLine(line)
                if bt.match(backtrace_filter_out):
                    continue
                if len(currentBackTrace) > 0:
                    currentBackTrace += '\n'
                currentBackTrace += bt.toString()
    print()

def summary():
    print("# Backtraces")
    for backtrace in dict(sorted(backtraces.items(), key=lambda item: item[1]['count'])):
        print("backtrace:\n{0}".format(backtrace))
        stats = backtraces[backtrace]
        print("stats:")
        print("calls: {0}".format(stats['count']))
        for method in ('malloc', 'free', 'realloc', 'calloc'):
            if len(stats[method]) > 0:
                print("{0}: {1}".format(method, stats[method]))
        print()

    print("# Memory not released:\n   Address     Size")
    for key, value in mallocs.items():
        if len(value) > 0 and value[0] != '*':
            print("{0} {1}".format(key, value))

if __name__ == '__main__':
    parse()
    summary()
