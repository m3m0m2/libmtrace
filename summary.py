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

def printHeader(s):
    n=len(s)
    l='#'*(n+2)
    print("{0}\n# {1}\n{0}\n".format('#'*(n+2), s))

class ParsingStatus(Enum):
    READY=0
    THREAD=1
    METHOD=2
    BACKTRACE_START=3
    BACKTRACE=4
    BACKTRACE_END=5

backtraces = {}
mallocs = {}
membt = {}

def parse():
    comments = []
    printHeader("Parsing")
    status = ParsingStatus.READY

    for line in fileinput.input():
        line = line.rstrip()
        if status == ParsingStatus.READY:
            thread_id = None
            method = None
            allocSize = 0
            address = None
            currentBackTrace = ''
            status = ParsingStatus.THREAD
        if len(line) == 0 or line[0] == ' ' or line[0] == '-' or line[0] == '#':
            if len(line) > 1:
                comments.append(line)
            continue
        elif status == ParsingStatus.THREAD:
            assert(line.startswith('* '))
            m = re.findall(r'\d+', line)
            if len(m) < 1:
                sys.exit(1)
            thread_id = m[0]
            currentBackTrace += 'Thread {0}'.format(thread_id)
            line = line[3+len(m[0]):]
            status = ParsingStatus.METHOD
            #elif status == ParsingStatus.METHOD:
            status = ParsingStatus.BACKTRACE_START
            match = re.search(r"^malloc\((\d*)\) = (.*)$", line)
            if match:
                method = 'malloc'
                allocSize = match.group(1)
                print("matched malloc {0} {1}".format(match.group(1), match.group(2)))
                mallocs[match.group(2)] = match.group(1)
                address = match.group(2)
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
                if match.group(1) in membt:
                    del membt[match.group(1)]
                continue
            match = re.search(r"^realloc\((.*), (\d*)\) = (.*)$", line)
            if match:
                method = 'realloc'
                allocSize = match.group(2)
                print("matched remalloc {0} {1}".format(match.group(1), match.group(2)))
                mallocs[match.group(3)] = match.group(2)
                if match.group(1) != match.group(3):
                    mallocs[match.group(1)] = '***ALREADY_REALLOCED***'
                if match.group(1) in membt:
                    del membt[match.group(1)]
                address = match.group(3)
                continue
            match = re.search(r"^calloc\((\d*), (\d*)\) = (.*)$", line)
            if match:
                method = 'calloc'
                allocSize = int(match.group(1)) * int(match.group(2))
                print("matched calloc {0} {1} {2}".format(match.group(1),
                    match.group(2), match.group(3)))
                mallocs[match.group(3)] = allocSize
                address = match.group(3)
                continue
            match = re.search(r"^aligned_alloc\((\d*), (\d*)\) = (.*)$", line)
            if match:
                method = 'aligned_alloc'
                allocSize = int(match.group(2))
                print("matched aligned_alloc {0} {1} {2}".format(match.group(1),
                    match.group(2), match.group(3)))
                mallocs[match.group(3)] = allocSize
                address = match.group(3)
                continue
            match = re.search(r"^posix_memalign\((\d*), (\d*)\) = (.*)$", line)
            if match:
                method = 'posix_memalign'
                allocSize = int(match.group(2))
                print("matched posix_memalign {0} {1} {2}".format(match.group(1),
                    match.group(2), match.group(3)))
                mallocs[match.group(3)] = allocSize
                address = match.group(3)
                continue
            match = re.search(r"^memalign\((\d*), (\d*)\) = (.*)$", line)
            if match:
                method = 'memalign'
                allocSize = int(match.group(2))
                print("matched memalign {0} {1} {2}".format(match.group(1),
                    match.group(2), match.group(3)))
                mallocs[match.group(3)] = allocSize
                address = match.group(3)
                continue
            error('Unexpected line {0}: '.format(line))
        elif status == ParsingStatus.BACKTRACE_START:
            assert(line == '[')
            status = ParsingStatus.BACKTRACE
        elif status == ParsingStatus.BACKTRACE:
            if line == ']':
                if not currentBackTrace in backtraces:
                    backtraces[currentBackTrace] = {'count': 0, 'malloc': list(),
                            'free': list(), 'realloc': list(), 'calloc': list(),
                            'aligned_alloc': list(), 'posix_memalign': list(),
                            'memalign': list() }
                backtraces[currentBackTrace]['count'] += 1
                backtraces[currentBackTrace][method].append(allocSize)
                if address is not None:
                    membt[address] = currentBackTrace
                status = ParsingStatus.READY
            else:
                bt = BacktraceLine(line)
                if bt.match(backtrace_filter_out):
                    continue
                if len(currentBackTrace) > 0:
                    currentBackTrace += '\n'
                currentBackTrace += bt.toString()
    print()

    printHeader("Comments")
    for line in comments:
        print(line)
    print()

def summary():
    printHeader("Backtraces")
    for backtrace in dict(sorted(backtraces.items(), key=lambda item: item[1]['count'])):
        print("{0}".format(backtrace))
        stats = backtraces[backtrace]
        print("* Calls: {0}".format(stats['count']))
        for method in sorted(stats):
            if method == 'count':
                continue
            if len(stats[method]) > 0:
                print("  {0}: {1}".format(method, stats[method]))
        print()

    printHeader("Memory not released")
    for key, value in mallocs.items():
        if len(value) > 0 and value[0] != '*':
            print("   Address     Size")
            print("{0} {1}".format(key, value))
            print("\nbacktrace:\n{0}\n".format(membt[key]))

if __name__ == '__main__':
    parse()
    summary()
