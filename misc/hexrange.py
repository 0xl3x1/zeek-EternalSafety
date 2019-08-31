#!/usr/bin/env python3

import sys

def r(start, end):
    x = list(map(hex, range(start, end+1)))
    print(", ".join(x))

r(int(sys.argv[1], 0), int(sys.argv[2], 0))
