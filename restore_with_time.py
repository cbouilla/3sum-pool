#!/usr/bin/env python3
import sys
from binascii import hexlify, unhexlify
from share import Share

# take a NEW-STYLE block file, in ASCII-HEX (one record/line), check it and put it back in binary.

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("USAGE: ./restore_with_time.py [filename_in] [filename_out]")
        sys.exit(1)

    i = 0
    with open(sys.argv[1], 'r') as f, open(sys.argv[2], 'wb') as g:
        for line in f:
            blob = unhexlify(line.strip())
            s = Share.unserialize(blob)
            if not s.valid():
                print("Invalid block {}! bad hash".format(i))
            g.write(s.serialize())

            if i & 0xfff == 0:
                print("Done {}".format(i), end='\r', flush=True)
            i += 1

    print()