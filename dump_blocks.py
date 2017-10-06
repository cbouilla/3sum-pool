import sys
from math import log
from share import Share, JOB_TYPES
import persistence

def humanize_number(n):
    if n < 1024:
        return str(n)
    if n < 1024**2:
        return "{:.1f}K".format(n / 1024)
    if n < 1024**3:
        return "{:.1f}M".format(n / 1024**2)
    if n < 1024**4:
        return "{:.1f}G".format(n / 1024**3)
    return "{:.1f}T".format(n / 1024**4)


def process(blob):
    s = Share.unserialize(blob)
    if not s.valid():
        print("Invalid block {}! bad hash".format(i))
        return None
    as_number = int.from_bytes(s.block_hash(), byteorder="little")
    assert as_number < (1 << 224)
    top = as_number >> (224 - n)
    return (s.kind, top.to_bytes(8, byteorder='little'))



if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("USAGE: python3 blocks_dispatch.py [n]")
        print("    [n] : number of bits to match on")
        sys.exit(1)
    n = int(sys.argv[1])

    db = persistence.ShareDB()
    print("block file is {} byte".format(humanize_number(db.n * 16)))
    print("Expecting {} complete blocks".format(db.n))

    list_size = db.n // 3
    total_size = list_size ** 3
    print("expecting 3SUM on {:.1f} bits (@ D=1)".format(log(total_size, 2)))

    N = [0, 0, 0]
    i = 0
    FILES = [open("hash.{}.bin".format(x), 'wb') for x in JOB_TYPES]

    with open(persistence.BLOCK_FILE, 'rb') as f:
        while True:
            blob = f.read(16)
            if not blob:
                break

            kind, x = process(blob)
            N[kind] += 1
            FILES[kind].write(x)

            if i & 0xfff == 0:
                print("Done {}".format(i), end='\r', flush=True)
            i += 1

    print()
    print("Successfully read {} blocks. FOO / BAR / FOOBAR : {}".format(i, N))