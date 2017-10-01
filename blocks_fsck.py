from share import Share
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

N = [0, 0, 0]
i = 0

db = persistence.ShareDB()

print("block file is {} byte".format(humanize_number(db.n * 16)))
print("Expecting {} complete blocks".format(db.n))
f = db.block_file

with open(persistence.BLOCK_FILE, 'rb') as f:
    while True:
        b = f.read(16)
        if b == bytes():
            break
        if len(b) != 16:
            print("Incomplete block {}! Just read {} bytes".format(i, len(b)))
            sys.exit(1)
        s = Share.unserialize(b)
        N[s.kind] += 1
        if not s.valid():
            print("Invalid block {}! bad hash".format(i))
        i += 1
        if i % 256 == 0:
            print("Checking block {}".format(i), end='\r', flush=True)

print()
print("Successfully read {} blocks. FOO / BAR / FOOBAR : {}".format(i, N))