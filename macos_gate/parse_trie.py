import base64
import sys


def uleb(buf, pos):
    out = 0
    shift = 0
    while True:
        b = buf[pos]
        pos += 1
        out |= (b & 0x7F) << shift
        if not b & 0x80:
            return out, pos
        shift += 7


def parse_trie(buf):
    out = []

    def walk(pos, prefix, depth):
        if depth > 64 or pos >= len(buf):
            return
        tsize, after = uleb(buf, pos)
        if tsize and prefix:
            out.append(prefix)
        p = after + tsize
        if p >= len(buf):
            return
        n, p = uleb(buf, p)
        for _ in range(n):
            e = buf.index(b'\x00', p)
            edge = buf[p:e].decode('latin-1')
            off, p = uleb(buf, e + 1)
            walk(off, prefix + edge, depth + 1)

    walk(0, '', 0)
    return out


def main(argv):
    data = sys.stdin.buffer.read().decode('latin-1')
    out = sys.stdout.buffer
    for line in data.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        parts = line.split()
        if len(parts) >= 3 and parts[1] == 'TRIE':
            for sym in parse_trie(base64.b64decode(parts[2])):
                if sym and ' ' not in sym:
                    out.write(('%s %s\n' % (parts[0], sym))
                              .encode('latin-1'))
        elif len(parts) == 2 or (len(parts) == 3 and parts[1] == 'REEXPORT'):
            out.write((line + '\n').encode('latin-1'))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
