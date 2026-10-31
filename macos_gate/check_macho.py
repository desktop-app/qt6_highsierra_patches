import gzip
import os
import struct
import sys

MH_MAGIC = 0xFEEDFACE
MH_MAGIC_64 = 0xFEEDFACF
FAT_MAGIC = 0xBEBAFECA
FAT_MAGIC_64 = 0xBFBAFECA
LC_REQ = 0x80000000
LC_SYMTAB = 0x2
LC_LOAD_DYLIB = 0xC
LC_ID_DYLIB = 0xD
LC_LOAD_WEAK_DYLIB = 0x18
LC_RPATH = 0x1C
LC_REEXPORT_DYLIB = 0x1F
LC_LAZY_LOAD_DYLIB = 0x20
LC_LOAD_UPWARD_DYLIB = 0x23
LC_VERSION_MIN_MACOSX = 0x24
LC_BUILD_VERSION = 0x32
LC_DYLD_CHAINED_FIXUPS = 0x34
N_EXT = 0x01
N_TYPE = 0x0E
N_UNDF = 0x00
N_ABS = 0x02
N_PBUD = 0x0C
N_SECT = 0x0E
N_WEAK_REF = 0x0040
PLATFORM_MACOS = 1
DYNAMIC_LOOKUP_ORDINAL = 0xFE
EXECUTABLE_ORDINAL = 0xFF

TARGET = (10, 13, 6)
TARGET_TEXT = '.'.join(str(v) for v in TARGET)
WEAK_PRINT_LIMIT = 100


def ver_tuple(value):
    return ((value >> 16) & 0xFF, (value >> 8) & 0xFF, value & 0xFF)


def ver_text(value):
    return '.'.join(str(v) for v in ver_tuple(value))


class Slice(object):
    def __init__(self, data, base, bits):
        self.data = data
        self.base = base
        self.bits = bits
        self.id_dylib = None
        self.load_dylibs = []
        self.rpaths = []
        self.minos = None
        self.platform = None
        self.chained = False
        self.undefined = []
        self.exported = set()
        self._parse()

    def _str_at(self, off):
        end = self.data.find(b'\x00', off)
        return self.data[off:end].decode('latin-1')

    def _lc_str(self, off):
        return self._str_at(off + struct.unpack_from(
            '<I', self.data, off + 8)[0])

    def _parse(self):
        ncmds = struct.unpack_from('<I', self.data, self.base + 16)[0]
        off = self.base + (32 if self.bits == 64 else 28)
        symoff = nsyms = 0
        stroff = None
        for _ in range(ncmds):
            cmd, size = struct.unpack_from('<II', self.data, off)
            if size < 8:
                break
            cmd &= ~LC_REQ
            if cmd == LC_SYMTAB:
                symoff, nsyms = struct.unpack_from('<II', self.data, off + 8)
                stroff = self.base + struct.unpack_from(
                    '<I', self.data, off + 16)[0]
            elif cmd in (LC_LOAD_DYLIB, LC_LOAD_WEAK_DYLIB,
                         LC_REEXPORT_DYLIB, LC_LAZY_LOAD_DYLIB,
                         LC_LOAD_UPWARD_DYLIB):
                self.load_dylibs.append(
                    (self._lc_str(off), cmd == LC_LOAD_WEAK_DYLIB))
            elif cmd == LC_ID_DYLIB:
                self.id_dylib = self._lc_str(off)
            elif cmd == LC_RPATH:
                self.rpaths.append(self._lc_str(off))
            elif cmd == LC_BUILD_VERSION:
                self.platform = struct.unpack_from('<I', self.data, off + 8)[0]
                self.minos = max(self.minos or 0, struct.unpack_from(
                    '<I', self.data, off + 12)[0])
            elif cmd == LC_VERSION_MIN_MACOSX:
                self.minos = max(self.minos or 0, struct.unpack_from(
                    '<I', self.data, off + 8)[0])
            elif cmd == LC_DYLD_CHAINED_FIXUPS:
                self.chained = True
            off += size
        if stroff is not None:
            self._symbols(symoff, nsyms, stroff)

    def _symbols(self, symoff, nsyms, stroff):
        if self.bits == 64:
            entry, fmt = 16, '<IBBHQ'
        else:
            entry, fmt = 12, '<IBBHI'
        for i in range(nsyms):
            at = self.base + symoff + i * entry
            n_strx, n_type, _, n_desc, _ = struct.unpack_from(
                fmt, self.data, at)
            if not n_type & N_EXT:
                continue
            kind = n_type & N_TYPE
            if kind in (N_UNDF, N_PBUD):
                ordinal = ((n_desc >> 8) if self.bits == 64
                           else n_desc) & 0xFF
                self.undefined.append((
                    self._str_at(stroff + n_strx),
                    ordinal,
                    bool(n_desc & N_WEAK_REF)))
            elif kind in (N_ABS, N_SECT):
                self.exported.add(self._str_at(stroff + n_strx))


def load_slices(data):
    magic = struct.unpack_from('<I', data, 0)[0]
    if magic in (MH_MAGIC, MH_MAGIC_64):
        return [Slice(data, 0, 64 if magic == MH_MAGIC_64 else 32)]
    if magic not in (FAT_MAGIC, FAT_MAGIC_64):
        raise ValueError('not mach-o')
    out = []
    nfat = struct.unpack_from('>I', data, 4)[0]
    entry = 20 if magic == FAT_MAGIC else 32
    for i in range(nfat):
        at = 8 + i * entry
        if magic == FAT_MAGIC:
            off = struct.unpack_from('>I', data, at + 8)[0]
        else:
            off = struct.unpack_from('>Q', data, at + 8)[0]
        smagic = struct.unpack_from('<I', data, off)[0]
        if smagic in (MH_MAGIC, MH_MAGIC_64):
            out.append(Slice(data, off, 64 if smagic == MH_MAGIC_64 else 32))
    return out


def is_macho(path):
    try:
        with open(path, 'rb') as f:
            head = f.read(4)
    except OSError:
        return False
    if len(head) < 4:
        return False
    return struct.unpack('<I', head)[0] in (
        MH_MAGIC, MH_MAGIC_64, FAT_MAGIC, FAT_MAGIC_64)


class MachoFile(object):
    def __init__(self, path):
        self.path = os.path.abspath(path)
        with open(path, 'rb') as f:
            self.data = f.read()
        self.slices = load_slices(self.data)


class ImageCache(object):
    def __init__(self):
        self.files = {}

    def get(self, path):
        key = os.path.abspath(path)
        if key not in self.files:
            self.files[key] = MachoFile(key)
        return self.files[key]


def load_db(path):
    opener = gzip.open if open(path, 'rb').read(2) == b'\x1f\x8b' else open
    own = {}
    reexp = {}
    with opener(path, 'rt', encoding='latin-1') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            parts = line.split()
            if len(parts) < 2:
                raise ValueError('bad db line: %r' % line)
            lib = parts[0].lower()
            sym = parts[1]
            if sym == 'REEXPORT':
                reexp.setdefault(lib, []).append(parts[2].lower())
            elif sym.startswith('$ld$'):
                continue
            else:
                own.setdefault(lib, set()).add(sym)
    cache = {}

    def exports(lib, stack=()):
        if lib in cache:
            return cache[lib]
        if lib in stack:
            return set()
        out = set(own.get(lib, ()))
        for other in reexp.get(lib, ()):
            out |= exports(other, stack + (lib,))
        cache[lib] = out
        return out

    return exports, set(own) | set(reexp)


def collect_images(root):
    root = os.path.abspath(root)
    main = None
    if os.path.isfile(root):
        return [root], root
    macos = os.path.join(root, 'Contents', 'MacOS')
    if os.path.isdir(macos):
        for name in sorted(os.listdir(macos)):
            p = os.path.join(macos, name)
            if os.path.isfile(p):
                main = p
                break
    images = []
    for dirpath, _, filenames in os.walk(root):
        for name in filenames:
            p = os.path.join(dirpath, name)
            if is_macho(p):
                images.append(os.path.abspath(p))
    return images, main


class Resolver(object):
    def __init__(self, main, image_cache):
        self.main = main
        self.image_cache = image_cache
        self.main_rpaths = []
        if main:
            for s in image_cache.get(main).slices:
                self.main_rpaths += s.rpaths

    def _base(self, rp, image_path):
        if rp == '@executable_path' or rp.startswith('@executable_path/'):
            if not self.main:
                return None
            tail = rp[len('@executable_path'):]
            return os.path.dirname(self.main) + tail.replace('/', os.sep)
        if rp == '@loader_path' or rp.startswith('@loader_path/'):
            tail = rp[len('@loader_path'):]
            return os.path.dirname(image_path) + tail.replace('/', os.sep)
        return rp

    def candidates(self, name, image_path, image_rpaths):
        if not name.startswith('@'):
            return [name]
        out = []
        if name.startswith('@rpath/'):
            rest = name[len('@rpath/'):]
            bases = list(image_rpaths) + self.main_rpaths
            for rp in bases:
                base = self._base(rp, image_path)
                if base is not None:
                    out.append(os.path.join(base, rest))
        elif name.startswith('@executable_path/'):
            base = self._base('@executable_path', image_path)
            if base is not None:
                out.append(os.path.join(
                    base, name[len('@executable_path/'):]))
        elif name.startswith('@loader_path/'):
            base = self._base('@loader_path', image_path)
            out.append(os.path.join(base, name[len('@loader_path/'):]))
        return out

    def resolve(self, name, image_path, image_rpaths):
        fallback = None
        for cand in self.candidates(name, image_path, image_rpaths):
            if os.path.isfile(cand):
                return 'bundle', cand
            posix = cand.replace('\\', '/')
            if posix.startswith('/usr/lib/') \
                    or posix.startswith('/usr/local/lib/') \
                    or posix.startswith('/System/Library/'):
                fallback = fallback or ('system', posix)
        return fallback or ('unresolved', name)


def check(root, db_path):
    exports, known = load_db(db_path)
    cache = ImageCache()
    images, main = collect_images(root)
    bundle_root = os.path.abspath(root)
    if not images:
        print('MACOS GATE: bundle=%s db=%s target=%s' % (
            root, db_path, TARGET_TEXT))
        print('NO-MACHO-FOUND')
        print('GATE: FAIL (1 problem(s), 0 weak)')
        return 1
    resolver = Resolver(main, cache)
    problems = []
    weak_report = []
    all_syms = None
    bundle_syms = None
    bundled_exports = {}
    main_exported = set()
    nlibs = nsyms = nslices = 0
    for path in images:
        mf = cache.get(path)
        rel = os.path.relpath(path, os.path.abspath(root))
        nslices += len(mf.slices)
        exported_here = set()
        for s in mf.slices:
            exported_here |= s.exported
            if s.minos and ver_tuple(s.minos) > TARGET:
                problems.append('MINOS-ABOVE-%s %s %s' % (
                    TARGET_TEXT, rel, ver_text(s.minos)))
            if s.platform is not None and s.platform != PLATFORM_MACOS:
                problems.append('PLATFORM-NOT-MACOS %s %d' % (
                    rel, s.platform))
            if s.chained:
                problems.append('CHAINED-FIXUPS %s' % rel)
        if path == main:
            main_exported = exported_here
        for s in mf.slices:
            for name, weak in s.load_dylibs:
                nlibs += 1
                kind, val = resolver.resolve(name, path, s.rpaths)
                if kind == 'bundle':
                    continue
                tag = 'LIB-NOT-IN-DB' if kind == 'system' else 'LIB-NOT-FOUND'
                if val.lower() not in known:
                    if weak:
                        weak_report.append((tag, name))
                    else:
                        problems.append('%s %s' % (tag, name))
            for name, ordinal, weak in s.undefined:
                nsyms += 1
                if ordinal in (0, DYNAMIC_LOOKUP_ORDINAL):
                    if all_syms is None:
                        all_syms = set()
                        for lib in known:
                            all_syms |= exports(lib)
                    target = 'dynamic'
                    ok = name in all_syms
                    if not ok:
                        if bundle_syms is None:
                            bundle_syms = set()
                            for p in images:
                                for sl in cache.get(p).slices:
                                    bundle_syms |= sl.exported
                        ok = name in bundle_syms
                elif ordinal == EXECUTABLE_ORDINAL:
                    target = 'executable'
                    ok = name in main_exported
                else:
                    idx = ordinal - 1
                    if idx >= len(s.load_dylibs):
                        problems.append('BAD-ORDINAL %s %d %s' % (
                            rel, ordinal, name))
                        continue
                    tname = s.load_dylibs[idx][0]
                    kind, val = resolver.resolve(tname, path, s.rpaths)
                    if kind == 'bundle':
                        target = 'bundle:%s' % os.path.relpath(
                            val, bundle_root).replace(os.sep, '/')
                        if val not in bundled_exports:
                            bundled_exports[val] = set()
                            for sl in cache.get(val).slices:
                                bundled_exports[val] |= sl.exported
                        ok = name in bundled_exports[val]
                    else:
                        target = tname.lower()
                        if target not in known:
                            if weak:
                                weak_report.append(('WEAK-LIB', name))
                            else:
                                problems.append('LIB-NOT-IN-DB %s' % target)
                            continue
                        ok = name in exports(target)
                if not ok:
                    if weak:
                        weak_report.append((target, name))
                    else:
                        problems.append('MISSING %s %s' % (target, name))
    print('MACOS GATE: bundle=%s db=%s target=%s' % (
        root, db_path, TARGET_TEXT))
    print('images: %d files / %d slices, load dylib refs: %d, '
          'undefined: %d' % (len(images), nslices, nlibs, nsyms))
    for line in problems:
        print(line)
    for lib, name in weak_report[:WEAK_PRINT_LIMIT]:
        print('WEAK-NO-EXPORT %s %s' % (lib, name))
    if len(weak_report) > WEAK_PRINT_LIMIT:
        print('... %d more weak' % (len(weak_report) - WEAK_PRINT_LIMIT))
    print('GATE: %s (%d problem(s), %d weak)' % (
        'FAIL' if problems else 'PASS', len(problems), len(weak_report)))
    return 1 if problems else 0


def exports_cmd(paths):
    for path in paths:
        mf = MachoFile(path)
        for s in mf.slices:
            ident = s.id_dylib or mf.path
            for name in sorted(s.exported):
                print('%s %s' % (ident, name))
    return 0


def main(argv):
    if len(argv) >= 4 and argv[1] == 'check':
        return check(argv[2], argv[3])
    if len(argv) >= 3 and argv[1] == 'exports':
        return exports_cmd(argv[2:])
    print('usage: check_macho.py check <bundle|file> <db> | '
          'exports <file>...')
    return 2


if __name__ == '__main__':
    sys.exit(main(sys.argv))
