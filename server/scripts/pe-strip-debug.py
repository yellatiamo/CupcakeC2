#!/usr/bin/env python3
"""Strip PE debug-directory residue (RSDS/PDB build path).

Even with `strip = "symbols"`, MSVC-linked PEs keep a CodeView (RSDS)
debug-directory entry whose record embeds the absolute .pdb path of the
build machine - a high-signal forensic string. This tool:

  1. zeroes every debug payload blob (CodeView/RSDS PDB path, POGO, ...),
  2. zeroes the debug-directory entries themselves,
  3. clears IMAGE_DIRECTORY_ENTRY_DEBUG (RVA+Size) in the optional header.

Both structured parsers and raw string scans then lose the build path.
File size and checksums of other sections are unchanged.

Usage:  python pe_strip_debug.py <file> [<file> ...]
Exit:   0 on success (including "nothing to strip"), 1 on error.
"""
import struct
import sys


def strip(path):
    with open(path, 'r+b') as f:
        data = bytearray(f.read())

    if data[:2] != b'MZ':
        raise ValueError('not a PE file (missing MZ)')
    e_lfanew = struct.unpack_from('<I', data, 0x3C)[0]
    if data[e_lfanew:e_lfanew + 4] != b'PE\x00\x00':
        raise ValueError('missing PE signature')

    coff = e_lfanew + 4
    _machine, nsec, _ts, _sym, _nsym, optsize, _char = struct.unpack_from('<HHIIIHH', data, coff)
    opt = coff + 20
    magic = struct.unpack_from('<H', data, opt)[0]
    if magic == 0x20B:        # PE32+
        ddoff = opt + 112
    elif magic == 0x10B:      # PE32
        ddoff = opt + 96
    else:
        raise ValueError('bad optional-header magic 0x%04x' % magic)

    ndirs = struct.unpack_from('<I', data, ddoff - 4)[0]
    if ndirs <= 6:
        print('%s: no data directory slot for debug - nothing to do' % path)
        return

    dbg_ent = ddoff + 6 * 8   # IMAGE_DIRECTORY_ENTRY_DEBUG == 6
    dbg_rva, dbg_size = struct.unpack_from('<II', data, dbg_ent)
    if dbg_rva == 0 or dbg_size == 0:
        print('%s: debug directory already empty' % path)
        return

    # section table -> RVA to file offset
    sec_off = opt + optsize
    sections = []
    for i in range(nsec):
        o = sec_off + i * 40
        vs, va, rs, ro = struct.unpack_from('<IIII', data, o + 8)
        sections.append((va, max(vs, rs), ro))

    def r2o(rva):
        for va, span, ro in sections:
            if va <= rva < va + span:
                return ro + (rva - va)
        raise ValueError('RVA 0x%08x not covered by any section' % rva)

    off = r2o(dbg_rva)
    wiped = 0
    for i in range(dbg_size // 28):
        e = off + i * 28
        _ch, _ts2, _maj, _min, typ, sod, arva, prow = struct.unpack_from('<IIHHIIII', data, e)
        if sod > 0:
            # Wipe the pointed-to debug payload (CodeView/RSDS, POGO, ...).
            rec = prow if prow else r2o(arva)
            data[rec:rec + sod] = b'\x00' * sod
            wiped += 1

    # remove structured references: directory entries + optional-header slot
    data[off:off + dbg_size] = b'\x00' * dbg_size
    data[dbg_ent:dbg_ent + 8] = b'\x00' * 8

    with open(path, 'wb') as f:
        f.write(data)
    print('%s: wiped %d debug payload(s), cleared debug directory (%d bytes)'
          % (path, wiped, dbg_size))


def main(argv):
    if len(argv) < 2:
        print(__doc__.strip().splitlines()[0])
        print('usage: python pe_strip_debug.py <file> [<file> ...]')
        return 1
    rc = 0
    for p in argv[1:]:
        try:
            strip(p)
        except Exception as ex:
            print('%s: ERROR: %s' % (p, ex))
            rc = 1
    return rc


if __name__ == '__main__':
    sys.exit(main(sys.argv))
