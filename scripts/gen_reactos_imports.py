#!/usr/bin/env python3
# gen_reactos_imports.py — resolve ReactOS smss.exe's ntdll imports against ntdll.dll's export
# table (both real binaries) and emit a compact patch table the executive applies at runtime.
#
# The resolution (import name -> ntdll export RVA) is a static property of the two binaries, so
# it's done here at build time; the executive reads the table and patches smss's IAT live (each
# slot := NTDLL_BASE + export_rva) so smss's ntdll calls land in real ntdll.
#
# Output (imports.bin, little-endian): u32 count, then count * (u32 iat_file_offset, u32 export_rva).
# iat_file_offset is the byte offset WITHIN smss.exe's file of the 8-byte IAT slot (so the
# executive patches its in-memory copy of the file directly).
import struct, sys

def sections(d):
    e = struct.unpack_from("<I", d, 0x3c)[0]
    n = struct.unpack_from("<H", d, e + 6)[0]
    so = e + 24 + struct.unpack_from("<H", d, e + 20)[0]
    secs = []
    for i in range(n):
        o = so + i * 40
        vs, va, rs, rp = struct.unpack_from("<IIII", d, o + 8)
        secs.append((va, vs, rp, rs))
    return e, secs

def r2o(secs, rva):
    for va, vs, rp, rs in secs:
        if va <= rva < va + max(vs, rs):
            return rp + (rva - va)
    return None

def ntdll_exports(d):
    e, secs = sections(d)
    exp_rva = struct.unpack_from("<I", d, e + 24 + 112 + 0 * 8)[0]
    o = r2o(secs, exp_rva)
    base, nfun, nname, af, an, ao = struct.unpack_from("<IIIIII", d, o + 16)
    afo, ano, aoo = r2o(secs, af), r2o(secs, an), r2o(secs, ao)
    out = {}
    for i in range(nname):
        nr = struct.unpack_from("<I", d, ano + i * 4)[0]
        no = r2o(secs, nr)
        nm = d[no:d.index(b"\0", no)].decode("latin1")
        ordi = struct.unpack_from("<H", d, aoo + i * 2)[0]
        out[nm] = struct.unpack_from("<I", d, afo + ordi * 4)[0]
    return out

def smss_ntdll_imports(d):
    e, secs = sections(d)
    imp_rva = struct.unpack_from("<I", d, e + 24 + 112 + 1 * 8)[0]
    o = r2o(secs, imp_rva)
    res = []
    while True:
        oft, tds, fc, namer, ft = struct.unpack_from("<IIIII", d, o)
        if oft == 0 and namer == 0 and ft == 0:
            break
        no = r2o(secs, namer)
        dll = d[no:d.index(b"\0", no)].decode("latin1").lower()
        to, iat_rva = r2o(secs, ft), ft
        while True:
            v = struct.unpack_from("<Q", d, to)[0]
            if v == 0:
                break
            if not (v & (1 << 63)):
                hn = r2o(secs, v & 0x7fffffff)
                nm = d[hn + 2:d.index(b"\0", hn + 2)].decode("latin1")
                if dll == "ntdll.dll":
                    res.append((iat_rva, nm))
            to += 8
            iat_rva += 8
        o += 20
    return secs, res

smss = open(sys.argv[1], "rb").read()
ntdll = open(sys.argv[2], "rb").read()
out = sys.argv[3]

exports = ntdll_exports(ntdll)
secs, imports = smss_ntdll_imports(smss)

entries = []
missing = []
for iat_rva, name in imports:
    rva = exports.get(name)
    if rva is None:
        missing.append(name)
        continue
    entries.append((r2o(secs, iat_rva), rva))

buf = struct.pack("<I", len(entries))
for off, rva in entries:
    buf += struct.pack("<II", off, rva)
open(out, "wb").write(buf)
print("resolved %d/%d ntdll imports (%d bytes)%s" %
      (len(entries), len(imports), len(buf),
       ("; MISSING: " + ",".join(missing)) if missing else ""))
