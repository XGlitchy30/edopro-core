#!/usr/bin/env python3
"""
verify_cores.py - Static sanity checks for EDOPro ocgcore shared libraries.

Purpose
-------
The EDOPro client (gframe/dllinterface.cpp) picks ONE file name per platform
and loads it with LoadLibrary/dlopen. If the file under that name was built
for the wrong architecture, the wrong OS, or lacks the exported API, the
client silently rejects it and keeps whatever core it already had. This
script inspects the binaries WITHOUT running them (so it works for every
target from any host) and fails loudly instead.

Only the Python standard library is used. Tested with Python 3.8+.

Usage
-----
    python verify_cores.py DIR
    python verify_cores.py DIR --reference path/to/EDOPro/repositories/delta-bagooska/bin
    python verify_cores.py DIR --load --expect-version 11.0
    python verify_cores.py DIR --windows-arch x64

    DIR            folder holding the built cores (the folder your core_path points to)
    --reference    folder with known-good cores (e.g. the official DeltaBagooska bin/);
                   format, bitness, CPU and target OS of same-named files must match
    --windows-arch expected machine for ocgcore.dll: x86 (default), x64, arm64
    --load         additionally load the core matching THIS host (and this Python's
                   bitness) and call OCG_GetVersion
    --expect-version MAJOR.MINOR | reference
                   value OCG_GetVersion must report (used with --load); "reference"
                   takes it from the host-native core in --reference, i.e. the version
                   the current official client accepts

Exit code: 0 if no errors, 1 if at least one error was found.
"""

import argparse
import os
import platform
import struct
import subprocess
import sys

# =====================
# EXPECTED BY THE CLIENT
# =====================

# Every symbol the client resolves by name (edopro gframe/ocgcore_functions.inl)
# A missing export makes Core::Load() return nullptr
REQUIRED_EXPORTS = [
    "OCG_GetVersion", "OCG_CreateDuel", "OCG_DestroyDuel", "OCG_DuelNewCard",
    "OCG_StartDuel", "OCG_DuelProcess", "OCG_DuelGetMessage", "OCG_DuelSetResponse",
    "OCG_LoadScript", "OCG_DuelQueryCount", "OCG_DuelQuery",
    "OCG_DuelQueryLocation", "OCG_DuelQueryField",
]

# file name -> expected properties
#   fmt      : "pe" | "elf" | "macho"
#   bits     : 32 | 64 (ELF/PE)
#   cpu      : normalised CPU name
#   os       : "linux" | "android" (ELF only; decides which libc the file may depend on)
#   arches   : required Mach-O slices (a universal binary must contain all of them)
#   align    : (bytes, "error"|"warn") minimum LOAD segment alignment; smaller values
#              cannot be mapped on kernels using larger pages (16 KiB Android 15+ devices,
#              16/64 KiB aarch64 Linux kernels)
#   core     : True for the files the official DeltaBagooska bin/ ships
EXPECTED = {
    "libocgcore.so":         dict(fmt="elf", bits=64, cpu="x86_64",  os="linux",   core=True),
    "libocgcore.aarch64.so": dict(fmt="elf", bits=64, cpu="aarch64", os="linux",   core=True,
                                  align=(0x10000, "warn")),
    "libocgcorev7.so":       dict(fmt="elf", bits=32, cpu="arm",     os="android", core=True),
    "libocgcorev8.so":       dict(fmt="elf", bits=64, cpu="aarch64", os="android", core=True,
                                  align=(0x4000, "error")),
    "libocgcorex86.so":      dict(fmt="elf", bits=32, cpu="x86",     os="android", core=True),
    "libocgcorex64.so":      dict(fmt="elf", bits=64, cpu="x86_64",  os="android", core=False,
                                  align=(0x4000, "warn")),
    "libocgcore.dylib":      dict(fmt="macho", arches={"x86_64", "arm64"}, core=True),
    "libocgcore-ios.dylib":  dict(fmt="macho", arches={"arm64"}, core=False),
    "libocgcore.haiku.so":   dict(fmt="elf", bits=64, cpu="x86_64",  os="haiku",   core=False),
    # ocgcore.dll is filled in from --windows-arch in main()
}

WINDOWS_ARCHES = {  # --windows-arch value -> (PE machine name, bits)
    "x86": ("x86", 32), "x64": ("x86_64", 64), "arm64": ("aarch64", 64),
}

# Shared libraries a core may depend on, per target OS.
ALLOWED_NEEDED = {
    "linux": {"libc.so.6", "libm.so.6", "libdl.so.2", "libpthread.so.0", "librt.so.1",
              "ld-linux-x86-64.so.2", "ld-linux-aarch64.so.1", "libc.musl-x86_64.so.1",
              "libc.musl-aarch64.so.1"},
    "android": {"libc.so", "libm.so", "libdl.so", "liblog.so"},
    "haiku": {"libroot.so"},
}

ELF_MACHINES = {3: "x86", 8: "mips", 40: "arm", 62: "x86_64", 183: "aarch64", 243: "riscv"}
PE_MACHINES = {0x14C: "x86", 0x8664: "x86_64", 0xAA64: "aarch64", 0x1C4: "arm"}
MACHO_CPUS = {0x7: "i386", 0x01000007: "x86_64", 0xC: "arm", 0x0100000C: "arm64"}


class Report:
    """Collects findings for one file."""

    def __init__(self, name):
        self.name = name
        self.errors, self.warnings, self.infos = [], [], []

    def error(self, msg):
        self.errors.append(msg)

    def warn(self, msg):
        self.warnings.append(msg)

    def info(self, msg):
        self.infos.append(msg)

    def print(self):
        status = "FAIL" if self.errors else ("WARN" if self.warnings else "OK")
        print(f"[{status:4}] {self.name}")
        for m in self.infos:
            print(f"         info : {m}")
        for m in self.warnings:
            print(f"         WARN : {m}")
        for m in self.errors:
            print(f"         ERROR: {m}")


# =====================
# PE (WINDOWS)
# =====================

def parse_pe(data):
    if data[:2] != b"MZ":
        raise ValueError("not a PE file")
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if data[e_lfanew:e_lfanew + 4] != b"PE\0\0":
        raise ValueError("missing PE signature")
    coff = e_lfanew + 4
    machine, nsect, _, _, _, opt_size, characteristics = struct.unpack_from("<HHIIIHH", data, coff)
    opt = coff + 20
    magic = struct.unpack_from("<H", data, opt)[0]
    if magic == 0x10B:
        bits, dd_off, n_rva_off = 32, 96, 92
    elif magic == 0x20B:
        bits, dd_off, n_rva_off = 64, 112, 108
    else:
        raise ValueError(f"unknown optional header magic {magic:#x}")
    n_rva = struct.unpack_from("<I", data, opt + n_rva_off)[0]

    sections = []
    sec = opt + opt_size
    for i in range(nsect):
        _, vsize, va, rawsize, rawptr = struct.unpack_from("<8sIIII", data, sec + 40 * i)
        sections.append((va, max(vsize, rawsize), rawptr))

    def rva2off(rva):
        for va, size, rawptr in sections:
            if va <= rva < va + size:
                return rva - va + rawptr
        raise ValueError(f"RVA {rva:#x} not in any section")

    def cstr(off):
        return data[off:data.index(b"\0", off)].decode("ascii", "replace")

    def ddir(index):
        if index >= n_rva:
            return 0, 0
        return struct.unpack_from("<II", data, opt + dd_off + 8 * index)

    exports = set()
    exp_rva, exp_size = ddir(0)
    if exp_rva:
        e = rva2off(exp_rva)
        n_names = struct.unpack_from("<I", data, e + 24)[0]
        names_rva = struct.unpack_from("<I", data, e + 32)[0]
        names = rva2off(names_rva)
        for i in range(n_names):
            exports.add(cstr(rva2off(struct.unpack_from("<I", data, names + 4 * i)[0])))

    imports = []
    imp_rva, _ = ddir(1)
    if imp_rva:
        d = rva2off(imp_rva)
        while True:
            desc = struct.unpack_from("<IIIII", data, d)
            if not any(desc):
                break
            name = cstr(rva2off(desc[3]))
            if name.lower() not in (i.lower() for i in imports):
                imports.append(name)
            d += 20

    return dict(fmt="pe", bits=bits, cpu=PE_MACHINES.get(machine, f"unknown({machine:#x})"),
                is_dll=bool(characteristics & 0x2000), exports=exports, needed=imports)


# ====================
# ELF (Linux / Android / Haiku)
# ====================

def parse_elf(data):
    if data[:4] != b"\x7fELF":
        raise ValueError("not an ELF file")
    ei_class, ei_data = data[4], data[5]
    if ei_data != 1:
        raise ValueError("big-endian ELF is not an EDOPro target")
    bits = {1: 32, 2: 64}[ei_class]
    if bits == 32:
        (e_type, e_machine, _, _, e_phoff, e_shoff, _, _, e_phentsize, e_phnum,
         e_shentsize, e_shnum, _) = struct.unpack_from("<HHIIIIIHHHHHH", data, 16)
    else:
        (e_type, e_machine, _, _, e_phoff, e_shoff, _, _, e_phentsize, e_phnum,
         e_shentsize, e_shnum, _) = struct.unpack_from("<HHIQQQIHHHHHH", data, 16)

    # Program headers: LOAD alignment, DYNAMIC, NOTE.
    loads, dynamic, notes = [], None, []
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        if bits == 32:
            p_type, p_offset, p_vaddr, _, p_filesz, _, _, p_align = struct.unpack_from("<8I", data, off)
        else:
            p_type, _, p_offset, p_vaddr, _, p_filesz, _, p_align = struct.unpack_from("<IIQQQQQQ", data, off)
        if p_type == 1:
            loads.append((p_vaddr, p_offset, p_filesz, p_align))
        elif p_type == 2:
            dynamic = (p_offset, p_filesz)
        elif p_type == 4:
            notes.append((p_offset, p_filesz))

    def vaddr2off(addr):
        for vaddr, offset, filesz, _ in loads:
            if vaddr <= addr < vaddr + filesz:
                return addr - vaddr + offset
        raise ValueError(f"vaddr {addr:#x} not in any LOAD segment")

    # Notes: bionic's crtbegin_so.o adds an "Android" note to every NDK-built library.
    note_owners = set()
    for off, size in notes:
        p, end = off, off + size
        while p + 12 <= end:
            namesz, descsz, _ = struct.unpack_from("<III", data, p)
            name = data[p + 12:p + 12 + namesz].rstrip(b"\0").decode("ascii", "replace")
            note_owners.add(name)
            p += 12 + ((namesz + 3) & ~3) + ((descsz + 3) & ~3)

    # Dynamic section: NEEDED, SONAME, string/symbol tables.
    needed_idx, soname_idx, dt = [], None, {}
    if dynamic:
        entsize = 8 if bits == 32 else 16
        fmt = "<iI" if bits == 32 else "<qQ"
        for i in range(dynamic[1] // entsize):
            tag, val = struct.unpack_from(fmt, data, dynamic[0] + i * entsize)
            if tag == 0:
                break
            if tag == 1:
                needed_idx.append(val)
            elif tag == 14:
                soname_idx = val
            else:
                dt.setdefault(tag, val)

    strtab = vaddr2off(dt[5]) if 5 in dt else None
    strsz = dt.get(10, 0)

    def dynstr(idx):
        s = strtab + idx
        return data[s:data.index(b"\0", s)].decode("ascii", "replace")

    needed = [dynstr(i) for i in needed_idx] if strtab is not None else []
    soname = dynstr(soname_idx) if (strtab is not None and soname_idx is not None) else None

    # Dynamic symbols. Prefer the section header table (kept by strip);
    # fall back to "dynsym ends where dynstr starts", which holds for common linkers.
    syms = []
    symsize = 16 if bits == 32 else 24
    dynsym_range = None
    if e_shoff and e_shnum:
        for i in range(e_shnum):
            off = e_shoff + i * e_shentsize
            if bits == 32:
                _, sh_type, _, _, sh_offset, sh_size, _, _, _, _ = struct.unpack_from("<10I", data, off)
            else:
                _, sh_type, _, _, sh_offset, sh_size, _, _, _, _ = struct.unpack_from("<IIQQQQIIQQ", data, off)
            if sh_type == 11:  # SHT_DYNSYM
                dynsym_range = (sh_offset, sh_size)
    if dynsym_range is None and 6 in dt and 5 in dt and dt[5] > dt[6]:
        dynsym_range = (vaddr2off(dt[6]), dt[5] - dt[6])
    exports = set()
    if dynsym_range and strtab is not None:
        start, size = dynsym_range
        for i in range(size // symsize):
            off = start + i * symsize
            if bits == 32:
                st_name, _, _, st_info, st_other, st_shndx = struct.unpack_from("<IIIBBH", data, off)
            else:
                st_name, st_info, st_other, st_shndx, _, _ = struct.unpack_from("<IBBHQQ", data, off)
            bind, vis = st_info >> 4, st_other & 3
            if st_shndx != 0 and bind in (1, 2, 10) and vis in (0, 3):
                exports.add(dynstr(st_name))

    # Highest GLIBC symbol version referenced (portability of glibc builds).
    glibc = []
    if strtab is not None and strsz:
        for s in data[strtab:strtab + strsz].split(b"\0"):
            if s.startswith(b"GLIBC_2."):
                try:
                    glibc.append(tuple(int(x) for x in s[6:].decode().split(".")))
                except ValueError:
                    pass

    if "Android" in note_owners or ("libc.so" in needed):
        target_os = "android"
    elif "libroot.so" in needed:
        target_os = "haiku"
    else:
        target_os = "linux"

    return dict(fmt="elf", bits=bits, cpu=ELF_MACHINES.get(e_machine, f"unknown({e_machine})"),
                is_dll=(e_type == 3), exports=exports, needed=needed, soname=soname,
                os=target_os, min_load_align=min((a for *_, a in loads), default=0),
                glibc_max=max(glibc) if glibc else None)


# ====================
# Mach-O (macOS / iOS)
# ====================

def _uleb(data, p):
    result = shift = 0
    while True:
        b = data[p]
        p += 1
        result |= (b & 0x7F) << shift
        shift += 7
        if not b & 0x80:
            return result, p


def _walk_export_trie(data, start, size):
    """Yield exported symbol names from an LC_DYLD_INFO / LC_DYLD_EXPORTS_TRIE trie."""
    out, stack = [], [(start, "")]
    seen = set()
    while stack:
        node, prefix = stack.pop()
        if node in seen or node >= start + size:
            continue
        seen.add(node)
        term_size, p = _uleb(data, node)
        if term_size:
            out.append(prefix)
        p += term_size
        n_children = data[p]
        p += 1
        for _ in range(n_children):
            end = data.index(b"\0", p)
            edge = data[p:end].decode("ascii", "replace")
            child, p = _uleb(data, end + 1)
            stack.append((start + child, prefix + edge))
    return out


def _parse_macho_slice(data):
    magic = struct.unpack_from("<I", data, 0)[0]
    if magic == 0xFEEDFACF:
        hdr = 32
    elif magic == 0xFEEDFACE:
        hdr = 28
    else:
        raise ValueError("not a little-endian Mach-O slice")
    cputype, _, filetype, ncmds, _, _ = struct.unpack_from("<iiIIII", data, 4)
    p = hdr
    exports, deps, signed, minos = set(), [], False, None
    trie, symtab = None, None
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", data, p)
        if cmd == 0x2:                              # LC_SYMTAB
            symtab = struct.unpack_from("<IIII", data, p + 8)
        elif cmd in (0x22, 0x80000022):             # LC_DYLD_INFO(_ONLY)
            exp_off, exp_size = struct.unpack_from("<II", data, p + 40)
            if exp_size:
                trie = (exp_off, exp_size)
        elif cmd == 0x80000033:                     # LC_DYLD_EXPORTS_TRIE
            trie = struct.unpack_from("<II", data, p + 8)
        elif cmd in (0xC, 0x18, 0x1F, 0x23):        # LC_LOAD_(WEAK_|REEXPORT_|UPWARD_)DYLIB
            name_off = struct.unpack_from("<I", data, p + 8)[0]
            raw = data[p + name_off:p + cmdsize]
            deps.append(raw.split(b"\0")[0].decode("utf-8", "replace"))
        elif cmd == 0x1D:                           # LC_CODE_SIGNATURE
            signed = True
        elif cmd == 0x32:                           # LC_BUILD_VERSION
            v = struct.unpack_from("<I", data, p + 12)[0]
            minos = f"{v >> 16}.{(v >> 8) & 0xFF}.{v & 0xFF}"
        elif cmd in (0x24, 0x25):                   # LC_VERSION_MIN_MACOSX / _IPHONEOS
            v = struct.unpack_from("<I", data, p + 8)[0]
            minos = f"{v >> 16}.{(v >> 8) & 0xFF}.{v & 0xFF}"
        p += cmdsize

    if trie:
        exports.update(n[1:] if n.startswith("_") else n for n in _walk_export_trie(data, *trie))
    elif symtab:
        symoff, nsyms, stroff, _ = symtab
        entsize = 16 if hdr == 32 else 12
        for i in range(nsyms):
            off = symoff + i * entsize
            n_strx, n_type = struct.unpack_from("<IB", data, off)
            if not (n_type & 0xE0) and (n_type & 0x01) and (n_type & 0x0E) == 0x0E:
                s = data[stroff + n_strx:data.index(b"\0", stroff + n_strx)].decode("ascii", "replace")
                exports.add(s[1:] if s.startswith("_") else s)

    return dict(cpu=MACHO_CPUS.get(cputype, f"unknown({cputype:#x})"), is_dll=(filetype == 6),
                exports=exports, needed=deps, signed=signed, minos=minos)


def parse_macho(data):
    magic_be = struct.unpack_from(">I", data, 0)[0]
    slices = []
    if magic_be in (0xCAFEBABE, 0xCAFEBABF):       
        n = struct.unpack_from(">I", data, 4)[0]
        for i in range(n):
            if magic_be == 0xCAFEBABE:
                _, _, off, size, _ = struct.unpack_from(">iiIII", data, 8 + 20 * i)
            else:
                _, _, off, size, _, _ = struct.unpack_from(">iiQQII", data, 8 + 32 * i)
            slices.append(_parse_macho_slice(data[off:off + size]))
    else:
        slices.append(_parse_macho_slice(data))
    return dict(fmt="macho", slices=slices, arches={s["cpu"] for s in slices})


def parse_any(path):
    with open(path, "rb") as f:
        data = f.read()
    if data[:2] == b"MZ":
        return parse_pe(data)
    if data[:4] == b"\x7fELF":
        return parse_elf(data)
    if data[:4] in (b"\xca\xfe\xba\xbe", b"\xca\xfe\xba\xbf", b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe"):
        return parse_macho(data)
    raise ValueError("unrecognised binary format")


def describe(info):
    if info["fmt"] == "macho":
        return "Mach-O [" + ", ".join(sorted(info["arches"])) + "]"
    extra = f", {info['os']}" if info["fmt"] == "elf" else ""
    return f"{info['fmt'].upper()}{info['bits']} {info['cpu']}{extra}"


# ====================
# Checks
# ====================

def check_exports(rep, exports, where=""):
    missing = [s for s in REQUIRED_EXPORTS if s not in exports]
    if missing:
        rep.error(f"{where}missing exported API symbols: {', '.join(missing)} "
                  "(built without OCGCORE_EXPORT_FUNCTIONS, or API differs from the client)")


def check_file(path, exp):
    rep = Report(os.path.basename(path))
    try:
        info = parse_any(path)
    except Exception as exc:  # noqa: BLE001 - report any parse failure as an error
        rep.error(f"cannot parse: {exc}")
        return rep, None
    rep.info(describe(info))

    if info["fmt"] != exp["fmt"]:
        rep.error(f"wrong binary format: expected {exp['fmt'].upper()}, found {info['fmt'].upper()}")
        return rep, info

    if info["fmt"] in ("pe", "elf"):
        if info["bits"] != exp["bits"] or info["cpu"] != exp["cpu"]:
            rep.error(f"wrong architecture: expected {exp['bits']}-bit {exp['cpu']}, "
                      f"found {info['bits']}-bit {info['cpu']}")
        if not info["is_dll"]:
            rep.error("not a shared library / DLL")
        check_exports(rep, info["exports"])

    if info["fmt"] == "pe":
        runtime = [d for d in info["needed"] if d.lower().startswith(("vcruntime", "msvcp", "api-ms-win-crt", "ucrtbase"))]
        debug_rt = [d for d in runtime if d.lower().endswith("d.dll")]
        if debug_rt:
            rep.error(f"depends on the DEBUG C runtime ({', '.join(debug_rt)}), absent on end-user machines")
        elif runtime:
            rep.warn(f"depends on the dynamic MSVC runtime ({', '.join(runtime)}); "
                     "upstream links it statically (staticruntime \"on\")")
        rep.info("imports: " + (", ".join(info["needed"]) or "none"))

    if info["fmt"] == "elf":
        if info["os"] != exp["os"]:
            rep.error(f"built for {info['os']}, expected {exp['os']} "
                      "(same CPU but wrong C library: dlopen will fail on the target)")
        allowed = ALLOWED_NEEDED.get(exp["os"], set())
        extra = [n for n in info["needed"] if n not in allowed]
        if extra:
            rep.warn(f"unexpected dependencies: {', '.join(extra)} (must exist on every target system)")
        rep.info("NEEDED: " + (", ".join(info["needed"]) or "none (fully static)"))
        if exp["os"] == "linux" and info["glibc_max"]:
            rep.warn("requires glibc >= " + ".".join(map(str, info["glibc_max"])) +
                     " (upstream builds fully static against musl to avoid this)")
        if "align" in exp and info["min_load_align"] < exp["align"][0]:
            need, severity = exp["align"]
            msg = (f"LOAD segment alignment {info['min_load_align']:#x} < {need:#x}: "
                   f"cannot be loaded on systems using {need // 1024} KiB pages")
            (rep.error if severity == "error" else rep.warn)(msg)

    if info["fmt"] == "macho":
        missing = exp["arches"] - info["arches"]
        if missing:
            rep.error(f"missing slice(s): {', '.join(sorted(missing))} "
                      "(the client uses one name for every Mac, so build a universal binary)")
        for s in info["slices"]:
            where = f"[{s['cpu']}] "
            if not s["is_dll"]:
                rep.error(where + "slice is not a dylib")
            check_exports(rep, s["exports"], where)
            if s["cpu"] == "arm64" and not s["signed"]:
                rep.error(where + "no code signature: Apple Silicon refuses unsigned arm64 code "
                          "(ad-hoc signing is enough)")
            odd = [d for d in s["needed"] if not d.startswith(("/usr/lib/", "/System/"))]
            if odd:
                rep.warn(where + f"non-system dependencies: {', '.join(odd)}")
            if s["minos"]:
                rep.info(where + f"minimum OS version {s['minos']}")
    return rep, info


def compare_reference(rep, info, ref_path):
    try:
        ref = parse_any(ref_path)
    except Exception as exc:  # noqa: BLE001
        rep.warn(f"reference file unreadable: {exc}")
        return
    a, b = describe(info), describe(ref)
    if a != b:
        rep.error(f"differs from reference: built = {a}, reference = {b}")
    else:
        rep.info("matches reference format/architecture/OS")


def host_core_name():
    system, machine = platform.system(), platform.machine().lower()
    if system == "Windows":
        return "ocgcore.dll"
    if system == "Darwin":
        return "libocgcore.dylib"
    if system == "Linux":
        return "libocgcore.aarch64.so" if machine in ("aarch64", "arm64") else "libocgcore.so"
    return None


_QUERY_SNIPPET = (
    "import ctypes, sys\n"
    "lib = ctypes.CDLL(sys.argv[1])\n"
    "a, b = ctypes.c_int(), ctypes.c_int()\n"
    "lib.OCG_GetVersion(ctypes.byref(a), ctypes.byref(b))\n"
    "print(a.value, b.value)\n"
)


def query_version(path):
    """Load a core with the host loader and return OCG_GetVersion() as (major, minor).

    Runs in a separate Python process so that (a) two cores sharing a module name or
    SONAME can never alias each other, and (b) a core that crashes while loading is
    reported as an error instead of killing the verifier.
    Raises OSError if the host cannot load it (wrong architecture, missing export...)."""
    proc = subprocess.run([sys.executable, "-c", _QUERY_SNIPPET, os.path.abspath(path)],
                          capture_output=True, text=True, timeout=60)
    if proc.returncode != 0:
        detail = (proc.stderr.strip().splitlines() or [f"exit code {proc.returncode}"])[-1]
        raise OSError(detail)
    major, minor = proc.stdout.split()
    return int(major), int(minor)


def load_and_query(rep, path, info, expect_version):
    py_bits = struct.calcsize("P") * 8
    if info.get("fmt") in ("pe", "elf") and info.get("bits") != py_bits:
        rep.warn(f"--load skipped: core is {info['bits']}-bit, this Python is {py_bits}-bit")
        return
    try:
        version = query_version(path)
    except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
        rep.error(f"host loader rejected the file: {exc}")
        return
    rep.info(f"loaded on this host, OCG_GetVersion() = {version[0]}.{version[1]}")
    if expect_version and version != expect_version:
        rep.error(f"API version {version[0]}.{version[1]} != expected "
                  f"{expect_version[0]}.{expect_version[1]}: the client will reject it")


def main():
    ap = argparse.ArgumentParser(description="Verify EDOPro ocgcore binaries before publishing them.")
    ap.add_argument("dir")
    ap.add_argument("--reference")
    ap.add_argument("--windows-arch", choices=sorted(WINDOWS_ARCHES), default="x86")
    ap.add_argument("--load", action="store_true")
    ap.add_argument("--expect-version")
    args = ap.parse_args()

    cpu, bits = WINDOWS_ARCHES[args.windows_arch]
    expected = dict(EXPECTED)
    expected["ocgcore.dll"] = dict(fmt="pe", bits=bits, cpu=cpu, core=True)

    host_name = host_core_name()
    expect_version = None
    if args.expect_version == "reference":
        ref_core = os.path.join(args.reference or "", host_name or "")
        if not (args.reference and host_name and os.path.isfile(ref_core)):
            print(f"ERROR: --expect-version reference needs --reference containing {host_name}")
            return 1
        try:
            expect_version = query_version(ref_core)
        except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
            print(f"ERROR: cannot load reference core {ref_core}: {exc}")
            return 1
        print(f"Expected API version (from reference {host_name}): "
              f"{expect_version[0]}.{expect_version[1]}\n")
    elif args.expect_version:
        expect_version = tuple(int(x) for x in args.expect_version.split("."))

    present = sorted(f for f in os.listdir(args.dir) if os.path.isfile(os.path.join(args.dir, f)))
    errors = warnings = 0
    if args.load and host_name not in present:
        print(f"[WARN] --load: no {host_name} in {args.dir}, API version not checked\n")
        warnings += 1

    for name in present:
        path = os.path.join(args.dir, name)
        if name not in expected:
            if name.endswith((".so", ".dll", ".dylib")):
                rep = Report(name)
                rep.warn("file name not recognised by the client (see CORENAME in dllinterface.cpp); it is never loaded")
                rep.print()
                warnings += 1
            continue
        rep, info = check_file(path, expected[name])
        if info is not None and args.reference:
            ref_path = os.path.join(args.reference, name)
            if os.path.isfile(ref_path):
                compare_reference(rep, info, ref_path)
        if info is not None and args.load and name == host_name:
            load_and_query(rep, path, info, expect_version)
        rep.print()
        errors += bool(rep.errors)
        warnings += bool(rep.warnings)

    for name, exp in sorted(expected.items()):
        if exp.get("core") and name not in present:
            print(f"[MISS] {name}: not present; clients on that platform keep their current core")

    checked = sum(1 for f in present if f in expected or f.endswith((".so", ".dll", ".dylib")))
    print(f"\n{checked} binary file(s) checked: {errors} with errors, {warnings} with warnings")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())