#!/usr/bin/env python3
import argparse
import hashlib
import os
import re
import shutil
import string
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path


class Die(Exception):
    pass


def run(cmd, *, check=True):
    try:
        p = subprocess.run(cmd, check=False, capture_output=True, text=True)
    except FileNotFoundError as e:
        raise Die(f"missing command: {cmd[0]}") from e
    if check and p.returncode != 0:
        msg = p.stderr.strip() or p.stdout.strip() or f"exit {p.returncode}"
        raise Die(f"{' '.join(cmd)} failed: {msg}")
    return p


def extract_lib(apk_path, abi, out_dir):
    member = f"lib/{abi}/libclash.so"
    with zipfile.ZipFile(apk_path) as z:
        names = set(z.namelist())
        if member not in names:
            candidates = sorted(n for n in names if n.endswith("/libclash.so"))
            raise Die(
                f"{member} not found in APK. Available libclash.so entries: "
                + (", ".join(candidates) if candidates else "<none>")
            )
        out = Path(out_dir) / f"libclash_{abi}.so"
        with z.open(member) as src, out.open("wb") as dst:
            shutil.copyfileobj(src, dst)
    return out


def detect_scheme(lib_path):
    """Scheme A = upstream convert.DecodeAESBase64, scheme B = FlyingBird-Lite's main-pkg fork."""
    data = Path(lib_path).read_bytes()

    convert_rx = rb"metacubex/mihomo/common/convert\.[A-Za-z0-9]+"
    convert_syms = sorted({m.group(0).decode("ascii") for m in re.finditer(convert_rx, data)})
    has_a = any(s.endswith("DecodeAESBase64") for s in convert_syms) and any(
        s.endswith("aesDecryptCBC") for s in convert_syms
    )

    b_prefixes = ("main.configSecretBytes", "main.diskXorKey", "main.xorDiskTransform")
    main_rx = rb"main\.[A-Za-z0-9_]+(?:\.func\d+)?"
    b_hits = sorted(
        {m.group(0).decode("ascii") for m in re.finditer(main_rx, data) if m.group(0).decode("ascii").startswith(b_prefixes)}
    )

    a_evidence = [s for s in convert_syms if "AES" in s or "aes" in s][:6] or convert_syms[:6]
    if b_hits:
        return "B", b_hits[:6]
    if has_a:
        return "A", a_evidence
    return "?", convert_syms[:6]


def cstr(data, off):
    if off < 0 or off >= len(data):
        return ""
    end = data.find(b"\x00", off)
    if end < 0:
        end = len(data)
    return data[off:end].decode("utf-8", errors="replace")


def read_elf64_le_sections(data):
    if len(data) < 64 or data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
        raise Die("not an ELF64 little-endian file")

    shoff = int.from_bytes(data[40:48], "little")
    shentsize = int.from_bytes(data[58:60], "little")
    shnum = int.from_bytes(data[60:62], "little")
    shstrndx = int.from_bytes(data[62:64], "little")
    if shoff == 0 or shentsize == 0 or shnum == 0 or shstrndx >= shnum:
        raise Die("invalid section table")

    def raw_section(index):
        start = shoff + index * shentsize
        end = start + shentsize
        if start < 0 or end > len(data):
            raise Die("invalid section header")
        return data[start:end]

    shstr = raw_section(shstrndx)
    shstr_off = int.from_bytes(shstr[24:32], "little")
    shstr_size = int.from_bytes(shstr[32:40], "little")
    if shstr_off + shstr_size > len(data):
        raise Die("invalid shstrtab data")
    names = data[shstr_off : shstr_off + shstr_size]

    sections = []
    for i in range(shnum):
        s = raw_section(i)
        off = int.from_bytes(s[24:32], "little")
        size = int.from_bytes(s[32:40], "little")
        sections.append(
            {
                "name": cstr(names, int.from_bytes(s[0:4], "little")),
                "addr": int.from_bytes(s[16:24], "little"),
                "off": off,
                "size": size,
                "data": data[off : off + size] if off + size <= len(data) else b"",
            }
        )
    return sections


class GoPclnTable:
    MAGICS = {
        0xFFFFFFFB: "ver12",
        0xFFFFFFFA: "ver116",
        0xFFFFFFF0: "ver118",
        0xFFFFFFF1: "ver120",
    }

    def __init__(self, pcln, text_addr):
        self.data = pcln
        self.text_addr = text_addr
        self.order = "little"
        self.version = None
        self.ptrsize = 0
        self.nfunctab = 0
        self.funcnametab = b""
        self.funcdata = b""
        self.functab = b""
        self.field_size = 0
        self._parse_header()

    def _uint(self, data, off, size):
        if off < 0 or off + size > len(data):
            raise Die("malformed Go pclntab")
        return int.from_bytes(data[off : off + size], self.order)

    def _uintptr_at(self, off):
        return self._uint(self.data, off, self.ptrsize)

    def _offset_word(self, word):
        return self._uintptr_at(8 + word * self.ptrsize)

    def _data_from_word(self, word):
        off = self._offset_word(word)
        if off > len(self.data):
            raise Die("malformed Go pclntab offset")
        return self.data[off:]

    def _parse_header(self):
        if (
            len(self.data) < 16
            or self.data[4] != 0
            or self.data[5] != 0
            or self.data[6] not in (1, 2, 4)
            or self.data[7] not in (4, 8)
        ):
            raise Die("invalid Go pclntab header")

        le_magic = int.from_bytes(self.data[:4], "little")
        be_magic = int.from_bytes(self.data[:4], "big")
        if le_magic in self.MAGICS:
            self.order = "little"
            self.version = self.MAGICS[le_magic]
        elif be_magic in self.MAGICS:
            self.order = "big"
            self.version = self.MAGICS[be_magic]
        else:
            raise Die("unsupported Go pclntab magic")

        self.ptrsize = self.data[7]
        if self.version in ("ver118", "ver120"):
            self.nfunctab = self._offset_word(0)
            self.funcnametab = self._data_from_word(3)
            self.funcdata = self._data_from_word(7)
            self.functab = self.funcdata
            self.field_size = 4
        elif self.version == "ver116":
            self.nfunctab = self._offset_word(0)
            self.funcnametab = self._data_from_word(2)
            self.funcdata = self._data_from_word(6)
            self.functab = self.funcdata
            self.field_size = self.ptrsize
        else:
            self.nfunctab = self._uintptr_at(8)
            self.funcnametab = self.data
            self.funcdata = self.data
            self.functab = self.data[8 + self.ptrsize :]
            self.field_size = self.ptrsize

        size = (self.nfunctab * 2 + 1) * self.field_size
        if size > len(self.functab):
            raise Die("malformed Go functab")
        self.functab = self.functab[:size]

    def _functab_uint(self, index):
        return self._uint(self.functab, index * self.field_size, self.field_size)

    def pc(self, index):
        pc = self._functab_uint(2 * index)
        if self.version in ("ver118", "ver120"):
            pc += self.text_addr
        return pc

    def func_offset(self, index):
        return self._functab_uint(2 * index + 1)

    def func_name(self, name_off):
        return cstr(self.funcnametab, name_off)

    def name_offset(self, index):
        off = self.func_offset(index)
        first_field_size = 4 if self.version in ("ver118", "ver120") else self.ptrsize
        name_off_pos = off + first_field_size
        return self._uint(self.funcdata, name_off_pos, 4)

    def funcs(self):
        out = []
        for i in range(self.nfunctab):
            entry = self.pc(i)
            end = self.pc(i + 1)
            name = self.func_name(self.name_offset(i))
            out.append({"entry": entry, "name": name, "size": end - entry})
        return out


def _pclntab_header_ok(blob):
    """Validate a pcHeader candidate.

    A bare magic match is not enough: the moduledata embedded in .data.rel.ro
    carries a copy of the magic bytes, and linker padding produces runs of 0xf0.
    Those decode to garbage pad/minLC/ptrsize, so check the header fields and then
    that the functab the header describes actually fits inside the section.
    """
    if len(blob) < 72:
        return False
    if blob[4] != 0 or blob[5] != 0 or blob[6] not in (1, 2, 4) or blob[7] not in (4, 8):
        return False

    magic = int.from_bytes(blob[:4], "little")
    ptrsize = blob[7]
    if magic == 0xFFFFFFFB:  # ver12 predates the pcHeader struct
        return True
    if magic not in (0xFFFFFFF1, 0xFFFFFFF0, 0xFFFFFFFA):
        return False

    nfunc = int.from_bytes(blob[8 : 8 + ptrsize], "little")
    if not 0 < nfunc < 20_000_000:
        return False

    field_size = 4 if magic in (0xFFFFFFF1, 0xFFFFFFF0) else ptrsize
    pcln_off = int.from_bytes(blob[8 + 7 * ptrsize : 8 + 8 * ptrsize], "little")
    return pcln_off + (nfunc * 2 + 1) * field_size <= len(blob)


def _go_text_base(pclntab_vaddr, relocs, text_vaddr, text_end):
    """Go's text origin, which is not the ELF .text vaddr.

    entryoff in the functab is relative to runtime.text.  A c-shared build prefixes
    .text with the C runtime preamble, so runtime.text sits some way in.  moduledata
    holds the real value: it is the struct owning the pcHeader pointer, and its
    minpc/text field is that base.  Locate moduledata by the relocation whose addend
    is the pclntab itself, then take the first field in it that lands inside .text.
    """
    if pclntab_vaddr == 0:
        return text_vaddr
    for addr, addend in relocs.items():
        if addend != pclntab_vaddr:
            continue
        for off in range(0, 0x200, 8):
            value = relocs.get(addr + off)
            if value is not None and text_vaddr <= value < text_end:
                return value
        break
    return text_vaddr


def find_go_pclntab_in_elf64_le(lib_path):
    data = Path(lib_path).read_bytes()
    sections = read_elf64_le_sections(data)
    text_section = next((s for s in sections if s["name"] == ".text"), None)
    if not text_section or not text_section["addr"]:
        raise Die("missing .text address")
    text_vaddr = text_section["addr"]
    text_end = text_vaddr + text_section["size"]
    relocs = read_relocations(data, sections)

    magics = (b"\xf1\xff\xff\xff", b"\xf0\xff\xff\xff", b"\xfa\xff\xff\xff", b"\xfb\xff\xff\xff")
    search_sections = [s for s in sections if s["name"] == ".gopclntab"]
    search_sections.extend(
        s for s in sections if s["name"] not in (".gopclntab", ".text")
    )
    for section in search_sections:
        blob = section["data"]
        for magic in magics:
            pos = blob.find(magic)
            while pos >= 0:
                if _pclntab_header_ok(blob[pos:]):
                    base = _go_text_base(section["addr"] + pos, relocs, text_vaddr, text_end)
                    return blob[pos:], base
                pos = blob.find(magic, pos + 1)
    raise Die("missing Go pclntab magic in ELF sections")


def find_go_func(lib_path, needle):
    pcln, text_addr = find_go_pclntab_in_elf64_le(lib_path)
    table = GoPclnTable(pcln, text_addr)
    funcs = []
    for f in table.funcs():
        if needle in f["name"]:
            f["line"] = f"0x{f['entry']:x} {f['name']} size={f['size']}"
            funcs.append(f)
    if not funcs:
        raise Die(f"function not found via Go pclntab: {needle}")
    exact = [f for f in funcs if f["name"].endswith(needle)]
    return (exact or funcs)[0]


def disassemble(lib_path, start, stop):
    p = run(["objdump", "-d", f"--start-address=0x{start:x}", f"--stop-address=0x{stop:x}", str(lib_path)])
    return p.stdout.splitlines()


def imm64_to_ascii_le(value):
    b = value.to_bytes(8, "little", signed=False)
    printable = set(bytes(string.printable, "ascii")) - {0x0b, 0x0c}
    if all(ch in printable and chr(ch) not in "\r\n\t" for ch in b):
        return b
    return None


def extract_arm64_movk_constants(lines):
    regs = {}
    constants = []
    for line in lines:
        m = re.search(r"\bmov\s+(x[0-9]+),\s*#(\d+)", line)
        if m:
            regs[m.group(1)] = int(m.group(2)) & 0xffff
            continue
        m = re.search(r"\bmovk\s+(x[0-9]+),\s*#(\d+),\s*lsl\s*#(\d+)", line)
        if not m:
            continue
        reg = m.group(1)
        if reg not in regs:
            continue
        imm = int(m.group(2)) & 0xffff
        shift = int(m.group(3))
        regs[reg] = (regs[reg] & ~(0xffff << shift)) | (imm << shift)
        if shift == 48:
            b = imm64_to_ascii_le(regs[reg])
            if b is not None:
                constants.append({"line": line.strip(), "bytes": b})
    if len(constants) < 4:
        detail = "\n".join("  " + x.strip() for x in lines[:120])
        raise Die("fewer than four printable arm64 mov/movk constants were found.\n" + detail)
    return constants[:4]


# ---------------------------------------------------------------------------
# Scheme B - the FlyingBird-Lite / securitynet mihomo fork.
#
# convert.DecodeAESBase64 is gone and the on-disk profile is binary:
#
#   file --xor--> base64 ascii --b64decode--> nonce(12) | ct | tag(16)
#                                               --AES-256-GCM--> plaintext YAML
#
# The XOR layer is disk-only; the panel serves bare base64 over the wire.  Both
# pieces of key material are built at runtime from obfuscated arrays, so neither
# exists as a literal anywhere in the binary:
#
#   main.diskXorKey.func1    35 B disk XOR key = obf[i] ^ 0xa7
#   main.configSecretBytes   32 B seed = three arrays of length 10/10/12:
#        dst1[i] = (src1[i] ^ ((i + 195) & 0xff)) ^ 0x5a
#        dst2[i] = (src2[i] - i - 60) & 0xff
#        dst3[i] = ror8(src3[i] ^ 0xa7, (i % 5) + 1)
#
# and the GCM key is sha256(seed) - the 32 ascii bytes are a seed, not the key.
# ---------------------------------------------------------------------------

FB_OBF_XOR = 0xA7
FB_DISK_XOR_LEN = 35
FB_SEED_CHUNKS = (10, 10, 12)
FB_SEED_A_ADD = 195
FB_SEED_A_XOR = 0x5A
FB_SEED_B_SUB = 60
FB_SEED_C_XOR = 0xA7
FB_SEED_C_ROL = 5
FB_SEED_LEN = sum(FB_SEED_CHUNKS)
FB_NEED = max(FB_DISK_XOR_LEN, FB_SEED_LEN)

IMM_RX = re.compile(r"\b(mov|movz|movk|movn)\s+(w|x)(\d+),\s*#(0x[0-9a-fA-F]+|\d+)")
SHIFT_RX = re.compile(r",\s*lsl\s*#(\d+)")
ADRP_RX = re.compile(r"\badrp\s+(x\d+),\s*(?:0x)?([0-9a-fA-F]+)\b")
ADD_RX = re.compile(r"\badd\s+(x\d+),\s*(x\d+),\s*#(0x[0-9a-fA-F]+|\d+)")
LDR_RX = re.compile(r"\bldr\s+(x\d+),\s*\[(x\d+)(?:,\s*#(0x[0-9a-fA-F]+|\d+))?\]")
MOV_RX = re.compile(r"\bmov\s+(x\d+),")
INSN_ADDR_RX = re.compile(r"^\s*([0-9a-f]+):")


def arch_imm(text):
    """llvm-objdump prints arm64 immediates in decimal; only 0x-prefixed ones are hex."""
    return int(text, 16) if text.lower().startswith("0x") else int(text, 10)


def ror8(value, n):
    n %= 8
    return ((value >> n) | (value << (8 - n))) & 0xFF


def is_printable(data, length):
    return len(data) == length and all(0x20 <= b < 0x7F for b in data)


def fb_seed_first(obf):
    return bytes((v ^ ((i + FB_SEED_A_ADD) & 0xFF)) ^ FB_SEED_A_XOR for i, v in enumerate(obf[:10]))


def fb_seed_second(obf):
    return bytes((v - i - FB_SEED_B_SUB) & 0xFF for i, v in enumerate(obf[:10]))


def fb_seed_third(obf):
    return bytes(ror8(v ^ FB_SEED_C_XOR, (i % FB_SEED_C_ROL) + 1) for i, v in enumerate(obf[:12]))


def fb_disk_xor_key(obf):
    """main.diskXorKey.func1 - xor with 0xa7 is its own inverse."""
    return bytes(b ^ FB_OBF_XOR for b in obf[:FB_DISK_XOR_LEN])


def fb_config_secret(obf):
    """main.configSecretBytes - undo the three obfuscated arrays into the ascii seed."""
    if len(obf) < FB_SEED_LEN:
        return None
    n1, n2, _ = FB_SEED_CHUNKS
    return (
        fb_seed_first(obf[:n1])
        + fb_seed_second(obf[n1 : n1 + n2])
        + fb_seed_third(obf[n1 + n2 : FB_SEED_LEN])
    )


def arm64_immediate_stream(lines):
    """Reassemble movz/movk chains into complete 32/64-bit constants, in program order.

    A `mov`/`movz` is held back until either the movk chain that builds it finishes, or
    the register is used for something else (in which case it was a standalone constant).
    """
    regs = {}
    pending = {}
    out = []
    for raw in lines:
        line = raw.strip()
        m = IMM_RX.search(line)
        if not m:
            continue
        op = m.group(1)
        width = 4 if m.group(2) == "w" else 8
        reg = int(m.group(3))
        imm = int(m.group(4), 0)
        shift_m = SHIFT_RX.search(line)
        shift = int(shift_m.group(1)) if shift_m else 0
        mask = (1 << (width * 8)) - 1

        if op == "movk":
            if reg not in regs:
                continue
            if shift:
                pending.pop(reg, None)
            value = (regs[reg] & ~(0xFFFF << shift)) | ((imm & 0xFFFF) << shift)
            regs[reg] = value
            if shift == width * 8 - 16:
                out.append((value, width, line))
            continue

        if reg in pending:
            out.append(pending.pop(reg))
        value = (~imm if op == "movn" else imm << shift) & mask
        regs[reg] = value
        pending[reg] = (value, width, line)

    out.extend(pending.values())
    return out


def imm_stream_bytes(stream, start, need, force_width=None):
    buf = bytearray()
    for value, width, _ in stream[start:]:
        buf += value.to_bytes(force_width or width, "little", signed=False)
        if len(buf) >= need:
            break
    return bytes(buf)


def read_relocations(data, sections):
    """instruction vaddr -> relocation addend; Go c-shared .so resolve adrp targets this way."""
    out = {}
    for name in (".rela.dyn", ".rela.plt"):
        sec = next((s for s in sections if s["name"] == name), None)
        if not sec or not sec["data"]:
            continue
        blob = sec["data"]
        for off in range(0, len(blob) - 24 + 1, 24):  # Elf64_Rela
            r_offset = int.from_bytes(blob[off : off + 8], "little")
            r_addend = int.from_bytes(blob[off + 16 : off + 24], "little", signed=True)
            out.setdefault(r_offset, r_addend)
    return out


def arm64_global_addrs(lines, relocs):
    """Best-effort absolute vaddrs for adrp+add / adrp+ldr data references."""
    regs = {}
    out = []
    for raw in lines:
        line = raw.strip()
        addr_m = INSN_ADDR_RX.match(raw)
        insn = int(addr_m.group(1), 16) if addr_m else None

        m = ADRP_RX.search(line)
        if m:
            page = relocs.get(insn)
            regs[m.group(1)] = int(m.group(2), 16) if page is None else page
            continue

        m = ADD_RX.search(line)
        if m:
            dst, src = m.group(1), m.group(2)
            if src in regs:
                regs[dst] = regs[src] + arch_imm(m.group(3))
                out.append(regs[dst])
            else:
                regs.pop(dst, None)
            continue

        m = LDR_RX.search(line)
        if m:
            dst, src = m.group(1), m.group(2)
            if src in regs:
                out.append(regs[src] + (arch_imm(m.group(3)) if m.group(3) else 0))
            regs.pop(dst, None)  # the register now holds data, not an address
            continue

        m = MOV_RX.search(line)
        if m:
            regs.pop(m.group(1), None)
    return out


def vaddr_reader(sections):
    class _Reader:
        def read(self, vaddr, n):
            if vaddr <= 0:
                return None
            for s in sections:
                if s["addr"] and s["size"] and s["addr"] <= vaddr < s["addr"] + s["size"]:
                    base = vaddr - s["addr"]
                    return s["data"][base : base + n]
            return None

    return _Reader()


def deref_slice(image, relocs, addr):
    """Follow a Go slice/string header global to the bytes it points at.

    A `[]byte{...}` literal that the compiler keeps in a global is stored as a
    three-word header {ptr, len, cap} in .data; the pointer is only filled in by
    the loader, so on disk the word reads 0 and the addend lives in .rela.dyn.
    Returns (data_vaddr, bytes) or None when *addr* is not such a header.
    """
    hdr = image.read(addr, 24)
    if not hdr or len(hdr) < 24:
        return None
    ptr = relocs.get(addr) or int.from_bytes(hdr[0:8], "little")
    length = relocs.get(addr + 8) or int.from_bytes(hdr[8:16], "little")
    if not ptr or not 0 < length <= FB_NEED * 4:
        return None
    blob = image.read(ptr, length)
    if not blob or len(blob) < length:
        return None
    return ptr, blob


def scheme_b_candidates(lines, image, addrs, relocs):
    """(label, raw obfuscated bytes) candidates for the scheme B key arrays."""
    out = []
    stream = arm64_immediate_stream(lines)
    for start in range(len(stream)):
        for force in (None, 8):
            buf = imm_stream_bytes(stream, start, FB_NEED, force)
            if len(buf) >= FB_NEED:
                out.append((f"{'imm.w8' if force else 'imm.nat'}@{start}", buf))
    for addr in addrs:
        blob = image.read(addr, FB_NEED)
        if blob and len(blob) >= FB_NEED:
            out.append((f"global 0x{addr:x}", blob))
        got = deref_slice(image, relocs, addr)
        if got:
            ptr, data = got
            out.append((f"slice 0x{addr:x}->0x{ptr:x} ({len(data)}B)", data))
    return out


def run_scheme_a(lib):
    print("[3/4] locating DecodeAESBase64 with Go pclntab")
    fn = find_go_func(lib, "convert.DecodeAESBase64")
    aes = find_go_func(lib, "convert.aesDecryptCBC")
    print(f"      {fn['line']}")
    print(f"      {aes['line']}")

    print("[4/4] extracting arm64 prologue constants")
    lines = disassemble(lib, fn["entry"], fn["entry"] + min(fn["size"], 512))
    constants = extract_arm64_movk_constants(lines)
    for i, c in enumerate(constants, 1):
        print(f"      imm{i}: {c['bytes']!r}    {c['line']}")

    key = constants[0]["bytes"] + constants[1]["bytes"]
    iv = constants[2]["bytes"] + constants[3]["bytes"]
    print()
    print(f"AES-128-CBC KEY ascii: {key.decode('ascii')}")
    print(f"AES-128-CBC IV  ascii: {iv.decode('ascii')}")
    print(f"AES-128-CBC KEY hex:   {key.hex()}")
    print(f"AES-128-CBC IV  hex:   {iv.hex()}")


def run_scheme_b(lib, raw_dump):
    print("[3/4] locating scheme B key builders with Go pclntab")
    pcln, text_addr = find_go_pclntab_in_elf64_le(lib)
    funcs = GoPclnTable(pcln, text_addr).funcs()

    def pick(*needles):
        for needle in needles:
            exact = [f for f in funcs if f["name"] == needle]
            if exact:
                return exact[0]
        for needle in needles:
            prefixed = sorted(
                (f for f in funcs if f["name"].startswith(needle)), key=lambda f: len(f["name"])
            )
            if prefixed:
                return prefixed[0]
        return None

    secret = pick("main.configSecretBytes")
    xor_key = pick("main.diskXorKey.func1", "main.diskXorKey")
    if secret is None and xor_key is None:
        raise Die(
            "neither main.configSecretBytes nor main.diskXorKey was found via Go pclntab - "
            "this libclash.so does not look like the scheme B layout"
        )
    for f in (xor_key, secret):
        if f:
            print(f"      {f['name']}  entry=0x{f['entry']:x} size={f['size']}")

    print("[4/4] recovering the obfuscated key arrays")
    lib_data = Path(lib).read_bytes()
    sections = read_elf64_le_sections(lib_data)
    image = vaddr_reader(sections)
    relocs = read_relocations(lib_data, sections)

    found = {}
    dumped = {}
    segments = {"a": [], "b": [], "c": []}

    for f, kind in ((xor_key, "xor"), (secret, "seed")):
        if f is None:
            continue
        lines = disassemble(lib, f["entry"], f["entry"] + min(f["size"], 2048))
        addrs = arm64_global_addrs(lines, relocs)
        items = scheme_b_candidates(lines, image, addrs, relocs)
        dumped[kind] = items
        print(f"      {f['name']}: {len(items)} candidate array(s), {len(addrs)} data ref(s)")

        for label, blob in items:
            if kind == "xor":
                value = fb_disk_xor_key(blob)
                if is_printable(value, FB_DISK_XOR_LEN):
                    found.setdefault(kind, (value, label, blob))
            else:
                value = fb_config_secret(blob)
                if value is not None and is_printable(value, FB_SEED_LEN):
                    found.setdefault(kind, (value, label, blob))

        if kind == "seed":
            # the three obfuscated chunks are separate []byte globals; their lengths
            # (10/10/12) tell them apart and ascending header order is chunk order
            slices = []
            for addr in sorted(set(addrs)):
                got = deref_slice(image, relocs, addr)
                if got:
                    slices.append((addr, got[1]))
            for i in range(len(slices)):
                run = b""
                for _, blob in slices[i : i + 3]:
                    run += blob
                    if len(run) >= FB_SEED_LEN:
                        break
                if len(run) >= FB_SEED_LEN:
                    value = fb_config_secret(run[:FB_SEED_LEN])
                    if value is not None and is_printable(value, FB_SEED_LEN):
                        found.setdefault(kind, (value, f"slice run @0x{slices[i][0]:x}", run))
            for slot, fn, size in (
                ("a", fb_seed_first, 10),
                ("b", fb_seed_second, 10),
                ("c", fb_seed_third, 12),
            ):
                if segments[slot]:
                    continue
                for addr, blob in slices:
                    if len(blob) != size:
                        continue
                    piece = fn(blob)
                    if is_printable(piece, size):
                        segments[slot].append((piece, f"0x{addr:x}"))
                        break

    if all(segments[slot] for slot in "abc"):
        seed = segments["a"][0][0] + segments["b"][0][0] + segments["c"][0][0]
        found.setdefault("seed", (seed, "split arrays a+b+c", b""))

    if raw_dump:
        for kind, items in dumped.items():
            for label, blob in items[:24]:
                print(f"      raw {kind}: {blob.hex()}  ({label})")
            if len(items) > 24:
                print(f"      raw {kind}: ... {len(items) - 24} more")
        for slot in "abc":
            for piece, where in segments[slot][:6]:
                print(f"      seg {slot}: {piece!r}  ({where})")

    print()
    if "xor" in found:
        value, label, _ = found["xor"]
        print(f"disk XOR key (35 B ascii): {value.decode('ascii')}    [{label}]")
    else:
        print("disk XOR key (35 B ascii): <not recovered - rerun with --raw>")
    if "seed" in found:
        value, label, _ = found["seed"]
        print(f"AES seed     (32 B ascii): {value.decode('ascii')}    [{label}]")
        print(f"AES-256-GCM key   hex:     {hashlib.sha256(value).digest().hex()}")
    else:
        print("AES seed     (32 B ascii): <not recovered - rerun with --raw>")


def main(argv):
    ap = argparse.ArgumentParser(
        description="Extract mihomo profile-encryption key material from an Android APK's libclash.so."
    )
    ap.add_argument("apk", help="path to APK")
    ap.add_argument("--abi", default="arm64-v8a", help="APK ABI to inspect, default: arm64-v8a")
    ap.add_argument("--scheme", choices=("auto", "a", "b"), default="auto",
                    help="force a scheme instead of auto-detecting")
    ap.add_argument("--raw", action="store_true", help="dump candidate obfuscated arrays")
    args = ap.parse_args(argv)

    apk = Path(os.path.expanduser(args.apk)).resolve()
    if not apk.is_file():
        raise Die(f"APK not found: {apk}")

    with tempfile.TemporaryDirectory(prefix="mihomo-apk-") as td:
        print("[1/4] extracting libclash.so")
        lib = extract_lib(apk, args.abi, td)
        print(f"      {lib}")

        print("[2/4] detecting profile encryption scheme")
        detected, evidence = detect_scheme(lib)
        scheme = detected if args.scheme == "auto" else args.scheme.upper()
        if scheme == "?":
            raise Die(
                "no known profile-encryption scheme in libclash.so: neither "
                "convert.DecodeAESBase64 (scheme A) nor main.configSecretBytes (scheme B) is present"
            )
        note = "" if scheme == detected else f"  (forced; auto-detect said {detected})"
        print(f"      scheme {scheme}{note}")
        for line in evidence:
            print(f"      {line}")

        if scheme == "A":
            run_scheme_a(lib)
        else:
            run_scheme_b(lib, args.raw)


if __name__ == "__main__":
    try:
        main(sys.argv[1:])
    except Die as e:
        print(f"error: {e}", file=sys.stderr)
        sys.exit(1)
