#!/usr/bin/env python3
"""Plant a not-taken alias check in the padding before set_password.

The fast path falls through into the existing prologue, so the function body
and every later function stay at the same file offsets. The taken side is
ada_agg_set_password_alias.
"""

import struct
import sys

from elftools.elf.elffile import ELFFile

PASSWORD = (
    "_ZN3ada14url_aggregator12set_passwordESt17basic_string_viewIcSt11char_"
    "traitsIcEE"
)
ALIAS = "ada_agg_set_password_alias"
ENDBR = bytes.fromhex("f30f1efa")
PUSH_R13 = bytes.fromhex("4155")
# mov rax, rdx; sub rax, [rdi+0x30]; cmp rax, [rdi+0x38]; jb rel32
STUB_HEAD = bytes.fromhex("4889d0482b4730483b47380f82")
STUB_LEN = len(STUB_HEAD) + 4
R_X86_64_PLT32 = 4


def load(path):
    with open(path, "rb") as handle:
        elf = ELFFile(handle)
        sections = list(elf.iter_sections())
        symtab = elf.get_section_by_name(".symtab")
        symbols = list(symtab.iter_symbols())
    return sections, symtab, symbols


def section_index(sections, name):
    for index, section in enumerate(sections):
        if section.name == name:
            return index
    sys.exit(f"patch_password_alias: missing {name}")


def patch_section_header(data, sections, index, offset, size):
    e_shoff = struct.unpack_from("<Q", data, 40)[0]
    e_shentsize = struct.unpack_from("<H", data, 58)[0]
    base = e_shoff + index * e_shentsize
    struct.pack_into("<Q", data, base + 24, offset)
    struct.pack_into("<Q", data, base + 32, size)


def main():
    path = sys.argv[1]
    sections, symtab, symbols = load(path)
    text = sections[section_index(sections, ".text")]
    password_index = next(
        (i for i, symbol in enumerate(symbols) if symbol.name == PASSWORD), None
    )
    if password_index is None:
        sys.exit("patch_password_alias: set_password symbol missing")
    password = symbols[password_index]
    value = password["st_value"]
    size = password["st_size"]
    text_off = text["sh_offset"]
    text_addr = text["sh_addr"]

    def file_at(addr):
        return text_off + (addr - text_addr)

    data = bytearray(open(path, "rb").read())
    entry = file_at(value)
    if data[entry : entry + 3] == STUB_HEAD[:3]:
        return
    if data[entry : entry + 4] != ENDBR or data[entry + 4 : entry + 6] != PUSH_R13:
        sys.exit("patch_password_alias: unexpected set_password prologue")

    stub_addr = value + 4 - STUB_LEN
    text_index = section_index(sections, ".text")
    for symbol in symbols:
        if symbol["st_shndx"] != text_index or symbol["st_value"] >= value:
            continue
        end = symbol["st_value"] + symbol["st_size"]
        if end > stub_addr:
            sys.exit("patch_password_alias: stub would overlap " + symbol.name)

    stub_file = file_at(stub_addr)
    data[stub_file : stub_file + STUB_LEN] = STUB_HEAD + b"\x00\x00\x00\x00"

    sym_off = symtab["sh_offset"] + password_index * symtab["sh_entsize"]
    struct.pack_into("<Q", data, sym_off + 8, stub_addr)
    struct.pack_into("<Q", data, sym_off + 16, size + (value - stub_addr))

    strtab_index = section_index(sections, ".strtab")
    rela_index = section_index(sections, ".rela.text")
    symtab_index = section_index(sections, ".symtab")
    strtab = sections[strtab_index]
    rela = sections[rela_index]

    new_str = bytearray(
        data[strtab["sh_offset"] : strtab["sh_offset"] + strtab["sh_size"]]
    )
    name_off = len(new_str)
    new_str += ALIAS.encode() + b"\x00"
    str_file = len(data)
    data += new_str
    patch_section_header(data, sections, strtab_index, str_file, len(new_str))

    old_syms = bytes(
        data[symtab["sh_offset"] : symtab["sh_offset"] + symtab["sh_size"]]
    )
    # Global function, undefined.
    new_sym = struct.pack("<IBBHQQ", name_off, 0x12, 0, 0, 0, 0)
    sym_file = len(data)
    data += old_syms + new_sym
    new_sym_index = len(symbols)
    patch_section_header(
        data, sections, symtab_index, sym_file, len(old_syms) + len(new_sym)
    )

    old_rela = bytes(data[rela["sh_offset"] : rela["sh_offset"] + rela["sh_size"]])
    r_offset = stub_addr + len(STUB_HEAD)
    r_info = (new_sym_index << 32) | R_X86_64_PLT32
    new_rela = struct.pack("<QQq", r_offset, r_info, -4)
    rela_file = len(data)
    data += old_rela + new_rela
    patch_section_header(
        data, sections, rela_index, rela_file, len(old_rela) + len(new_rela)
    )

    with open(path, "wb") as handle:
        handle.write(data)


if __name__ == "__main__":
    main()
