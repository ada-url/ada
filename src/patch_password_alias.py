#!/usr/bin/env python3
# ruff: noqa
"""Plant a not-taken alias check in the padding before set_password.

The fast path falls through into the existing prologue, so the function body
and every later function stay at the same file offsets. The taken side is
ada_agg_set_password_alias.
"""

import struct
import sys

PASSWORD = (
    "_ZN3ada14url_aggregator12set_passwordESt17basic_string_viewIcSt11char_"
    "traitsIcEE"
)
ALIAS = b"ada_agg_set_password_alias\x00"
ENDBR = bytes.fromhex("f30f1efa")
PUSH_R13 = bytes.fromhex("4155")
# mov rax, rdx; sub rax, [rdi+0x30]; cmp rax, [rdi+0x38]; jb rel32
STUB_HEAD = bytes.fromhex("4889d0482b4730483b47380f82")
STUB_LEN = len(STUB_HEAD) + 4
R_X86_64_PLT32 = 4


def sections(data):
    e_shoff = struct.unpack_from("<Q", data, 40)[0]
    e_shentsize = struct.unpack_from("<H", data, 58)[0]
    e_shnum = struct.unpack_from("<H", data, 60)[0]
    e_shstrndx = struct.unpack_from("<H", data, 62)[0]
    headers = []
    for index in range(e_shnum):
        base = e_shoff + index * e_shentsize
        name, sh_type, sh_flags, sh_addr, sh_offset, sh_size, sh_link, sh_info, sh_addralign, sh_entsize = struct.unpack_from(
            "<IIQQQQIIQQ", data, base
        )
        headers.append(
            {
                "index": index,
                "name_off": name,
                "offset": sh_offset,
                "size": sh_size,
                "addr": sh_addr,
                "entsize": sh_entsize,
                "base": base,
            }
        )
    strtab = headers[e_shstrndx]
    blob = data[strtab["offset"] : strtab["offset"] + strtab["size"]]
    for header in headers:
        end = blob.index(b"\x00", header["name_off"])
        header["name"] = blob[header["name_off"] : end].decode()
    return headers


def by_name(headers, name):
    for header in headers:
        if header["name"] == name:
            return header
    sys.exit("patch_password_alias: missing " + name)


def set_header(data, header, offset, size):
    struct.pack_into("<Q", data, header["base"] + 24, offset)
    struct.pack_into("<Q", data, header["base"] + 32, size)
    header["offset"] = offset
    header["size"] = size


def cstr(blob, offset):
    end = blob.index(b"\x00", offset)
    return blob[offset:end].decode()


def is_x86_64(data):
    # EM_X86_64, ELFCLASS64, ELFDATA2LSB. Other objects keep the weak setter.
    return (
        len(data) >= 64
        and data[:4] == b"\x7fELF"
        and data[4] == 2
        and data[5] == 1
        and struct.unpack_from("<H", data, 18)[0] == 62
    )


def reject(message):
    print("patch_password_alias: " + message, file=sys.stderr)
    sys.exit(2)


def relocation_in_range(data, rela, text, start, length):
    if rela["entsize"] != 24:
        return True
    for index in range(rela["size"] // 24):
        r_offset = struct.unpack_from("<Q", data, rela["offset"] + index * 24)[0]
        if start <= r_offset < start + length:
            return True
    return False


def strengthen(path, symbol):
    """Turn the weak fallback into a global once it is the only definition."""
    data = bytearray(open(path, "rb").read())
    if not (
        len(data) >= 64
        and data[:4] == b"\x7fELF"
        and data[4] == 2
        and data[5] == 1
    ):
        return
    headers = sections(data)
    symtab = by_name(headers, ".symtab")
    strtab = by_name(headers, ".strtab")
    names = data[strtab["offset"] : strtab["offset"] + strtab["size"]]
    found = False
    for index in range(symtab["size"] // symtab["entsize"]):
        off = symtab["offset"] + index * symtab["entsize"]
        st_name = struct.unpack_from("<I", data, off)[0]
        if not st_name or cstr(names, st_name) != symbol:
            continue
        info = data[off + 4]
        if (info >> 4) == 2:
            data[off + 4] = (1 << 4) | (info & 0xF)
        found = True
    if not found:
        sys.exit("patch_password_alias: cannot strengthen " + symbol)
    with open(path, "wb") as handle:
        handle.write(data)


def main():
    if len(sys.argv) == 4 and sys.argv[1] == "--strengthen":
        strengthen(sys.argv[2], sys.argv[3])
        return
    path = sys.argv[1]
    data = bytearray(open(path, "rb").read())
    if not is_x86_64(data):
        reject("not an x86_64 object")
    headers = sections(data)
    text = by_name(headers, ".text")
    symtab = by_name(headers, ".symtab")
    strtab = by_name(headers, ".strtab")
    rela = by_name(headers, ".rela.text")
    names = data[strtab["offset"] : strtab["offset"] + strtab["size"]]

    password = None
    symbols = []
    for index in range(symtab["size"] // symtab["entsize"]):
        off = symtab["offset"] + index * symtab["entsize"]
        st_name, st_info, st_other, st_shndx, st_value, st_size = struct.unpack_from(
            "<IBBHQQ", data, off
        )
        symbols.append((off, st_shndx, st_value, st_size, cstr(names, st_name) if st_name else ""))
        if symbols[-1][4] == PASSWORD:
            password = symbols[-1]

    if password is None:
        sys.exit("patch_password_alias: set_password symbol missing")
    _, _, value, size, _ = password

    def file_at(addr):
        return text["offset"] + (addr - text["addr"])

    entry = file_at(value)
    if data[entry : entry + 3] == STUB_HEAD[:3]:
        return
    if data[entry : entry + 4] != ENDBR or data[entry + 4 : entry + 6] != PUSH_R13:
        reject("unexpected set_password prologue")

    stub_addr = value + 4 - STUB_LEN
    stub_off = stub_addr - text["addr"]
    if stub_off < 0 or relocation_in_range(data, rela, text, stub_off, STUB_LEN):
        reject("no padding in front of set_password")
    for _, shndx, sym_value, sym_size, sym_name in symbols:
        if shndx != text["index"] or sym_value >= value or sym_size == 0:
            continue
        if sym_value + sym_size > stub_addr:
            reject("stub would overlap " + sym_name)

    data[file_at(stub_addr) : file_at(stub_addr) + STUB_LEN] = STUB_HEAD + b"\x00\x00\x00\x00"
    struct.pack_into("<Q", data, password[0] + 8, stub_addr)
    struct.pack_into("<Q", data, password[0] + 16, size + (value - stub_addr))

    new_str = bytearray(data[strtab["offset"] : strtab["offset"] + strtab["size"]])
    name_off = len(new_str)
    new_str += ALIAS
    str_file = len(data)
    data += new_str
    set_header(data, strtab, str_file, len(new_str))

    old_syms = bytes(data[symtab["offset"] : symtab["offset"] + symtab["size"]])
    new_sym = struct.pack("<IBBHQQ", name_off, 0x12, 0, 0, 0, 0)
    sym_file = len(data)
    data += old_syms + new_sym
    new_index = len(symbols)
    set_header(data, symtab, sym_file, len(old_syms) + len(new_sym))

    old_rela = bytes(data[rela["offset"] : rela["offset"] + rela["size"]])
    new_rela = struct.pack(
        "<QQq", stub_addr + len(STUB_HEAD), (new_index << 32) | R_X86_64_PLT32, -4
    )
    rela_file = len(data)
    data += old_rela + new_rela
    set_header(data, rela, rela_file, len(old_rela) + len(new_rela))

    with open(path, "wb") as handle:
        handle.write(data)


if __name__ == "__main__":
    main()
