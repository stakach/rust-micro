#!/usr/bin/env python3
"""Validate boot ELF64 load geometry and runtime preservation across stripping."""

import argparse
from dataclasses import dataclass
from pathlib import Path
import struct
import sys


ELF_HEADER = struct.Struct("<16sHHIQQQIHHHHHH")
PROGRAM_HEADER = struct.Struct("<IIQQQQQQ")
SECTION_HEADER = struct.Struct("<IIQQQQIIQQ")
U64_MAX = (1 << 64) - 1
PT_LOAD = 1
SHT_NOBITS = 8
SHF_ALLOC = 2
SHF_EXECINSTR = 4
PF_X = 1


class LayoutError(ValueError):
    pass


def extent(start, size, limit, description):
    end = start + size
    if start < 0 or size < 0 or start > limit or end > limit:
        raise LayoutError(f"{description}: range {start:#x}+{size:#x} exceeds {limit:#x}")
    return end


def alignment(value, description):
    if value not in (0, 1) and value & (value - 1):
        raise LayoutError(f"{description}: alignment {value:#x} is not a power of two")


@dataclass(frozen=True)
class Load:
    offset: int
    address: int
    physical: int
    file_size: int
    memory_size: int
    flags: int

    @property
    def end(self):
        return self.address + self.memory_size


@dataclass(frozen=True)
class Section:
    name: str
    kind: int
    flags: int
    address: int
    offset: int
    size: int

    @property
    def identity(self):
        return self.name, self.kind, self.flags, self.address, self.size


@dataclass
class Image:
    data: bytes
    machine: int
    kind: int
    entry: int
    loads: list
    sections: list

    def covering_load(self, address, size):
        return next((load for load in self.loads
                     if load.address <= address and address + size <= load.end), None)

    def zero_ranges(self):
        # Keep the complete segment zero tail, including linker-owned padding beyond .bss.
        ranges = []
        for load in self.loads:
            start, end = load.address + load.file_size, load.end
            if start == end:
                continue
            if ranges and ranges[-1][1] == start:
                ranges[-1] = (ranges[-1][0], end)
            else:
                ranges.append((start, end))
        return ranges


def parse_image(data):
    if len(data) < ELF_HEADER.size:
        raise LayoutError("truncated ELF header")
    (ident, kind, machine, version, entry, phoff, shoff, _, ehsize,
     phentsize, phnum, shentsize, shnum, shstrndx) = ELF_HEADER.unpack_from(data)
    if ident[:4] != b"\x7fELF" or ident[4:7] != b"\x02\x01\x01":
        raise LayoutError("expected ELF64 little-endian version 1")
    if kind not in (2, 3) or version != 1 or ehsize != ELF_HEADER.size:
        raise LayoutError("invalid executable ELF header")
    if phnum in (0, 0xffff) or phentsize != PROGRAM_HEADER.size:
        raise LayoutError("missing or unsupported program-header table")
    if shoff == 0 or shnum == 0 or shentsize != SECTION_HEADER.size:
        raise LayoutError("boot layout verification requires an ordinary section-header table")
    if shstrndx == 0 or shstrndx >= shnum:
        raise LayoutError("missing or unsupported section-name table")
    extent(phoff, phnum * phentsize, len(data), "program-header table")
    extent(shoff, shnum * shentsize, len(data), "section-header table")

    loads = []
    for index in range(phnum):
        ptype, flags, offset, address, physical, filesz, memsz, align = PROGRAM_HEADER.unpack_from(
            data, phoff + index * phentsize)
        if ptype != PT_LOAD:
            continue
        label = f"PT_LOAD[{index}]"
        if filesz > memsz:
            raise LayoutError(f"{label}: p_filesz exceeds p_memsz")
        extent(offset, filesz, len(data), label + " file")
        extent(address, memsz, U64_MAX, label + " virtual")
        extent(physical, memsz, U64_MAX, label + " physical")
        alignment(align, label)
        if align > 1 and offset % align != address % align:
            raise LayoutError(f"{label}: p_offset {offset:#x} and p_vaddr {address:#x} "
                              f"are incongruent modulo p_align {align:#x}")
        if memsz:
            loads.append(Load(offset, address, physical, filesz, memsz, flags))
    loads.sort(key=lambda load: load.address)
    if not loads:
        raise LayoutError("no nonempty PT_LOAD segments")
    for previous, current in zip(loads, loads[1:]):
        if previous.end > current.address:
            raise LayoutError("overlapping PT_LOAD memory ranges have ambiguous boot ownership")

    headers = [SECTION_HEADER.unpack_from(data, shoff + index * shentsize)
               for index in range(shnum)]
    names_header = headers[shstrndx]
    if names_header[1] != 3:
        raise LayoutError("section-name table is not SHT_STRTAB")
    names_start, names_size = names_header[4], names_header[5]
    names_end = extent(names_start, names_size, len(data), "section-name table")
    names = data[names_start:names_end]
    sections = []
    for index, (name, skind, flags, address, offset, size, _, _, align, _) in enumerate(headers):
        if not flags & SHF_ALLOC:
            continue
        if name >= len(names):
            raise LayoutError(f"allocated section[{index}]: invalid name offset")
        end = names.find(b"\0", name)
        if end < 0:
            raise LayoutError(f"allocated section[{index}]: unterminated name")
        section_name = names[name:end].decode("utf-8", errors="backslashreplace")
        extent(address, size, U64_MAX, section_name + " virtual")
        alignment(align, section_name)
        if align > 1 and address % align:
            raise LayoutError(f"{section_name}: unaligned allocated section")
        if skind != SHT_NOBITS:
            extent(offset, size, len(data), section_name + " file")
        sections.append(Section(section_name, skind, flags, address, offset, size))

    image = Image(data, machine, kind, entry, loads, sections)
    if not any(load.flags & PF_X and load.address <= entry < load.address + load.file_size
               for load in loads):
        raise LayoutError(f"entry {entry:#x} is not in initialized executable PT_LOAD memory")
    if not sections:
        raise LayoutError("no allocated sections to verify")
    if not any(section.kind != SHT_NOBITS and section.flags & SHF_EXECINSTR
               and section.address <= entry < section.address + section.size for section in sections):
        raise LayoutError(f"entry {entry:#x} is not in an initialized executable allocated section")
    for section in sections:
        if section.size == 0:
            continue
        load = image.covering_load(section.address, section.size)
        if load is None:
            raise LayoutError(f"{section.name}: full allocated extent is not covered by PT_LOAD")
        if section.kind == SHT_NOBITS:
            if section.address < load.address + load.file_size:
                raise LayoutError(f"{section.name}: NOBITS memory is not entirely zero-filled")
        else:
            delta = section.address - load.address
            if delta + section.size > load.file_size or section.offset != load.offset + delta:
                raise LayoutError(f"{section.name}: initialized section does not match PT_LOAD bytes")
    return image


def compare_images(before, after):
    if (before.machine, before.kind, before.entry) != (after.machine, after.kind, after.entry):
        raise LayoutError("strip changed the machine, image type, or entry address")
    if before.zero_ranges() != after.zero_ranges():
        raise LayoutError("strip changed PT_LOAD zero-fill ranges")
    original = sorted(before.sections, key=lambda section: section.identity)
    stripped = sorted(after.sections, key=lambda section: section.identity)
    if [section.identity for section in original] != [section.identity for section in stripped]:
        raise LayoutError("strip changed allocated section identity or virtual extent")
    for source, target in zip(original, stripped):
        if source.size == 0:
            continue
        source_load = before.covering_load(source.address, source.size)
        target_load = after.covering_load(target.address, target.size)
        if (source_load.flags, source_load.physical - source_load.address) != (
                target_load.flags, target_load.physical - target_load.address):
            raise LayoutError(f"{source.name}: strip changed load permissions or physical placement")
        if source.kind != SHT_NOBITS and (
                before.data[source.offset:source.offset + source.size] !=
                after.data[target.offset:target.offset + target.size]):
            raise LayoutError(f"{source.name}: strip changed initialized runtime bytes")


def read_image(path):
    try:
        return parse_image(Path(path).read_bytes())
    except (OSError, LayoutError) as error:
        raise LayoutError(f"{path}: {error}") from error


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    validate = commands.add_parser("validate")
    validate.add_argument("images", nargs="+")
    compare = commands.add_parser("compare")
    compare.add_argument("before")
    compare.add_argument("after")
    args = parser.parse_args(argv)
    try:
        if args.command == "validate":
            for path in args.images:
                read_image(path)
        else:
            compare_images(read_image(args.before), read_image(args.after))
    except LayoutError as error:
        print(f"error: ELF load layout: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
