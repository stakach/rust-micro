import contextlib
import io
from pathlib import Path
import struct
import tempfile
import unittest

from verify_elf_layout import (
    ELF_HEADER, PROGRAM_HEADER, SECTION_HEADER, LayoutError, compare_images, main, parse_image,
)


def executable(*, base=0x401000, offset=0x1000, align=0x1000, bss_size=0x2000,
               memory_size=None, code=b"\x90" * 16, shoff=None, entry=None):
    names = b"\0.text\0.bss\0.shstrtab\0"
    names_offset = offset + len(code)
    if shoff is None:
        shoff = (names_offset + len(names) + 0xff) & ~0xff
    data = bytearray(max(shoff + 4 * SECTION_HEADER.size, names_offset + len(names), 120))
    ident = b"\x7fELF\x02\x01\x01" + b"\0" * 9
    ELF_HEADER.pack_into(data, 0, ident, 2, 62, 1, base if entry is None else entry,
                         64, shoff, 0, 64, 56, 1, 64, 4, 3)
    PROGRAM_HEADER.pack_into(data, 64, 1, 7, offset, base, base, len(code),
                             len(code) + bss_size if memory_size is None else memory_size, align)
    data[offset:offset + len(code)] = code
    data[names_offset:names_offset + len(names)] = names
    SECTION_HEADER.pack_into(data, shoff, *([0] * 10))
    SECTION_HEADER.pack_into(data, shoff + 64, 1, 1, 6, base, offset, len(code), 0, 0, 16, 0)
    SECTION_HEADER.pack_into(data, shoff + 128, 7, 8, 3, base + len(code),
                             offset + len(code), bss_size, 0, 0, 16, 0)
    SECTION_HEADER.pack_into(data, shoff + 192, 12, 3, 0, 0, names_offset, len(names), 0, 0, 1, 0)
    return data


class ElfLayoutTests(unittest.TestCase):
    def test_valid_initialized_and_large_zero_fill_ranges(self):
        data = executable(bss_size=128 * 1024 * 1024)
        image = parse_image(data)
        self.assertLess(len(data), 8192, "NOBITS validation must not materialize virtual memory")
        self.assertEqual(image.zero_ranges(), [(0x401010, 0x401010 + 128 * 1024 * 1024)])
        compare_images(image, parse_image(data))

    def test_relocated_file_layout_and_metadata_are_allowed(self):
        before = parse_image(executable())
        after = parse_image(executable(offset=0x2000, shoff=0x2400))
        compare_images(before, after)
        self.assertNotEqual(before.data[:64], after.data[:64])

    def test_original_kernel_offset_zero_shifted_origin_is_rejected(self):
        # Actual failure geometry: LOAD begins at file zero but VA is 8 KiB into a 2 MiB span.
        data = executable(base=0xfe002000)
        struct.pack_into("<Q", data, 64 + 8, 0)
        struct.pack_into("<Q", data, 64 + 48, 0x200000)
        with self.assertRaisesRegex(LayoutError, "incongruent"):
            parse_image(data)

    def test_strip_shift_dropping_last_two_bss_pages_is_rejected(self):
        data = executable(base=0xfe002000, offset=0x2000, align=0x200000, bss_size=0x6000)
        parse_image(data)
        # Model strip's header-alignment repair without extending p_memsz: .bss stays in place.
        struct.pack_into("<Q", data, 64 + 8, 0)
        struct.pack_into("<Q", data, 64 + 16, 0xfe000000)
        struct.pack_into("<Q", data, 64 + 24, 0xfe000000)
        struct.pack_into("<Q", data, 64 + 32, 0x2010)
        with self.assertRaisesRegex(LayoutError, "full allocated extent"):
            parse_image(data)

    def test_initialized_code_change_is_rejected(self):
        before = parse_image(executable())
        after = parse_image(executable(code=b"\xcc" + b"\x90" * 15))
        with self.assertRaisesRegex(LayoutError, "initialized runtime bytes"):
            compare_images(before, after)

    def test_lost_zero_padding_is_rejected_even_if_bss_still_fits(self):
        before = parse_image(executable(memory_size=0x4010))
        after = parse_image(executable(memory_size=0x3010))
        with self.assertRaisesRegex(LayoutError, "zero-fill ranges"):
            compare_images(before, after)

    def test_changed_allocated_flags_and_permissions_are_rejected(self):
        before = parse_image(executable())
        data = executable()
        shoff = ELF_HEADER.unpack_from(data)[6]
        struct.pack_into("<Q", data, shoff + 64 + 8, 7)
        with self.assertRaisesRegex(LayoutError, "section identity"):
            compare_images(before, parse_image(data))
        data = executable()
        struct.pack_into("<I", data, 64 + 4, 5)
        with self.assertRaisesRegex(LayoutError, "permissions"):
            compare_images(before, parse_image(data))

    def test_entry_must_be_initialized_and_executable(self):
        with self.assertRaisesRegex(LayoutError, "entry"):
            parse_image(executable(entry=0x401010))
        data = executable()
        struct.pack_into("<I", data, 64 + 4, 6)
        with self.assertRaisesRegex(LayoutError, "entry"):
            parse_image(data)

    def test_filesz_larger_than_memsz_is_rejected(self):
        with self.assertRaisesRegex(LayoutError, "p_filesz"):
            parse_image(executable(memory_size=8))

    def test_exact_u64_end_is_not_representable_by_the_loader(self):
        with self.assertRaisesRegex(LayoutError, "virtual.*range"):
            parse_image(executable(base=(1 << 64) - 0x1000, bss_size=0xff0))

    def test_entry_cannot_point_into_rewritable_elf_metadata(self):
        data = executable()
        struct.pack_into("<Q", data, 24, 0x400000)
        struct.pack_into("<Q", data, 64 + 8, 0)
        struct.pack_into("<Q", data, 64 + 16, 0x400000)
        struct.pack_into("<Q", data, 64 + 24, 0x400000)
        struct.pack_into("<Q", data, 64 + 32, 0x1010)
        struct.pack_into("<Q", data, 64 + 40, 0x3010)
        with self.assertRaisesRegex(LayoutError, "entry.*allocated section"):
            parse_image(data)

    def test_truncated_header_and_tables_fail_closed(self):
        for size in (0, 16, 63, 119):
            with self.subTest(size=size), self.assertRaises(LayoutError):
                parse_image(executable()[:size])
        with self.assertRaisesRegex(LayoutError, "section-header table"):
            parse_image(executable()[:-1])

    def test_overflowed_virtual_and_file_extents_are_rejected(self):
        for field, value in ((16, (1 << 64) - 0x1000), (8, (1 << 64) - 8)):
            data = executable()
            struct.pack_into("<Q", data, 64 + field, value)
            with self.subTest(field=field), self.assertRaisesRegex(LayoutError, "range"):
                parse_image(data)

    def test_wrong_section_file_mapping_is_rejected(self):
        data = executable()
        shoff = ELF_HEADER.unpack_from(data)[6]
        struct.pack_into("<Q", data, shoff + 64 + 24, 0x1001)
        with self.assertRaisesRegex(LayoutError, "does not match PT_LOAD"):
            parse_image(data)

    def test_nobits_cannot_overlap_initialized_memory(self):
        data = executable()
        struct.pack_into("<Q", data, 64 + 32, 32)
        with self.assertRaisesRegex(LayoutError, "not entirely zero-filled"):
            parse_image(data)

    def test_unsupported_format_and_nonpower_alignment_are_rejected(self):
        data = executable()
        data[4] = 1
        with self.assertRaisesRegex(LayoutError, "ELF64"):
            parse_image(data)
        data = executable()
        struct.pack_into("<Q", data, 64 + 48, 24)
        with self.assertRaisesRegex(LayoutError, "power of two"):
            parse_image(data)

    def test_cli_reports_input_path_and_does_not_modify_files(self):
        with tempfile.TemporaryDirectory() as directory:
            before = Path(directory) / "before.elf"
            after = Path(directory) / "after.elf"
            before.write_bytes(executable())
            after.write_bytes(executable(offset=0x2000))
            original = after.read_bytes()
            self.assertEqual(main(["validate", str(before), str(after)]), 0)
            self.assertEqual(main(["compare", str(before), str(after)]), 0)
            self.assertEqual(after.read_bytes(), original)
            after.write_bytes(b"bad")
            errors = io.StringIO()
            with contextlib.redirect_stderr(errors):
                self.assertEqual(main(["validate", str(after)]), 1)
            self.assertIn(str(after), errors.getvalue())


if __name__ == "__main__":
    unittest.main()
