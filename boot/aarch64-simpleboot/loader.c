/*
 * Simpleboot-compatible first stage for QEMU's AArch64 virt machine.
 *
 * QEMU supplies a Linux-style FDT entry to this loader. The loader owns that
 * platform-specific contract, loads the ELF kernel from the initrd, starts
 * every FDT-advertised CPU, and enters the kernel using Simpleboot's 64-bit
 * Multiboot2 ABI: x0=0x36d76289, x1=MBI address on every CPU.
 */

#include <stddef.h>
#include <stdint.h>

#define MAX_CPUS 4u
#define STACK_SIZE (1u << 16)
#define MBI_CAPACITY 4096u

#define FDT_MAGIC 0xd00dfeedu
#define FDT_BEGIN_NODE 1u
#define FDT_END_NODE 2u
#define FDT_PROP 3u
#define FDT_NOP 4u
#define FDT_END 9u

#define PT_LOAD 1u
#define EM_AARCH64 183u

#define MULTIBOOT_TAG_END 0u
#define MULTIBOOT_TAG_MODULE 3u
#define MULTIBOOT_TAG_MMAP 6u
#define MULTIBOOT_TAG_SMP 257u
#define MULTIBOOT_TAG_KERNEL 259u
#define MULTIBOOT_MEMORY_AVAILABLE 1u

#define PSCI_0_2_FN64_CPU_ON 0xc4000003u

typedef struct {
    uint64_t memory_base;
    uint64_t memory_size;
    uint64_t initrd_start;
    uint64_t initrd_end;
    uint64_t cpus[MAX_CPUS];
    uint32_t cpu_count;
    uint32_t psci_hvc;
} boot_info_t;

typedef struct {
    uint32_t type;
    uint32_t flags;
    uint64_t offset;
    uint64_t vaddr;
    uint64_t paddr;
    uint64_t filesz;
    uint64_t memsz;
    uint64_t align;
} elf64_phdr_t;

typedef struct {
    uint32_t type;
    uint32_t size;
    uint32_t start;
    uint32_t end;
} module_tag_t;

typedef struct {
    uint32_t type;
    uint32_t size;
    uint32_t entry_size;
    uint32_t entry_version;
    uint64_t base;
    uint64_t length;
    uint32_t memory_type;
    uint32_t reserved;
} mmap_tag_t;

typedef struct {
    uint32_t type;
    uint32_t size;
    uint32_t numcores;
    uint32_t running;
    uint32_t bspid;
} smp_tag_t;

typedef struct {
    uint64_t entry;
    uint64_t load_start;
    uint64_t load_end;
} loaded_kernel_t;

__attribute__((aligned(STACK_SIZE))) uint8_t loader_stacks[MAX_CPUS][STACK_SIZE];
__attribute__((aligned(4096))) static uint8_t mbi[MBI_CAPACITY];

volatile uint32_t loader_ap_online[MAX_CPUS];
volatile uint32_t loader_handoff_ready;
volatile uint64_t loader_kernel_entry;
volatile uint64_t loader_mbi_address;

extern void loader_secondary_entry(void);
extern void loader_enter_kernel(uint64_t entry, uint64_t mbi_address) __attribute__((noreturn));

static inline uint32_t be32(const void *address)
{
    const uint8_t *p = address;
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static inline uint16_t le16(const void *address)
{
    const uint8_t *p = address;
    return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

static inline uint64_t le64(const void *address)
{
    const uint8_t *p = address;
    uint64_t value = 0;
    for (uint32_t index = 0; index < 8; ++index) {
        value |= (uint64_t)p[index] << (index * 8);
    }
    return value;
}

static void *copy_bytes(void *destination, const void *source, size_t length)
{
    uint8_t *dst = destination;
    const uint8_t *src = source;
    while (length-- != 0) {
        *dst++ = *src++;
    }
    return destination;
}

static void zero_bytes(void *destination, size_t length)
{
    uint8_t *dst = destination;
    while (length-- != 0) {
        *dst++ = 0;
    }
}

static int bytes_equal(const void *left, const char *right, size_t length)
{
    const uint8_t *lhs = left;
    for (size_t index = 0; index < length; ++index) {
        if (lhs[index] != (uint8_t)right[index]) {
            return 0;
        }
    }
    return 1;
}

static int cstr_equal(const char *left, const char *right)
{
    while (*left != 0 && *right != 0 && *left == *right) {
        ++left;
        ++right;
    }
    return *left == *right;
}

static int cstr_starts_with(const char *value, const char *prefix)
{
    while (*prefix != 0) {
        if (*value++ != *prefix++) {
            return 0;
        }
    }
    return 1;
}

static size_t bounded_cstr_length(const char *value, size_t available)
{
    size_t length = 0;
    while (length < available && value[length] != 0) {
        ++length;
    }
    return length;
}

static void uart_putc(char byte)
{
    volatile uint32_t *data = (volatile uint32_t *)0x09000000u;
    volatile uint32_t *flags = (volatile uint32_t *)0x09000018u;
    while ((*flags & (1u << 5)) != 0) {
        __asm__ volatile("yield");
    }
    *data = (uint32_t)(uint8_t)byte;
}

static void uart_puts(const char *message)
{
    while (*message != 0) {
        uart_putc(*message++);
    }
}

static void fail(const char *message) __attribute__((noreturn));
static void fail(const char *message)
{
    uart_puts("Simpleboot AArch64: ");
    uart_puts(message);
    uart_puts("\n");
    for (;;) {
        __asm__ volatile("wfe");
    }
}

static uint64_t read_cells(const uint8_t *data, uint32_t cells)
{
    uint64_t value = 0;
    for (uint32_t index = 0; index < cells; ++index) {
        value = (value << 32) | be32(data + index * 4);
    }
    return value;
}

static void parse_fdt(uint64_t fdt_address, boot_info_t *info)
{
    const uint8_t *fdt = (const uint8_t *)(uintptr_t)fdt_address;
    if (fdt_address == 0 || (fdt_address & 7u) != 0 || be32(fdt) != FDT_MAGIC) {
        fail("invalid QEMU FDT");
    }

    uint32_t total_size = be32(fdt + 4);
    uint32_t structure_offset = be32(fdt + 8);
    uint32_t strings_offset = be32(fdt + 12);
    uint32_t strings_size = be32(fdt + 32);
    uint32_t structure_size = be32(fdt + 36);
    if (total_size < 40 || structure_offset + structure_size > total_size ||
        strings_offset + strings_size > total_size) {
        fail("malformed QEMU FDT");
    }

    const uint8_t *cursor = fdt + structure_offset;
    const uint8_t *structure_end = cursor + structure_size;
    const char *strings = (const char *)(fdt + strings_offset);
    const char *nodes[8] = {0};
    int32_t depth = -1;
    uint32_t root_address_cells = 2;
    uint32_t root_size_cells = 2;
    uint32_t cpu_address_cells = 1;

    while (cursor + 4 <= structure_end) {
        uint32_t token = be32(cursor);
        cursor += 4;
        if (token == FDT_BEGIN_NODE) {
            ++depth;
            if (depth >= 8) {
                fail("FDT nesting is too deep");
            }
            nodes[depth] = (const char *)cursor;
            size_t available = (size_t)(structure_end - cursor);
            size_t length = bounded_cstr_length((const char *)cursor, available);
            if (length == available) {
                fail("unterminated FDT node");
            }
            cursor += (length + 1 + 3) & ~(size_t)3;
        } else if (token == FDT_END_NODE) {
            --depth;
        } else if (token == FDT_PROP) {
            if (cursor + 8 > structure_end || depth < 0) {
                fail("malformed FDT property");
            }
            uint32_t length = be32(cursor);
            uint32_t name_offset = be32(cursor + 4);
            cursor += 8;
            if (cursor + length > structure_end || name_offset >= strings_size) {
                fail("invalid FDT property bounds");
            }
            const char *name = strings + name_offset;
            const uint8_t *data = cursor;

            if (depth == 0 && cstr_equal(name, "#address-cells") && length == 4) {
                root_address_cells = be32(data);
            } else if (depth == 0 && cstr_equal(name, "#size-cells") && length == 4) {
                root_size_cells = be32(data);
            } else if (depth == 1 && cstr_equal(nodes[1], "cpus") &&
                       cstr_equal(name, "#address-cells") && length == 4) {
                cpu_address_cells = be32(data);
            } else if (depth == 1 && cstr_starts_with(nodes[1], "memory@") &&
                       cstr_equal(name, "reg") &&
                       length >= (root_address_cells + root_size_cells) * 4) {
                info->memory_base = read_cells(data, root_address_cells);
                info->memory_size = read_cells(data + root_address_cells * 4, root_size_cells);
            } else if (depth == 1 && cstr_equal(nodes[1], "chosen") &&
                       cstr_equal(name, "linux,initrd-start")) {
                info->initrd_start = read_cells(data, length / 4);
            } else if (depth == 1 && cstr_equal(nodes[1], "chosen") &&
                       cstr_equal(name, "linux,initrd-end")) {
                info->initrd_end = read_cells(data, length / 4);
            } else if (depth == 1 && cstr_equal(nodes[1], "psci") &&
                       cstr_equal(name, "method") && length >= 4) {
                info->psci_hvc = bytes_equal(data, "hvc", 3);
            } else if (depth == 2 && cstr_equal(nodes[1], "cpus") &&
                       cstr_starts_with(nodes[2], "cpu@") && cstr_equal(name, "reg") &&
                       length >= cpu_address_cells * 4 && info->cpu_count < MAX_CPUS) {
                info->cpus[info->cpu_count++] = read_cells(data, cpu_address_cells);
            }
            cursor += (length + 3) & ~3u;
        } else if (token == FDT_NOP) {
            continue;
        } else if (token == FDT_END) {
            break;
        } else {
            fail("unknown FDT token");
        }
    }

    if (info->memory_size == 0 || info->initrd_end <= info->initrd_start ||
        info->cpu_count == 0 || !info->psci_hvc) {
        fail("FDT lacks memory, initrd, CPUs, or PSCI HVC");
    }
}

static uint64_t tar_octal(const uint8_t *field, size_t length)
{
    uint64_t value = 0;
    for (size_t index = 0; index < length; ++index) {
        uint8_t byte = field[index];
        if (byte == 0 || byte == ' ') {
            continue;
        }
        if (byte < '0' || byte > '7') {
            return 0;
        }
        value = (value << 3) | (uint64_t)(byte - '0');
    }
    return value;
}

static const uint8_t *find_tar_file(uint64_t start, uint64_t end, const char *wanted,
                                    uint64_t *file_size)
{
    const uint8_t *cursor = (const uint8_t *)(uintptr_t)start;
    const uint8_t *limit = (const uint8_t *)(uintptr_t)end;
    while (cursor + 512 <= limit && cursor[0] != 0) {
        uint64_t size = tar_octal(cursor + 124, 12);
        const uint8_t *contents = cursor + 512;
        if (contents + size > limit) {
            fail("truncated initrd archive");
        }
        if (cstr_equal((const char *)cursor, wanted)) {
            *file_size = size;
            return contents;
        }
        cursor = contents + ((size + 511) & ~511u);
    }
    return 0;
}

static loaded_kernel_t load_kernel(const uint8_t *elf, uint64_t size)
{
    loaded_kernel_t loaded = {0, ~(uint64_t)0, 0};
    if (size < 64 || !bytes_equal(elf, "\x7f" "ELF", 4) || elf[4] != 2 || elf[5] != 1 ||
        le16(elf + 18) != EM_AARCH64) {
        fail("boot/kernel is not an AArch64 ELF64 image");
    }
    uint64_t phoff = le64(elf + 32);
    uint16_t phentsize = le16(elf + 54);
    uint16_t phnum = le16(elf + 56);
    loaded.entry = le64(elf + 24);
    if (phentsize < sizeof(elf64_phdr_t) || phoff + (uint64_t)phentsize * phnum > size) {
        fail("invalid kernel program headers");
    }

    for (uint16_t index = 0; index < phnum; ++index) {
        const elf64_phdr_t *phdr =
            (const elf64_phdr_t *)(const void *)(elf + phoff + (uint64_t)index * phentsize);
        if (phdr->type != PT_LOAD) {
            continue;
        }
        uint64_t destination = phdr->paddr != 0 ? phdr->paddr : phdr->vaddr;
        if (phdr->filesz > phdr->memsz || phdr->offset + phdr->filesz > size ||
            destination + phdr->memsz < destination) {
            fail("invalid kernel load segment");
        }
        copy_bytes((void *)(uintptr_t)destination, elf + phdr->offset, phdr->filesz);
        zero_bytes((void *)(uintptr_t)(destination + phdr->filesz), phdr->memsz - phdr->filesz);
        if (destination < loaded.load_start) {
            loaded.load_start = destination;
        }
        if (destination + phdr->memsz > loaded.load_end) {
            loaded.load_end = destination + phdr->memsz;
        }
    }
    if (loaded.load_end == 0 || loaded.entry < loaded.load_start || loaded.entry >= loaded.load_end) {
        fail("kernel has no usable load segment");
    }

    for (uint64_t address = loaded.load_start & ~63u; address < loaded.load_end; address += 64) {
        __asm__ volatile("dc cvau, %0" : : "r"(address) : "memory");
    }
    __asm__ volatile("dsb ish" : : : "memory");
    for (uint64_t address = loaded.load_start & ~63u; address < loaded.load_end; address += 64) {
        __asm__ volatile("ic ivau, %0" : : "r"(address) : "memory");
    }
    __asm__ volatile("dsb ish; isb" : : : "memory");
    return loaded;
}

static uint8_t *append_tag(uint8_t *cursor, uint32_t type, uint32_t size)
{
    uint32_t padded = (size + 7u) & ~7u;
    if ((size_t)(cursor - mbi) + padded > MBI_CAPACITY) {
        fail("MBI buffer exhausted");
    }
    zero_bytes(cursor, padded);
    *(uint32_t *)(void *)cursor = type;
    *(uint32_t *)(void *)(cursor + 4) = size;
    return cursor + padded;
}

static uint64_t build_mbi(const boot_info_t *info, loaded_kernel_t kernel, uint32_t running)
{
    zero_bytes(mbi, sizeof(mbi));
    uint8_t *cursor = mbi + 8;

    mmap_tag_t *mmap = (mmap_tag_t *)(void *)cursor;
    cursor = append_tag(cursor, MULTIBOOT_TAG_MMAP, sizeof(*mmap));
    mmap->entry_size = 24;
    mmap->entry_version = 0;
    mmap->base = info->memory_base;
    mmap->length = info->memory_size;
    mmap->memory_type = MULTIBOOT_MEMORY_AVAILABLE;

    module_tag_t *module = (module_tag_t *)(void *)cursor;
    cursor = append_tag(cursor, MULTIBOOT_TAG_MODULE, sizeof(*module));
    module->start = (uint32_t)info->initrd_start;
    module->end = (uint32_t)info->initrd_end;

    module_tag_t *kernel_tag = (module_tag_t *)(void *)cursor;
    cursor = append_tag(cursor, MULTIBOOT_TAG_KERNEL, sizeof(*kernel_tag));
    kernel_tag->start = (uint32_t)kernel.load_start;
    kernel_tag->end = (uint32_t)kernel.load_end;

    smp_tag_t *smp = (smp_tag_t *)(void *)cursor;
    cursor = append_tag(cursor, MULTIBOOT_TAG_SMP, sizeof(*smp));
    smp->numcores = info->cpu_count;
    smp->running = running;
    smp->bspid = 0;

    cursor = append_tag(cursor, MULTIBOOT_TAG_END, 8);
    *(uint32_t *)(void *)mbi = (uint32_t)(cursor - mbi);
    *(uint32_t *)(void *)(mbi + 4) = 0;
    return (uint64_t)(uintptr_t)mbi;
}

static int64_t psci_cpu_on(uint64_t target, uint64_t entry, uint64_t context)
{
    register uint64_t x0 __asm__("x0") = PSCI_0_2_FN64_CPU_ON;
    register uint64_t x1 __asm__("x1") = target;
    register uint64_t x2 __asm__("x2") = entry;
    register uint64_t x3 __asm__("x3") = context;
    __asm__ volatile("hvc #0" : "+r"(x0) : "r"(x1), "r"(x2), "r"(x3) : "memory");
    return (int64_t)x0;
}

static uint64_t current_mpidr(void)
{
    uint64_t value;
    __asm__ volatile("mrs %0, mpidr_el1" : "=r"(value));
    return value & 0xff00ffffffu;
}

void loader_main(uint64_t fdt_address)
{
    boot_info_t info;
    zero_bytes(&info, sizeof(info));
    parse_fdt(fdt_address, &info);

    uint64_t kernel_size = 0;
    const uint8_t *kernel_elf =
        find_tar_file(info.initrd_start, info.initrd_end, "boot/kernel", &kernel_size);
    if (kernel_elf == 0) {
        fail("initrd missing boot/kernel");
    }
    loaded_kernel_t kernel = load_kernel(kernel_elf, kernel_size);

    uint64_t bsp = current_mpidr();
    uint32_t running = 1;
    for (uint32_t index = 0; index < info.cpu_count; ++index) {
        uint64_t target = info.cpus[index];
        if (target == bsp) {
            continue;
        }
        uint32_t logical_id = (uint32_t)(target & 0xffu);
        if (logical_id >= MAX_CPUS) {
            fail("CPU affinity exceeds loader limit");
        }
        if (psci_cpu_on(target, (uint64_t)(uintptr_t)&loader_secondary_entry, logical_id) != 0) {
            fail("PSCI CPU_ON failed");
        }
        while (loader_ap_online[logical_id] == 0) {
            __asm__ volatile("wfe");
        }
        ++running;
    }

    uint64_t mbi_address = build_mbi(&info, kernel, running);
    loader_kernel_entry = kernel.entry;
    loader_mbi_address = mbi_address;
    __asm__ volatile("dmb ishst" : : : "memory");
    __atomic_store_n(&loader_handoff_ready, 1, __ATOMIC_RELEASE);
    __asm__ volatile("sev");

    uart_puts("Simpleboot AArch64: entering kernel on all cores\n");
    loader_enter_kernel(kernel.entry, mbi_address);
}
