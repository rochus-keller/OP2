/*
 * bin2espelf.c — Convert a raw binary image to a minimal ELF32 for ESP32-P4
 *
 * Produces an ELF32 executable targeting RISC-V (EM_RISCV = 0xF3) with:
 *   - One PT_LOAD segment at the specified base address
 *   - Entry point at the base address (the image header contains JAL to real entry)
 *   - Optional esp_app_desc_t in a .rodata_desc section (required by standard bootloader)
 *
 * Usage:
 *   bin2espelf [--base <hex_addr>] [--no-desc] -o <output.elf> <input.bin>
 *
 * Defaults:
 *   --base 4FF00000   (ESP32-P4 HP SRAM start)
 *
 * Compile:
 *   cc -std=c99 -O2 -Wall -o bin2espelf bin2espelf.c
 *
 * Copyright 2026, placed in the public domain.
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

typedef uint16_t Elf32_Half;
typedef uint32_t Elf32_Word;
typedef uint32_t Elf32_Addr;
typedef uint32_t Elf32_Off;

typedef struct {
    unsigned char e_ident[16];
    Elf32_Half e_type;
    Elf32_Half e_machine;
    Elf32_Word e_version;
    Elf32_Addr e_entry;
    Elf32_Off  e_phoff;
    Elf32_Off  e_shoff;
    Elf32_Word e_flags;
    Elf32_Half e_ehsize;
    Elf32_Half e_phentsize;
    Elf32_Half e_phnum;
    Elf32_Half e_shentsize;
    Elf32_Half e_shnum;
    Elf32_Half e_shstrndx;
} Elf32_Ehdr;

typedef struct {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
} Elf32_Phdr;

typedef struct {
    Elf32_Word sh_name;
    Elf32_Word sh_type;
    Elf32_Word sh_flags;
    Elf32_Addr sh_addr;
    Elf32_Off  sh_offset;
    Elf32_Word sh_size;
    Elf32_Word sh_link;
    Elf32_Word sh_info;
    Elf32_Word sh_addralign;
    Elf32_Word sh_entsize;
} Elf32_Shdr;

#define ET_EXEC    2
#define EM_RISCV   0xF3
#define PT_LOAD    1
#define PF_X       1
#define PF_W       2
#define PF_R       4
#define SHT_PROGBITS 1
#define SHT_STRTAB   3
#define SHF_ALLOC    2
#define SHF_EXECINSTR 4

#define ESP_APP_DESC_MAGIC 0xABCD5432u

/* Default base address of ESP32-P4 HP SRAM */
#define DEFAULT_BASE 0x4FF00000u

static void write_le32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v);
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

static void write_le16(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)(v);
    p[1] = (uint8_t)(v >> 8);
}

/* Generate esp_app_desc_t (256 bytes) */
static void generate_app_desc(uint8_t desc[256], const char *project_name) {
    memset(desc, 0, 256);
    write_le32(desc + 0, ESP_APP_DESC_MAGIC);
    write_le32(desc + 4, 0); /* secure_version at offset 4 */
    strncpy((char *)(desc + 16), "1.0.0", 31);
    strncpy((char *)(desc + 48), project_name, 31);
    /* time[16] at offset 80 */
    {
        time_t now = time(NULL);
        struct tm *t = localtime(&now);
        strftime((char *)(desc + 80), 15, "%H:%M:%S", t);
        strftime((char *)(desc + 96), 15, "%b %d %Y", t);
    }
    /* idf_ver[32] at offset 112 */
    strncpy((char *)(desc + 112), "standalone", 31);
}

static void usage(void) {
    fprintf(stderr,
        "Usage: bin2espelf [options] -o <output.elf> <input.bin>\n"
        "\n"
        "Options:\n"
        "  --base <hex>    Segment load address (default: 4FF00000 = ESP32-P4 HP SRAM)\n"
        "  --no-desc       Omit esp_app_desc_t (binary placed directly at --base)\n"
        "  --name <str>    Project name in app descriptor (default: from input filename)\n"
        "  -o <file>       Output ELF file (required)\n"
        "\n"
        "Without --no-desc (default):\n"
        "  The segment starts at --base with a 4096-byte page containing the\n"
        "  esp_app_desc_t (padded). The binary follows at --base + 0x1000.\n"
        "  Link the binary with multibootlinker --base <base+1000>.\n"
        "  Entry point = --base + 0x1000.\n"
        "\n"
        "With --no-desc:\n"
        "  The binary is placed directly at --base. Entry = --base.\n"
        "  Use espflash --skip-update-check (or older: --ignore-app-descriptor).\n"
        "  Link the binary with multibootlinker --base <same as --base>.\n"
    );
}

int main(int argc, char **argv) {
    const char *input = NULL;
    const char *output = NULL;
    const char *proj_name = NULL;
    uint32_t base_addr = DEFAULT_BASE;
    int include_desc = 1;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--base") == 0 && i + 1 < argc) {
            base_addr = (uint32_t)strtoul(argv[++i], NULL, 16);
        } else if (strcmp(argv[i], "--no-desc") == 0) {
            include_desc = 0;
        } else if (strcmp(argv[i], "--name") == 0 && i + 1 < argc) {
            proj_name = argv[++i];
        } else if (strcmp(argv[i], "-o") == 0 && i + 1 < argc) {
            output = argv[++i];
        } else if (argv[i][0] != '-') {
            input = argv[i];
        } else {
            fprintf(stderr, "Unknown option: %s\n", argv[i]);
            usage();
            return 1;
        }
    }

    if (!input || !output) {
        usage();
        return 1;
    }

    /* Derive project name from input filename if not given */
    char name_buf[32];
    if (!proj_name) {
        const char *p = strrchr(input, '/');
        p = p ? p + 1 : input;
        strncpy(name_buf, p, 31);
        name_buf[31] = 0;
        char *dot = strrchr(name_buf, '.');
        if (dot) *dot = 0;
        proj_name = name_buf;
    }

    /* Read input binary */
    FILE *fin = fopen(input, "rb");
    if (!fin) {
        perror(input);
        return 1;
    }
    fseek(fin, 0, SEEK_END);
    long bin_size = ftell(fin);
    fseek(fin, 0, SEEK_SET);
    uint8_t *bin_data = (uint8_t *)malloc((size_t)bin_size);
    if (!bin_data || fread(bin_data, 1, (size_t)bin_size, fin) != (size_t)bin_size) {
        fprintf(stderr, "Failed to read %s\n", input);
        fclose(fin);
        return 1;
    }
    fclose(fin);

    /* Validate: first word should be a JAL x0 instruction (opcode bits [6:0] = 0x6F, rd=x0) */
    if (bin_size < 16) {
        fprintf(stderr, "Error: binary too small (need at least 16 bytes for image header)\n");
        return 1;
    }
    uint32_t first_word = bin_data[0] | (bin_data[1] << 8) | (bin_data[2] << 16) | (bin_data[3] << 24);
    if ((first_word & 0x00000FFF) != 0x0000006F) {
        fprintf(stderr, "Warning: first instruction doesn't look like JAL x0 (got 0x%08X)\n", first_word);
        fprintf(stderr, "         Expected RV32 image header. Continuing anyway.\n");
    }

    /* Prepare app descriptor (padded to full page = 4096 bytes) */
    uint8_t app_desc_page[4096];
    uint32_t desc_size = include_desc ? 4096 : 0;
    if (include_desc) {
        memset(app_desc_page, 0, 4096);
        generate_app_desc(app_desc_page, proj_name);
    }

    /*
     * ELF layout:
     *   [ELF header]           52 bytes
     *   [Program headers]      1 * 32 bytes
     *   [.rodata_desc]         4096 bytes (if include_desc, padded to page)
     *   [.text]                bin_size bytes (the Oberon image)
     *   [Section headers]      (shnum * 40 bytes)
     *   [.shstrtab]            string table
     *
     * Single PT_LOAD segment covers desc_page + binary.
     * The bootloader finds esp_app_desc_t at the start of the segment data.
     * The binary (linked at base + 0x1000) follows on the next page boundary.
     */

    /* Section header string table */
    const char shstrtab[] = "\0.text\0.rodata_desc\0.shstrtab\0";
    uint32_t shstrtab_size = sizeof(shstrtab);
    /* Offsets into shstrtab */
    uint32_t n_text = 1;           /* ".text" at offset 1 */
    uint32_t n_rodata_desc = 7;    /* ".rodata_desc" at offset 7 */
    uint32_t n_shstrtab = 20;      /* ".shstrtab" at offset 20 */

    /* Count sections: null + .text + .shstrtab [+ .rodata_desc] */
    uint32_t shnum = include_desc ? 4 : 3;
    uint32_t phnum = 1; /* single PT_LOAD covers everything */

    uint32_t ehdr_size = 52;
    uint32_t phdr_size = 32 * phnum;
    uint32_t headers_size = ehdr_size + phdr_size;

    /* File offsets */
    uint32_t desc_offset = headers_size;
    uint32_t text_offset = desc_offset + desc_size;
    uint32_t shdr_offset = text_offset + (uint32_t)bin_size;
    /* Align section headers to 4 bytes */
    shdr_offset = (shdr_offset + 3) & ~3u;
    uint32_t shstrtab_offset = shdr_offset + shnum * 40;
    uint32_t total_size = shstrtab_offset + shstrtab_size;

    /* Virtual addresses */
    uint32_t segment_vaddr = base_addr; /* everything loads here */
    uint32_t desc_vaddr = base_addr;
    uint32_t text_vaddr = base_addr + desc_size;
    uint32_t segment_filesz = desc_size + (uint32_t)bin_size;
    uint32_t segment_memsz = segment_filesz; /* no BSS for now */

    /* Entry point: the Oberon image starts at text_vaddr, its first instruction
     * is JAL x0 which jumps to the init code. */
    uint32_t entry = text_vaddr;

    /* Build output */
    uint8_t *elf = (uint8_t *)calloc(1, total_size);
    if (!elf) {
        fprintf(stderr, "Out of memory\n");
        return 1;
    }

    /* ELF Header */
    uint8_t *e = elf;
    e[0] = 0x7F; e[1] = 'E'; e[2] = 'L'; e[3] = 'F';
    e[4] = 1;  /* EI_CLASS: 32-bit */
    e[5] = 1;  /* EI_DATA: little-endian */
    e[6] = 1;  /* EI_VERSION */
    write_le16(e + 16, ET_EXEC);
    write_le16(e + 18, EM_RISCV);
    write_le32(e + 20, 1);           /* e_version */
    write_le32(e + 24, entry);       /* e_entry */
    write_le32(e + 28, ehdr_size);   /* e_phoff */
    write_le32(e + 32, shdr_offset); /* e_shoff */
    write_le32(e + 36, 0);          /* e_flags (no RV extensions for bare-metal) */
    write_le16(e + 40, (uint16_t)ehdr_size);  /* e_ehsize */
    write_le16(e + 42, 32);          /* e_phentsize */
    write_le16(e + 44, (uint16_t)phnum);
    write_le16(e + 46, 40);          /* e_shentsize */
    write_le16(e + 48, (uint16_t)shnum);
    write_le16(e + 50, (uint16_t)(shnum - 1)); /* e_shstrndx = last section */

    /* Program Header (PT_LOAD) */
    uint8_t *ph = elf + ehdr_size;
    write_le32(ph + 0, PT_LOAD);
    write_le32(ph + 4, desc_offset);       /* p_offset: start of content in file */
    write_le32(ph + 8, segment_vaddr);     /* p_vaddr */
    write_le32(ph + 12, segment_vaddr);    /* p_paddr */
    write_le32(ph + 16, segment_filesz);   /* p_filesz */
    write_le32(ph + 20, segment_memsz);    /* p_memsz */
    write_le32(ph + 24, PF_R | PF_W | PF_X); /* p_flags */
    write_le32(ph + 28, 0x1000);           /* p_align */

    /* .rodata_desc (page-padded) */
    if (include_desc) {
        memcpy(elf + desc_offset, app_desc_page, 4096);
    }
    /* .text (the Oberon binary image) */
    memcpy(elf + text_offset, bin_data, (size_t)bin_size);

    /* SH[0]: null */
    /* (already zeroed) */

    /* SH[1]: .text */
    uint8_t *sh = elf + shdr_offset + 40; /* skip null section */
    write_le32(sh + 0, n_text);
    write_le32(sh + 4, SHT_PROGBITS);
    write_le32(sh + 8, SHF_ALLOC | SHF_EXECINSTR);
    write_le32(sh + 12, text_vaddr);
    write_le32(sh + 16, text_offset);
    write_le32(sh + 20, (uint32_t)bin_size);
    write_le32(sh + 36, 4); /* sh_addralign */

    if (include_desc) {
        /* SH[2]: .rodata_desc */
        sh = elf + shdr_offset + 80;
        write_le32(sh + 0, n_rodata_desc);
        write_le32(sh + 4, SHT_PROGBITS);
        write_le32(sh + 8, SHF_ALLOC);
        write_le32(sh + 12, desc_vaddr);
        write_le32(sh + 16, desc_offset);
        write_le32(sh + 20, desc_size);
        write_le32(sh + 36, 4); /* sh_addralign */

        /* SH[3]: .shstrtab */
        sh = elf + shdr_offset + 120;
    } else {
        /* SH[2]: .shstrtab */
        sh = elf + shdr_offset + 80;
    }
    write_le32(sh + 0, n_shstrtab);
    write_le32(sh + 4, SHT_STRTAB);
    write_le32(sh + 16, shstrtab_offset);
    write_le32(sh + 20, shstrtab_size);
    write_le32(sh + 36, 1); /* sh_addralign */

    memcpy(elf + shstrtab_offset, shstrtab, shstrtab_size);

    /* Write output */
    FILE *fout = fopen(output, "wb");
    if (!fout) {
        perror(output);
        free(elf);
        free(bin_data);
        return 1;
    }
    fwrite(elf, 1, total_size, fout);
    fclose(fout);

    printf("Created %s:\n", output);
    printf("  Base address:  0x%08X\n", base_addr);
    printf("  Entry point:   0x%08X\n", entry);
    printf("  Image size:    %ld bytes\n", bin_size);
    if (include_desc)
        printf("  App descriptor: yes (256 bytes at 0x%08X)\n", desc_vaddr);
    else
        printf("  App descriptor: no\n");
    printf("  ELF size:      %u bytes\n", total_size);

    free(elf);
    free(bin_data);
    return 0;
}
