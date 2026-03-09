/*
* Copyright 2026 Rochus Keller <mailto:me@rochus-keller.ch>
*
* The following is the license that applies to this copy of the
* file. For a license to use the file under conditions
* other than those described here, please email to me@rochus-keller.ch.
*
* GNU General Public License Usage
* This file may be used under the terms of the GNU General Public
* License (GPL) versions 2.0 or 3.0 as published by the Free Software
* Foundation and appearing in the file LICENSE.GPL included in
* the packaging of this file. Please review the following information
* to ensure GNU General Public Licensing requirements will be met:
* http://www.fsf.org/licensing/licenses/info/GPLv2.html and
* http://www.gnu.org/copyleft/gpl.html.
*/

// op2objdump.c - OP2 (Native Oberon) object file checker/dumper (C99)
// Build: cc -std=c99 -O2 -Wall -Wextra objdump.c -o objdump

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <inttypes.h>
#include <ctype.h>
#include <errno.h>
#include <stdarg.h>

typedef struct {
    uint8_t *buf;
    size_t len;
    size_t pos;
    const char *path;
} Reader;

typedef struct {
    int show_header, show_symblock_hex, show_entries, show_commands;
    int show_pointers, show_imports, show_varcons, show_links;
    int show_consts_hex, show_exports, show_code_hex, show_use;
    int show_types, show_refs, strict;
    size_t hex_limit;
} Options;

static void dief(const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    vfprintf(stderr, fmt, ap); va_end(ap);
    fputc('\n', stderr); exit(1);
}

static void warnf(const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    vfprintf(stderr, fmt, ap); va_end(ap);
    fputc('\n', stderr);
}

static int need(Reader *r, size_t n) { return r->pos + n <= r->len; }

static uint8_t read_u8(Reader *r) {
    if (!need(r, 1)) dief("%s: unexpected EOF at pos %zu", r->path, r->pos);
    return r->buf[r->pos++];
}

static uint16_t read_u16le(Reader *r) {
    if (!need(r, 2)) dief("%s: unexpected EOF at pos %zu", r->path, r->pos);
    uint16_t v = r->buf[r->pos] | (r->buf[r->pos+1] << 8);
    r->pos += 2; return v;
}

static int16_t read_i16le(Reader *r) { return (int16_t)read_u16le(r); }

static uint32_t read_u32le(Reader *r) {
    if (!need(r, 4)) dief("%s: unexpected EOF at pos %zu", r->path, r->pos);
    uint32_t v = r->buf[r->pos] | (r->buf[r->pos+1] << 8) | 
                (r->buf[r->pos+2] << 16) | (r->buf[r->pos+3] << 24);
    r->pos += 4; return v;
}

static int32_t read_i32le(Reader *r) { return (int32_t)read_u32le(r); }

// Corrected string reader: handles 0x00 termination and 0X compression
static char *read_string(Reader *r, size_t maxout) {
    char *out = (char*)malloc(maxout + 1);
    if (!out) dief("out of memory");
    size_t n = 0;

    while (1) {
        uint8_t ch = read_u8(r);
        if (ch == 0x00) {
            out[n] = '\0';
            return out;
        } else if (ch < 0x7F) {
            if (n >= maxout) dief("%s: string too long", r->path);
            out[n++] = (char)ch;
        } else if (ch > 0x7F) {
            if (n >= maxout) dief("%s: string too long", r->path);
            out[n++] = (char)(ch - 0x80);
            out[n] = '\0';
            return out;
        } else { // ch == 0x7F (long string escape)
            while (1) {
                uint8_t b = read_u8(r);
                if (b == 0x00) {
                    out[n] = '\0';
                    return out;
                }
                if (n >= maxout) dief("%s: string too long", r->path);
                out[n++] = (char)b;
            }
        }
    }
}

// Signed LEB128 matching BootLinker GetNum
static int64_t read_num(Reader *r) {
    int64_t result = 0; int shift = 0; uint8_t byte = 0;
    while (1) {
        byte = read_u8(r);
        result |= (int64_t)(byte & 0x7F) << shift;
        shift += 7;
        if ((byte & 0x80) == 0) break;
        if (shift > 63) dief("%s: num too long at %zu", r->path, r->pos);
    }
    if (shift < 64 && (byte & 0x40)) result |= -((int64_t)1 << shift);
    return result;
}

static void hexdump(const uint8_t *p, size_t n, size_t limit) {
    if (n > limit) n = limit;
    for (size_t i = 0; i < n; i += 16) {
        printf("  %06zx: ", i);
        for (size_t j = 0; j < 16; j++) {
            if (i + j < n) printf("%02x ", p[i + j]); else printf("   ");
        }
        printf(" ");
        for (size_t j = 0; j < 16 && i + j < n; j++) {
            uint8_t c = p[i + j]; putchar(isprint(c) ? (char)c : '.');
        }
        putchar('\n');
    }
}

static void expect_tag(Reader *r, uint8_t tag, const char *name, int strict) {
    uint8_t got = read_u8(r);
    if (got != tag) {
        if (strict) dief("%s: expected %s tag 0x%02x, got 0x%02x at pos %zu", r->path, name, tag, got, r->pos-1);
        warnf("%s: expected %s tag 0x%02x, got 0x%02x at pos %zu (continuing)", r->path, name, tag, got, r->pos-1);
    }
}

static void indent(int d) { while (d-- > 0) printf("  "); }

// --- Recursive Export Grammar ---
static void parse_export_scope(Reader *r, const Options *opt, int depth, int level) {
    if (depth > 256) dief("%s: export scope recursion too deep", r->path);
    uint16_t nofExp = read_u16le(r);
    if (opt->show_exports) { indent(depth); printf("Scope nofExp=%u\n", nofExp); }

    while (1) {
        int64_t fp = read_num(r);
        if (fp == 0) break; // EUEnd

        if (fp == 1) { // EURecord
            int64_t off = read_num(r);
            if (opt->show_exports) { indent(depth); printf("Record off=%" PRId64 "\n", off); }
            if (off >= 0) {
                parse_export_scope(r, opt, depth + 1, 1 /* EUrecScope */);
            }
        } else {
            int64_t adr = 0;
            if (level == 0 /* EUobjScope */) adr = read_num(r);
            if (opt->show_exports) {
                indent(depth);
                if (level == 0) printf("FP=%" PRId64 " adr=%" PRId64 "\n", fp, adr);
                else printf("FP=%" PRId64 "\n", fp);
            }
        }
    }
}

// --- Recursive Use Grammar ---
static void parse_use_scope(Reader *r, const Options *opt, int depth, int level) {
    if (depth > 256) dief("%s: use scope recursion too deep", r->path);
    while (1) {
        int64_t fp = read_num(r);
        if (fp == 0) break; // EUEnd

        if (fp == 1) { // EURecord
            int64_t link = read_num(r);
            if (opt->show_use) { indent(depth); printf("Record link=%" PRId64 "\n", link); }
            parse_use_scope(r, opt, depth + 1, 1 /* EUrecScope */);
        } else {
            char *name = read_string(r, 256);
            int64_t link = 0;
            if (level == 0 /* EUobjScope */) link = read_num(r);
            if (opt->show_use) {
                indent(depth);
                if (level == 0) printf("FP=%" PRId64 " name=\"%s\" link=%" PRId64 "\n", fp, name, link);
                else printf("FP=%" PRId64 " name=\"%s\"\n", fp, name);
            }
            free(name);
        }
    }
}

static void parse_object(Reader *r, const Options *opt) {
    uint8_t oftag = read_u8(r);
    uint8_t ofver = read_u8(r);
    if (opt->show_header) printf("File:\n  OFTag=0x%02x\n  OFVersion=0x%02x\n", oftag, ofver);

    int64_t symSize = read_num(r);
    if (opt->show_header) printf("  symBlockSize=%" PRId64 "\n", symSize);
    if (!need(r, (size_t)symSize)) dief("%s: symBlock overruns file", r->path);
    if (opt->show_symblock_hex) {
        printf("SymBlock (first bytes):\n");
        hexdump(r->buf + r->pos, (size_t)symSize, opt->hex_limit);
    }
    r->pos += (size_t)symSize;

    // Header
    uint32_t refSize = read_u32le(r);
    uint16_t nofEntries = read_u16le(r), nofCommands = read_u16le(r), nofPointers = read_u16le(r);
    uint16_t nofTypes = read_u16le(r), nofImports = read_u16le(r), nofVarConsLists = read_u16le(r);
    uint16_t nofLinks = read_u16le(r);
    uint32_t dataSize = read_u32le(r);
    uint16_t constSize = read_u16le(r), codeSize = read_u16le(r);
    char *moduleName = read_string(r, 256);

    if (opt->show_header) {
        printf("Header:\n  refSize=%" PRIu32 "\n  nofEntries=%u\n  nofCommands=%u\n", refSize, nofEntries, nofCommands);
        printf("  nofPointers=%u\n  nofTypes=%u\n  nofImports=%u\n", nofPointers, nofTypes, nofImports);
        printf("  nofVarConsLists=%u\n  nofLinks=%u\n  dataSize=%" PRIu32 "\n", nofVarConsLists, nofLinks, dataSize);
        printf("  constSize=%u\n  codeSize=%u\n  moduleName=\"%s\"\n", constSize, codeSize, moduleName);
    }
    free(moduleName);

    // Entries
    expect_tag(r, 0x82, "Entries", opt->strict);
    if (opt->show_entries) printf("Entries:\n");
    for (uint16_t i = 0; i < nofEntries; i++) {
        uint16_t off = read_u16le(r);
        if (opt->show_entries) printf("  entry[%u]=0x%04x (%u)\n", i, off, off);
    }

    // Commands
    expect_tag(r, 0x83, "Commands", opt->strict);
    if (opt->show_commands) printf("Commands:\n");
    for (uint16_t i = 0; i < nofCommands; i++) {
        char *name = read_string(r, 256);
        uint16_t off = read_u16le(r);
        if (opt->show_commands) printf("  cmd[%u] name=\"%s\" off=0x%04x\n", i, name, off);
        free(name);
    }

    // Pointers
    expect_tag(r, 0x84, "Pointers", opt->strict);
    if (opt->show_pointers) printf("Pointers:\n");
    for (uint16_t i = 0; i < nofPointers; i++) {
        int32_t poff = read_i32le(r);
        // Deep copy flag stripped just like in BootLinker
        if (opt->show_pointers) printf("  ptr[%u]=%" PRId32 "\n", i, poff - (poff % 4));
    }

    // Imports
    expect_tag(r, 0x85, "Imports", opt->strict);
    if (opt->show_imports) printf("Imports:\n");
    for (uint16_t i = 0; i < nofImports; i++) {
        char *mn = read_string(r, 256);
        if (opt->show_imports) printf("  import[%u]=\"%s\"\n", i + 1, mn);
        free(mn);
    }

    // VarConstLinks
    expect_tag(r, 0x8D, "VarConstLinks", opt->strict);
    if (opt->show_varcons) printf("VarConstLinks (fixup lists):\n");
    for (uint16_t i = 0; i < nofVarConsLists; i++) {
        uint8_t mod = read_u8(r);
        int16_t entry = read_i16le(r);
        int16_t count = read_i16le(r);
        if (opt->show_varcons) printf("  list[%u]: mod=%u entry=0x%04x count=%u offsets:", i, mod, (uint16_t)entry, count);
        for (int16_t j = 0; j < count; j++) {
            uint16_t off = read_u16le(r);
            if (opt->show_varcons) printf(" 0x%04x", off);
        }
        if (opt->show_varcons) putchar('\n');
    }

    // Links
    expect_tag(r, 0x86, "Links", opt->strict);
    if (opt->show_links) printf("Links:\n");
    for (uint16_t i = 0; i < nofLinks; i++) {
        uint8_t mod = read_u8(r);
        uint8_t entry = read_u8(r);
        uint16_t off = read_u16le(r);
        if (opt->show_links) printf("  link[%u]: mod=%u entry=%u off=0x%04x\n", i, mod, entry, off);
    }

    // Consts/Data
    expect_tag(r, 0x87, "Consts/Data", opt->strict);
    if (!need(r, constSize)) dief("%s: consts overruns file", r->path);
    if (opt->show_consts_hex) {
        printf("Consts/Data (%u bytes):\n", constSize);
        hexdump(r->buf + r->pos, constSize, opt->hex_limit);
    }
    r->pos += constSize;

    // Exports
    expect_tag(r, 0x88, "Exports", opt->strict);
    if (opt->show_exports) printf("Exports:\n");
    parse_export_scope(r, opt, opt->show_exports ? 1 : 0, 0 /* EUobjScope */);

    // Code
    expect_tag(r, 0x89, "Code", opt->strict);
    if (!need(r, codeSize)) dief("%s: code overruns file", r->path);
    if (opt->show_code_hex) {
        printf("Code (%u bytes):\n", codeSize);
        hexdump(r->buf + r->pos, codeSize, opt->hex_limit);
    }
    r->pos += codeSize;

    // Use
    expect_tag(r, 0x8A, "Use", opt->strict);
    if (opt->show_use) printf("Use:\n");
    while (1) {
        char *modName = read_string(r, 256);
        if (modName[0] == '\0') { free(modName); break; }
        if (opt->show_use) printf("  UsedModule \"%s\":\n", modName);
        parse_use_scope(r, opt, opt->show_use ? 2 : 0, 0 /* EUobjScope */);
        free(modName);
    }

    // Types
    expect_tag(r, 0x8B, "Types", opt->strict);
    if (opt->show_types) printf("Types (nofTypes=%u):\n", nofTypes);
    for (uint16_t i = 0; i < nofTypes; i++) {
        uint32_t size = read_u32le(r);
        int16_t tdaddr = read_i16le(r);
        int16_t baseMod = read_i16le(r);
        int32_t baseEntry = read_i32le(r);
        int16_t nofMethods = read_i16le(r);
        int16_t nofInh = read_i16le(r); // "dummy"
        int16_t nofNew = read_i16le(r);
        int16_t nofPtrs = read_i16le(r);
        char *tname = read_string(r, 256);

        if (opt->show_types) {
            printf("  type[%u]: size=%" PRIu32 " tdaddr=0x%04x baseMod=%d baseEntry=0x%08x\n"
                   "            methods=%d inh=%d new=%d ptrs=%d name=\"%s\"\n",
                   i, size, (uint16_t)tdaddr, baseMod, (uint32_t)baseEntry,
                   nofMethods, nofInh, nofNew, nofPtrs, tname);
        }

        for (int16_t j = 0; j < nofNew; j++) {
            int16_t mnum = read_i16le(r); int16_t en = read_i16le(r);
            if (opt->show_types) printf("    newMethod[%d]: mthNo=%d entryNo=%d\n", j, mnum, en);
        }
        for (int16_t j = 0; j < nofPtrs; j++) {
            int32_t poff = read_i32le(r);
            if (opt->show_types) printf("    ptrOff[%d]=%" PRId32 "\n", j, poff);
        }
        free(tname);
    }

    // References
    expect_tag(r, 0x8C, "References", opt->strict);
    if (opt->show_refs) printf("References (declared size=%" PRIu32 "):\n", refSize);
    size_t ref_limit = r->pos + (refSize > 0 ? refSize - 1 : 0);
    if (ref_limit > r->len) ref_limit = r->len;
    while (r->pos < ref_limit) {
        uint8_t rt = read_u8(r);
        if (rt == 0xF8) {
            int64_t off = read_num(r); char *nm = read_string(r, 256);
            if (opt->show_refs) printf("  BodyRef off=%" PRId64 " name=\"%s\"\n", off, nm);
            free(nm);
        } else if (rt == 0xF9) {
            int64_t off = read_num(r); uint8_t nofPars = read_u8(r);
            uint8_t retType = read_u8(r), procLev = read_u8(r), slFlag = read_u8(r);
            char *nm = read_string(r, 256);
            if (opt->show_refs) {
                printf("  ProcRef off=%" PRId64 " pars=%u retType=0x%02x lev=%u sl=%u name=\"%s\"\n",
                       off, nofPars, retType, procLev, slFlag, nm);
            }
            free(nm);
        } else {
            if (opt->show_refs) {
                printf("  RefByte 0x%02x at +%zu (raw remainder)\n", rt, r->pos - 1 - (ref_limit - refSize + 1));
                hexdump(r->buf + (r->pos - 1), ref_limit - (r->pos - 1), opt->hex_limit);
            }
            r->pos = ref_limit; break;
        }
    }
}

static uint8_t *read_entire_file(const char *path, size_t *out_len) {
    FILE *f = fopen(path, "rb");
    if (!f) dief("open %s: %s", path, strerror(errno));
    fseek(f, 0, SEEK_END); long sz = ftell(f); fseek(f, 0, SEEK_SET);
    uint8_t *buf = (uint8_t*)malloc((size_t)sz);
    if (fread(buf, 1, (size_t)sz, f) != (size_t)sz) dief("read %s failed", path);
    fclose(f); *out_len = (size_t)sz; return buf;
}

static void usage(const char *argv0) {
    fprintf(stderr, "Usage: %s [options] file.Obj\n"
        "  --all         Show all sections\n"
        "  --header      Show header\n"
        "  --sym-hex     Hexdump sym block\n"
        "  --entries     Show entries\n"
        "  --commands    Show commands\n"
        "  --pointers    Show pointers\n"
        "  --imports     Show imports\n"
        "  --varcons     Show VarConstLinks\n"
        "  --links       Show Links\n"
        "  --consts-hex  Hexdump consts\n"
        "  --exports     Dump Exports\n"
        "  --code-hex    Hexdump code\n"
        "  --use         Dump Use section\n"
        "  --types       Dump Types section\n"
        "  --refs        Dump References\n", argv0);
    exit(2);
}

int main(int argc, char **argv) {
    Options opt = {0}; opt.hex_limit = 512;
    const char *path = NULL;
    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (!strcmp(a, "--all")) {
            opt.show_header = opt.show_symblock_hex = opt.show_entries = 1;
            opt.show_commands = opt.show_pointers = opt.show_imports = 1;
            opt.show_varcons = opt.show_links = opt.show_consts_hex = 1;
            opt.show_exports = opt.show_code_hex = opt.show_use = 1;
            opt.show_types = opt.show_refs = 1;
        } else if (!strcmp(a, "--header")) opt.show_header = 1;
        else if (!strcmp(a, "--sym-hex")) opt.show_symblock_hex = 1;
        else if (!strcmp(a, "--entries")) opt.show_entries = 1;
        else if (!strcmp(a, "--commands")) opt.show_commands = 1;
        else if (!strcmp(a, "--pointers")) opt.show_pointers = 1;
        else if (!strcmp(a, "--imports")) opt.show_imports = 1;
        else if (!strcmp(a, "--varcons")) opt.show_varcons = 1;
        else if (!strcmp(a, "--links")) opt.show_links = 1;
        else if (!strcmp(a, "--consts-hex")) opt.show_consts_hex = 1;
        else if (!strcmp(a, "--exports")) opt.show_exports = 1;
        else if (!strcmp(a, "--code-hex")) opt.show_code_hex = 1;
        else if (!strcmp(a, "--use")) opt.show_use = 1;
        else if (!strcmp(a, "--types")) opt.show_types = 1;
        else if (!strcmp(a, "--refs")) opt.show_refs = 1;
        else if (!strcmp(a, "--strict")) opt.strict = 1;
        else if (!strcmp(a, "--hex-limit")) opt.hex_limit = (size_t)strtoull(argv[++i], NULL, 10);
        else if (a[0] == '-') usage(argv[0]);
        else path = a;
    }
    if (!path) usage(argv[0]);

    size_t len = 0; uint8_t *buf = read_entire_file(path, &len);
    Reader r = {buf, len, 0, path};
    parse_object(&r, &opt);
    free(buf); return 0;
}
