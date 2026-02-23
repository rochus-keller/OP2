/*
* Copyright 2026 Rochus Keller <mailto:me@rochus-keller.ch>
*
* Multi-architecture boot linker for the Oberon System 3
*
* Standalone C99 port of BootLinker.Mod (Native Oberon static boot linker)
* with support for multiple target architectures: i386, ARM32, RV32.
*
* Notes:
* - This is a format-preserving translation intended to reproduce the same
*   located raw binary image produced by BootLinker.Mod.
* - The tool targets 32-bit little-endian OM object files (OFVersion 0x0AF).
* - In addition to the original version it can add a Multiboot header and
*   initialize the stack (and push the Multiboot info pointer to the stack).
* - The tool also works without the presence of Kernel module.
* - Architecture-specific code generation is abstracted via ArchOps function
*   pointers, making it easy to add new targets without modifying the core linker.
*
* compile e.g. with:
*   cc -std=c99 -O2 -Wall -Wextra -o multibootlinker multibootlinker.c
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

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------ */
/* Constants (from BootLinker.Mod) */

enum {
    /* SysFix constants */
    newSF = 0,          // "new", "Kernel.NewRec"
    sysnewSF = 1,       // "sysnew", "Kernel.NewSys"
    newarrSF = 2,       // "newarr", "Kernel.NewArr"
    StartSF = 3,        // "start", ""
    PassivateSF = 4,    // "passivate", ""
    ActivateSF = 5,     // "activate", ""
    LockSF = 6,         // "lock", ""
    UnlockSF = 7,       // "unlock", ""
    copyarraySF = 10,
    CurProcSF = 11,     // "", ""
    commandSF = 12,     // "command", ""
    listSF = 13,        // "list", "Kernel.modules"
    modDescSF = 14,     // "mdesc", "Kernel.ModuleDesc"
    expDescSF = 15,     // "expdesc", "Kernel.ExportDesc"
    objectSF = 16,      // "", ""
    MaxSF = 17,

    /*
     * Unused:
     * CheckSF = 8;
     * newsysarrSF = 9;
    */
    // automatically resolved from Kernel module:
    // newSf..copyarraySF, CurProcSF, listSF, modDescSF, expDescSF

    // SysFixes like passivate, activate etc. are no Oberon System feature and thus
    // not related to Kernel features here.
};

enum {
    Boundary = 32,
    PageSize = 4096,

    OFVersion = 0x0AF,

    PaddingSize = 64,
    hiddenTD = 20,

    /* FindAdr modes */
    Proc = 0,
    Var = 1,

    /* EU constants */
    EUEnd = 0,
    EURecord = 1,
    EUobjScope = 0,
    EUrecScope = 1,
    EUerrScope = -1,

    ExtTabWordSize = 16,

    DefMaxImport = 64,
    DefMaxStruct = 32,
    DefMaxReimp = 32,
};

#define EUProcFlag 0x80000000u

static bool Trace = true;
static bool TraceMore = false;

/* ------------------------------------------------------------ */
/* Basic types */

typedef char Name[32];
typedef char ModuleName[32];

typedef struct Module Module;
typedef struct TypeDesc TypeDesc;
typedef struct ExportDesc ExportDesc;

typedef struct {
    int32_t a, b, c, len;
} ArrayDesc;

enum { ArrayDescSize = 16, TagSize = 4 };

typedef struct {
    Name name;
    int32_t adr;
} CommandDesc;

typedef struct {
    int16_t mthNo;
    int16_t entryNo;
} NewMethod;

struct ExportDesc {
    int32_t fp;
    int32_t adr;
    int16_t nofExp;
    ExportDesc *dsc; /* array of ExportDesc, length nofExp */

    /* Linker-only bookkeeping */
    int32_t Adr;
    bool done;
    TypeDesc *type;
};

typedef struct {
    int32_t fp;
    int32_t adr;
    int32_t nofExp;
    int32_t dsc;
} DumpExportDesc;

struct TypeDesc {
    int32_t size;
    int32_t nofMethods;
    int32_t nofNewMethods;
    int32_t nofPtrs;
    int32_t tdAdr;
    int32_t tdEntry;
    int32_t tdSize;
    int32_t padSize;
    int32_t baseMod;
    int32_t baseEntry;
    Name name;
    NewMethod *newMethods;
    int32_t *ptrOffset;
    TypeDesc *baseType;
    int32_t extlev;
    bool initialized;
    Module *module;
};

typedef void (*TerminationHandler)(void);

struct Module {
    /* Normal module data */
    Module *link;
    Name name;
    bool init;
    int32_t refcnt;
    int32_t sb;

    uint32_t *entries;      /* nofEntries */
    CommandDesc *cmds;      /* nofCmds */
    int32_t *ptrTab;        /* nofPtrs */
    TypeDesc **tdescs;      /* nofTds (array of pointers) */
    Module **imports;       /* nofImps */

    uint8_t *data;          /* dataSize+conSize */
    uint8_t *code;          /* codeSize */
    uint8_t *refs;          /* refSize */

    int32_t publics;
    int32_t privates;

    /* These are present in the Oberon runtime ModuleDesc, but used here mainly
   * for image layout */
    int32_t nofimp;
    int32_t *import; /* DefMaxImport */
    int32_t nofstrc;
    int32_t *strct;  /* DefMaxStruct */
    int32_t nofreimp;
    int32_t *reimp;  /* DefMaxReimp */

    ExportDesc exportTree;
    TerminationHandler term;

    /* Linker-only */
    int32_t base;
    int32_t imageSize;
    int32_t codeBase;
    int32_t refBase;

    int32_t expAdr;
    int32_t expSize;
    int32_t expPadding;

    int32_t typeTableSize;
    int32_t typeTableAdr;

    int32_t modDescAdr;

    int32_t dataSize;
    int32_t conSize;
    int32_t codeSize;
    int32_t refSize;

    int32_t nofEntries;
    int32_t nofCmds;
    int32_t nofImps;
    int32_t nofTds;
    int32_t nofPtrs;
};

typedef struct InitPointNode InitPointNode;
struct InitPointNode {
    int32_t entryPoint;
    Module *object;
    InitPointNode *next;
};

typedef struct {
    uint8_t mod;
    uint8_t entry;
    uint16_t link;
} LinkEntry;

typedef struct {
    uint8_t mod;
    int16_t entry;
    int16_t nofFixups;
    uint16_t *offset; /* nofFixups */
} DataLinkEntry;

typedef struct {
    Name name;
    Name module;
    Name command;
    int32_t adr;
} SysFixEntry;

/* DumpModuleDesc (written verbatim in Oberon version) */
typedef struct {
    int32_t link;
    Name name;
    uint8_t init;
    uint8_t trapped;
    uint16_t pad0;
    int32_t refcnt;
    int32_t sb;
    int32_t entries;
    int32_t cmds;
    int32_t ptrTab;
    int32_t tdescs;
    int32_t imports;
    int32_t data;
    int32_t code;
    int32_t refs;
    int32_t publics;
    int32_t privates;
    int32_t nofimp;
    int32_t import;
    int32_t nofstrc;
    int32_t strct;
    int32_t nofreimp;
    int32_t reimp;
    DumpExportDesc exportDesc;
    int32_t term;
} DumpModuleDesc;

/* ------------------------------------------------------------ */
/* Architecture abstraction */

typedef struct ArchOps ArchOps;
struct ArchOps {
    const char *name;

    /* Size of one call instruction in bytes (5 for x86 CALL rel32, 4 for ARM BL / RV32 JAL) */
    int32_t call_instr_size;

    /* Size of the halt/idle sequence in bytes */
    int32_t halt_seq_size;

    /* Patch a procedure-call fixup chain in the in-memory code buffer.
     * Walks the linked list starting at code[link], following msw() links.
     * Writes the architecture-specific call/branch encoding targeting 'target'. */
    void (*PatchFunctionCall)(uint8_t *code, int32_t codeImgBase, int32_t link, int32_t target);

    /* Emit one call instruction to the output file at the given PC, targeting 'target'. */
    void (*WriteCallInstruction)(FILE *out, int32_t target, int32_t pc);

    /* Emit the halt/idle sequence at the end of the init code block. */
    void (*EmitHaltSequence)(FILE *out);

    /* Emit the stack initialization preamble into the init code block.
     * Returns the number of bytes emitted (0 if not applicable).
     * 'initial_sp' is the desired initial stack pointer value.
     * 'multiboot' indicates whether to push Multiboot info (x86-specific). */
    int32_t (*EmitStackPreamble)(FILE *out, int32_t initial_sp, bool multiboot);

    /* Patch the image header at the beginning of the output file.
     * 'base' is the image base address, 'entry' is the entry point address,
     * 'size' is the total image size, 'ramSize' is optional RAM size (0 if unused). */
    void (*PatchImageHeader)(FILE *out, int32_t base, int32_t entry,
                             int32_t size, int32_t ramSize);

    /* Patch a Multiboot header at the beginning of the output file.
     * Returns false if Multiboot is not supported on this architecture. */
    bool (*PatchMultibootHeader)(FILE *out, int32_t base, int32_t entry, int32_t size);
};

/* ArchOps instances are defined after the arch-specific implementations below. */
static const ArchOps arch_i386, arch_arm32, arch_rv32;
static const ArchOps *arch = &arch_i386; /* default */

/* ------------------------------------------------------------ */
/* Globals */

static SysFixEntry SysFix[MaxSF];
static Module *objectList = NULL;
static bool includeRefs = true;

/* For deferred listSF fixup in dump_modules */
static Module *listSF_module = NULL;
static int32_t listSF_offset = 0;

static int32_t imageBase = -1;
static int32_t imageSize = 0;
static int32_t ramSize = 0;

static int32_t nofEntryPoints = 0;
static InitPointNode *initPointList = NULL;

static uint8_t padding[PaddingSize];

static char extension[] = ".Obj";

static FILE *logFile = NULL;

static char* modulePath = NULL;

/* last loader error */
static int32_t res = 0;

/* res codes */
enum {
    done = 0,
    fileNotFound = 1,
    invalidObjFile = 2,
    corruptedObjFile = 4,
    cmdNotFound = 5,
    moduleNotFound = 6,
    notEnoughSpace = 7,
    refCntNotZero = 8,
    cyclicImport = 9,
    incompImport = 16,
};

/* ------------------------------------------------------------ */
/* Utility: logging */

static void log_close(void);

static void log_open(const char *path) {
    logFile = fopen(path, "wb");
    if (!logFile) {
        fprintf(stderr, "bootlinker: failed to open log file %s: %s\n", path, strerror(errno));
        exit(1);
    }
}

static void log_stdout() {
    logFile = stdout;
}

static void log_close(void) {
    if (logFile && logFile != stdout) {
        fclose(logFile);
        logFile = NULL;
    }
}

static void log_puts(const char *s) {
    if (logFile)
        fputs(s, logFile);
}

static void log_ch(char c) {
    if (logFile)
        fputc((unsigned char)c, logFile);
}

static void log_ln(void) {
    if (logFile)
        fputc('\n', logFile);
}

static void log_hex(int32_t x) {
    if (!logFile)
        return;
    fprintf(logFile, "%08" PRIX32 "H", (uint32_t)x);
}

static void log_int(int32_t x) {
    if (!logFile)
        return;
    fprintf(logFile, "%d", x);
}

static void dump_addr(int32_t next, const char *msg) {
    if (!Trace)
        return;
    log_hex(next);
    log_puts(" -- +");
    log_int(next % 32);
    log_puts("  ");
    log_puts(msg);
    log_ln();
}

static void err_msg(int32_t n, const char *name) {
    if ((res == done) && (n != 0)) {
        res = n;
        if (logFile) {
            log_puts(name);
            switch (n) {
            case fileNotFound:
            case moduleNotFound:
                log_puts(" not found");
                break;
            case invalidObjFile:
                log_puts(" not an obj-file");
                break;
            case corruptedObjFile:
                log_puts(" corrupted obj file");
                break;
            case notEnoughSpace:
                log_puts(" not enough space");
                break;
            case refCntNotZero:
                log_puts(" reference count not zero");
                break;
            case cyclicImport:
                log_puts(" imported cyclic");
                break;
            case cmdNotFound:
                log_puts(" not found");
                break;
            default:
                log_puts(" unknown error code");
                break;
            }
            log_ln();
        }
    }
}

static void halt_msg(const char *msg) {
    log_close();
    fflush(stdout);
    fprintf(stderr, "BootLinker Error: %s\n", msg);
    exit(100);
}

static void sysfix_warning(int i) {
    if (SysFix[i].adr == 0) {
        fprintf(stderr, "warning: system fixup '%s' not resolved\n", SysFix[i].name);
    }
}

/* ------------------------------------------------------------ */
/* Utility: string handling */

static void str_concat(const char *s1, const char *s2, char *out, size_t out_sz) {
    if (out_sz == 0)
        return;
    out[0] = 0;
    strncat(out, s1, out_sz - 1);
    strncat(out, s2, out_sz - 1 - strlen(out));
}

static void extract_names(const char *in, char *module, size_t module_sz, char *proc, size_t proc_sz) {
    const char *dot = strchr(in, '.');
    if (!dot) {
        snprintf(module, module_sz, "%s", in);
        proc[0] = 0;
        return;
    }
    size_t mlen = (size_t)(dot - in);
    if (mlen >= module_sz) mlen = module_sz - 1;
    memcpy(module, in, mlen);
    module[mlen] = 0;
    snprintf(proc, proc_sz, "%s", dot + 1);
}

/* ------------------------------------------------------------ */
/* Utility: endian read/write */

static uint8_t read_u8(FILE *f) {
    int c = fgetc(f);
    if (c == EOF)
        halt_msg("Unexpected EOF");
    return (uint8_t)c;
}

static void read_bytes(FILE *f, void *buf, size_t n) {
    if (n == 0)
        return;
    const int m = fread(buf, 1, n, f);
    if ( m != n)
        halt_msg("Unexpected EOF while reading bytes");
}

static uint16_t read_u16_le(FILE *f) {
    uint8_t lo = read_u8(f);
    uint8_t hi = read_u8(f);
    return (uint16_t)(lo | ((uint16_t)hi << 8));
}

static int16_t read_i16_le(FILE *f) {
    return (int16_t)read_u16_le(f);
}

static uint32_t read_u32_le(FILE *f) {
    uint32_t b0 = read_u8(f);
    uint32_t b1 = read_u8(f);
    uint32_t b2 = read_u8(f);
    uint32_t b3 = read_u8(f);
    return b0 | (b1 << 8) | (b2 << 16) | (b3 << 24);
}

static int32_t read_i32_le(FILE *f) {
    return (int32_t)read_u32_le(f);
}

/* Oberon Files.ReadNum encoding (matches GetNum pattern in BootLinker.Mod) */
static int32_t read_num(FILE *f) {
    int32_t n = 0;
    int shift = 0;
    uint8_t x = read_u8(f);
    while (x >= 128) {
        n += (int32_t)(x - 128) << shift;
        shift += 7;
        x = read_u8(f);
    }
    int32_t last = (int32_t)(x & 0x3F);
    if (x & 0x40) last -= 0x40;
    n += last << shift;
    return n;
}

/* ReadString variant used in object files (0-terminated OR last byte with high bit set). */
static void read_string(FILE *f, char *out, size_t out_sz) {
    if (out_sz == 0) return;
    size_t i = 0;
    while (1) {
        uint8_t ch = read_u8(f);
        if (ch == 0) {
            out[i < out_sz ? i : out_sz - 1] = 0;
            return;
        }
        if (ch > 0x7F) {
            if (i + 1 < out_sz) out[i++] = (char)(ch - 0x80);
            out[i < out_sz ? i : out_sz - 1] = 0;
            return;
        }
        if (i + 1 < out_sz) out[i++] = (char)ch;
    }
}

static void write_u8(FILE *f, uint8_t v) {
    if (fputc(v, f) == EOF)
        halt_msg("write failed");
}

static void write_u16_le(FILE *f, uint16_t v) {
    write_u8(f, (uint8_t)(v & 0xFF));
    write_u8(f, (uint8_t)((v >> 8) & 0xFF));
}

static void write_u32_le(FILE *f, uint32_t v) {
    write_u8(f, (uint8_t)(v & 0xFF));
    write_u8(f, (uint8_t)((v >> 8) & 0xFF));
    write_u8(f, (uint8_t)((v >> 16) & 0xFF));
    write_u8(f, (uint8_t)((v >> 24) & 0xFF));
}

static void write_i32_le(FILE *f, int32_t v) {
    write_u32_le(f, (uint32_t)v);
}

static void write_bytes(FILE *f, const void *buf, size_t n) {
    if (n == 0) return;
    if (fwrite(buf, 1, n, f) != n)
        halt_msg("write bytes failed");
}

static void seek_abs(FILE *f, long pos) {
    if (fseek(f, pos, SEEK_SET) != 0)
        halt_msg("seek failed");
}

static long tell_abs(FILE *f) {
    long p = ftell(f);
    if (p < 0)
        halt_msg("ftell failed");
    return p;
}

/* ------------------------------------------------------------ */
/* Utility: arithmetic */

static int32_t align_up(int32_t num, int32_t boundary) {
    int32_t mod = (-num) % boundary;
    if (mod < 0) mod += boundary;
    return num + mod;
}

static int32_t lsw(int32_t x) {
    return (int32_t)((uint32_t)x & 0xFFFFu);
}

static int32_t msw(int32_t x) {
    return (int32_t)((uint32_t)x >> 16);
}

static int32_t and32(int32_t x, int32_t y) {
    return (int32_t)((uint32_t)x & (uint32_t)y);
}

/* ------------------------------------------------------------ */
/* Module list handling */

static Module *find_module(const char *name) {
    Module *t = objectList;
    while (t && strcmp(t->name, name) != 0) t = t->link;
    return t;
}

static void insert_module_sorted(Module *o) {
    if (!objectList) {
        objectList = o;
        o->link = NULL;
        return;
    }
    Module *t = objectList;
    while (t->link && t->link->base < o->base) t = t->link;
    o->link = t->link;
    t->link = o;
}

static void add_init_point(int32_t entryPoint, Module *object) {
    InitPointNode *node = (InitPointNode *)calloc(1, sizeof(*node));
    if (!node)
        halt_msg("out of memory");
    node->entryPoint = entryPoint;
    node->object = object;
    node->next = NULL;
    if (!initPointList) {
        initPointList = node;
    } else {
        InitPointNode *p = initPointList;
        while (p->next) p = p->next;
        p->next = node;
    }
    nofEntryPoints++;
}

/* ------------------------------------------------------------ */
/* SysFix initialization */

static void init_sysfix(int idx, const char *name, const char *module, const char *command, bool autofix) {
    snprintf(SysFix[idx].name, sizeof(SysFix[idx].name), "%s", name);
    if( autofix )
    {
        snprintf(SysFix[idx].module, sizeof(SysFix[idx].module), "%s", module);
        snprintf(SysFix[idx].command, sizeof(SysFix[idx].command), "%s", command);
    }
    SysFix[idx].adr = 0;
}

/* DumpModuleDesc size computation mirrors BootLinker.Mod */
static int32_t moduleDescSize = 0;
static int32_t mDescPadSize = 0;

static void initialise(bool autofix) {
    objectList = NULL;
    includeRefs = true;
    res = done;

    memset(SysFix, 0, sizeof(SysFix));

    init_sysfix(newSF, "new", "Kernel", "NewRec", autofix);
    init_sysfix(sysnewSF, "sysnew", "Kernel", "NewSys", autofix);
    init_sysfix(newarrSF, "newarr", "Kernel", "NewArr", autofix);

    init_sysfix(listSF, "list", "Kernel", "modules", autofix);
    init_sysfix(modDescSF, "mdesc", "Kernel", "ModuleDesc", autofix);
    init_sysfix(expDescSF, "expdesc", "Kernel", "ExportDesc", autofix);

    init_sysfix(StartSF, "start", "", "", 0);
    init_sysfix(PassivateSF, "passivate", "", "", 0);
    init_sysfix(ActivateSF, "activate", "", "", 0);
    init_sysfix(LockSF, "lock", "", "", 0);
    init_sysfix(UnlockSF, "unlock", "", "", 0);

    init_sysfix(CurProcSF, "", "", "", 0);
    init_sysfix(objectSF, "", "", "", 0);

    init_sysfix(commandSF, "command", "", "", 0);

    nofEntryPoints = 0;
    initPointList = NULL;
    memset(padding, 0, sizeof(padding));

    /* SIZE(DumpModuleDesc)+4, then pad to Boundary */
    int32_t dumpSize = (int32_t)sizeof(DumpModuleDesc);
    moduleDescSize = dumpSize + 4;
    mDescPadSize = align_up(moduleDescSize, Boundary) - moduleDescSize;
    moduleDescSize += mDescPadSize;
}

/* ------------------------------------------------------------ */
/* Fixup helpers (operate on in-memory code/data arrays) */

static void put_dword(uint8_t *code, int32_t idx, int32_t value) {
    /* writes little-endian dword at code[idx] */
    code[idx + 0] = (uint8_t)(value & 0xFF);
    code[idx + 1] = (uint8_t)((value >> 8) & 0xFF);
    code[idx + 2] = (uint8_t)((value >> 16) & 0xFF);
    code[idx + 3] = (uint8_t)((value >> 24) & 0xFF);
}

static int32_t get_dword(const uint8_t *code, int32_t idx) {
    return (int32_t)((uint32_t)code[idx] | ((uint32_t)code[idx + 1] << 8) |
            ((uint32_t)code[idx + 2] << 16) | ((uint32_t)code[idx + 3] << 24));
}

/* ------------------------------------------------------------ */
/* Architecture-specific implementations */

/* ---- i386 ---- */

static void i386_PatchFunctionCall(uint8_t *code, int32_t codeImgBase, int32_t link, int32_t target) {
    int32_t instr, nextlink, jmp;
    do {
        instr = get_dword(code, link);
        nextlink = msw(instr);
        jmp = get_dword(code, link - 1);
        if ((lsw(jmp) % 0x100) == 0xE8) {
            /* CALL rel32: target - (PC after instruction) */
            put_dword(code, link, target - (codeImgBase + link + 4));
        } else {
            /* absolute address (e.g. procedure variable assignment) */
            put_dword(code, link, target);
        }
        link = nextlink;
    } while (link != 0xFFFF);
}

static void i386_WriteCallInstruction(FILE *out, int32_t target, int32_t pc) {
    uint8_t buf[5];
    buf[0] = 0xE8; /* CALL rel32 */
    int32_t rel = target - (pc + 5);
    buf[1] = (uint8_t)(rel & 0xFF);
    buf[2] = (uint8_t)((rel >> 8) & 0xFF);
    buf[3] = (uint8_t)((rel >> 16) & 0xFF);
    buf[4] = (uint8_t)((rel >> 24) & 0xFF);
    write_bytes(out, buf, 5);
}

static void i386_EmitHaltSequence(FILE *out) {
    /* STI; NOP; JMP $-1 (infinite loop with interrupts enabled) */
    uint8_t tail[4] = {0xFB, 0x90, 0xEB, 0xFD};
    write_bytes(out, tail, sizeof(tail));
}

static int32_t i386_EmitStackPreamble(FILE *out, int32_t initial_sp, bool multiboot) {
    int32_t emitted = 0;

    /* MOV ESP, imm32 */
    uint8_t esp_code[5];
    esp_code[0] = 0xBC; /* opcode for MOV ESP, imm32 */
    esp_code[1] = (uint8_t)(initial_sp & 0xFF);
    esp_code[2] = (uint8_t)((initial_sp >> 8) & 0xFF);
    esp_code[3] = (uint8_t)((initial_sp >> 16) & 0xFF);
    esp_code[4] = (uint8_t)((initial_sp >> 24) & 0xFF);
    write_bytes(out, esp_code, 5);
    emitted += 5;

    if (multiboot) {
        /* PUSH EBX — Multiboot info pointer */
        write_u8(out, 0x53);
        emitted += 1;
     }

    return emitted;
}

static void i386_PatchImageHeader(FILE *out, int32_t base, int32_t entry,
                                  int32_t size, int32_t rs) {
    (void)rs; /* ramSize not used in i386 standard header */

    /* At file offset 0: E8 + rel32 (CALL to entry point) */
    seek_abs(out, 0);
    write_u8(out, 0xE8);
    write_i32_le(out, entry - (base + 5));

    seek_abs(out, 6);
    write_i32_le(out, base); /* LinkBase */

    seek_abs(out, 22);
    write_i32_le(out, base + size); /* HeapStart */

    seek_abs(out, 30);
    write_i32_le(out, 0); /* PatchSize */

    log_ln();
    log_puts("PatchHeaders:"); log_ln();
    log_puts("  link base: "); log_hex(base); log_ln();
    log_puts("  image size: "); log_hex(size); log_ln();
    log_puts("  heap start: "); log_hex(base + size); log_ln();
    log_puts("  entry point: "); log_hex(entry - (base + 5)); log_ln();
    log_ln();
}

static bool i386_PatchMultibootHeader(FILE *out, int32_t base, int32_t entry, int32_t size) {
    uint32_t magic = 0x1BADB002;
    uint32_t flags = 0x00010000; /* bit 16: raw binary, use provided addresses */
    uint32_t checksum = -(magic + flags);

    seek_abs(out, 0);

    write_u32_le(out, magic);
    write_u32_le(out, flags);
    write_u32_le(out, checksum);

    /* AOUT kludge addresses */
    uint32_t header_addr  = (uint32_t)base;
    uint32_t load_addr    = (uint32_t)base;
    uint32_t load_end_addr = (uint32_t)(base + size);
    uint32_t bss_end_addr  = (uint32_t)(base + size);
    uint32_t entry_addr   = (uint32_t)entry;

    write_u32_le(out, header_addr);
    write_u32_le(out, load_addr);
    write_u32_le(out, load_end_addr);
    write_u32_le(out, bss_end_addr);
    write_u32_le(out, entry_addr);

    log_ln();
    log_puts("PatchHeaders (Multiboot):"); log_ln();
    log_puts("  load_addr: "); log_hex((int32_t)load_addr); log_ln();
    log_puts("  entry_addr: "); log_hex((int32_t)entry_addr); log_ln();
    log_ln();

    return true;
}

/* ---- ARMv6/v7 ---- */

static void arm_PatchFunctionCall(uint8_t *code, int32_t codeImgBase, int32_t link, int32_t target) {
    while (link != 0xFFFF) {
        int32_t instr = get_dword(code, link);
        int32_t nextlink = msw(instr);
        /* ARM BL: offset = (target - (PC + 8)) >> 2, encoded in low 24 bits */
        int32_t offset = (target - (codeImgBase + link + 8)) >> 2;
        int32_t bl = (int32_t)0xEB000000u | (offset & 0x00FFFFFF);
        put_dword(code, link, bl);
        link = nextlink;
    }
}

static void arm_WriteCallInstruction(FILE *out, int32_t target, int32_t pc) {
    /* ARM BL instruction: 0xEB000000 | offset[23:0] */
    int32_t offset = (target - (pc + 8)) >> 2;
    int32_t bl = (int32_t)0xEB000000u | (offset & 0x00FFFFFF);
    write_i32_le(out, bl);
}

static void arm_EmitHaltSequence(FILE *out) {
    /* CPSIE i; WFI; B . (infinite loop) */
    write_i32_le(out, (int32_t)0xF1080080u); /* CPSIE i */
    write_i32_le(out, (int32_t)0xE320F003u); /* WFI */
    write_i32_le(out, (int32_t)0xEAFFFFFEu); /* B . (branch to self) */
}

static int32_t arm_EmitStackPreamble(FILE *out, int32_t initial_sp, bool multiboot) {
    /* MOV SP, #(initial_sp & 0xFFFF)  — lower 16 bits via MOVW
     * MOVT SP, #(initial_sp >> 16)    — upper 16 bits
     * ARM encoding for MOVW Rd, #imm16: 0xE30D0000 | (imm4 << 16) | (Rd << 12) | imm12
     *   where imm16 = (imm4 << 12) | imm12, Rd = 13 (SP)
     * ARM encoding for MOVT Rd, #imm16: 0xE34D0000 | (imm4 << 16) | (Rd << 12) | imm12 */
    int32_t emitted = 0;

    uint32_t lo16 = (uint32_t)initial_sp & 0xFFFF;
    uint32_t hi16 = ((uint32_t)initial_sp >> 16) & 0xFFFF;

    /* MOVW SP, #lo16 */
    uint32_t movw = 0xE300D000u | ((lo16 & 0xF000) << 4) | (lo16 & 0x0FFF);
    write_i32_le(out, (int32_t)movw);

    /* MOVT SP, #hi16 */
    uint32_t movt = 0xE340D000u | ((hi16 & 0xF000) << 4) | (hi16 & 0x0FFF);
    write_i32_le(out, (int32_t)movt);
    emitted += 8;

    if (multiboot) {
        /* PUSH {R2} — boot info / device tree pointer
         * STMDB SP!, {R2} = 0xE92D0004 */
        write_i32_le(out, (int32_t)0xE92D0004u);
        emitted += 4;
    }

    return emitted;
}

static void arm_PatchImageHeader(FILE *out, int32_t base, int32_t entry,
                                 int32_t size, int32_t rs) {
    /* ARM header layout:
     * offset  0: B <entry> (branch to entry point)
     * offset  4: LinkBase
     * offset  8: HeapStart
     * offset 12: ImageSize
     * offset 16: RAMSize (optional) */

    /* ARM B instruction: 0xEA000000 | offset[23:0] */
    int32_t branch_offset = (entry - (base + 8)) >> 2;
    int32_t branch = (int32_t)0xEA000000u | (branch_offset & 0x00FFFFFF);

    seek_abs(out, 0);
    write_i32_le(out, branch);    /* B <entry> */

    seek_abs(out, 4);
    write_i32_le(out, base);      /* LinkBase */

    seek_abs(out, 8);
    write_i32_le(out, base + size); /* HeapStart */

    seek_abs(out, 12);
    write_i32_le(out, size);      /* ImageSize */

    if (rs > 0) {
        seek_abs(out, 16);
        write_i32_le(out, rs);    /* RAMSize */
    }

    log_ln();
    log_puts("PatchHeaders (ARM):"); log_ln();
    log_puts("  link base: "); log_hex(base); log_ln();
    log_puts("  image size: "); log_hex(size); log_ln();
    log_puts("  heap start: "); log_hex(base + size); log_ln();
    log_puts("  entry point: "); log_hex(entry); log_ln();
    if (rs > 0) {
        log_puts("  ram size: "); log_hex(rs); log_ln();
    }
    log_ln();
}

static bool arm_PatchMultibootHeader(FILE *out, int32_t base, int32_t entry, int32_t size) {
    (void)out; (void)base; (void)entry; (void)size;
    return false; /* Multiboot is not supported on ARM */
}

/* ---- RV32 (RISC-V 32-bit) ---- */

/* Encode a RISC-V J-type immediate (for JAL).
 * The 21-bit signed offset is encoded as: imm[20|10:1|11|19:12] in bits [31:12]. */
static uint32_t rv32_encode_j_imm(int32_t offset) {
    uint32_t u = (uint32_t)offset;
    return ((u & 0x100000) << 11) |  /* imm[20] -> bit 31 */
           ((u & 0x0007FE) << 20) |  /* imm[10:1] -> bits 30:21 */
           ((u & 0x000800) << 9)  |  /* imm[11] -> bit 20 */
           (u & 0x0FF000);           /* imm[19:12] -> bits 19:12 */
}

static void rv32_PatchFunctionCall(uint8_t *code, int32_t codeImgBase, int32_t link, int32_t target) {
    while (link != 0xFFFF) {
        int32_t instr = get_dword(code, link);
        int32_t nextlink = msw(instr);
        /* JAL ra, offset: opcode 0x6F, rd=1 (ra) */
        int32_t offset = target - (codeImgBase + link);
        uint32_t jal = 0x000000EFu | rv32_encode_j_imm(offset);
        put_dword(code, link, (int32_t)jal);
        link = nextlink;
    }
}

static void rv32_WriteCallInstruction(FILE *out, int32_t target, int32_t pc) {
    /* JAL ra, offset */
    int32_t offset = target - pc;
    uint32_t jal = 0x000000EFu | rv32_encode_j_imm(offset);
    write_i32_le(out, (int32_t)jal);
}

static void rv32_EmitHaltSequence(FILE *out) {
    /* WFI: 0x10500073 */
    write_i32_le(out, (int32_t)0x10500073u);
    /* J . (JAL x0, 0 — jump to self): offset=0, rd=0 -> opcode 0x6F */
    write_i32_le(out, (int32_t)0x0000006Fu);
}

static int32_t rv32_EmitStackPreamble(FILE *out, int32_t initial_sp, bool multiboot) {
    /* LUI sp, upper20  (sp = x2, so rd=2)
     * ADDI sp, sp, lower12
     *
     * LUI: imm[31:12] | rd | 0110111
     * ADDI: imm[11:0] | rs1 | 000 | rd | 0010011 */
    int32_t emitted = 0;
    uint32_t addr = (uint32_t)initial_sp;

    /* Split into upper 20 and lower 12 bits.
     * If lower12 is negative (bit 11 set), add 1 to upper to compensate. */
    int32_t lower12 = ((int32_t)(addr << 20)) >> 20; /* sign-extend low 12 bits */
    uint32_t upper20 = (addr - (uint32_t)lower12) & 0xFFFFF000u;

    /* LUI x2, upper20 */
    uint32_t lui = upper20 | (2 << 7) | 0x37;
    write_i32_le(out, (int32_t)lui);

    /* ADDI x2, x2, lower12 */
    uint32_t addi = ((uint32_t)lower12 << 20) | (2 << 15) | (0 << 12) | (2 << 7) | 0x13;
    write_i32_le(out, (int32_t)addi);
    emitted += 8;

    if (multiboot) {
        /* Push A1 (x11) onto stack — boot info / device tree pointer
         * ADDI sp, sp, -4 : 0xFFC10113
         * SW   a1, 0(sp)  : 0x00B12023 */
        write_i32_le(out, (int32_t)0xFFC10113u); /* ADDI sp, sp, -4 */
        write_i32_le(out, (int32_t)0x00B12023u); /* SW a1, 0(sp) */
        emitted += 8;
    }

    return emitted;
}

static void rv32_PatchImageHeader(FILE *out, int32_t base, int32_t entry,
                                  int32_t size, int32_t rs) {
    /* RV32 header layout (same structure as ARM):
     * offset  0: JAL x0, <entry> (unconditional jump to entry point)
     * offset  4: LinkBase
     * offset  8: HeapStart
     * offset 12: ImageSize
     * offset 16: RAMSize (optional) */

    int32_t offset = entry - base;
    uint32_t jal = 0x0000006Fu | rv32_encode_j_imm(offset); /* JAL x0 */

    seek_abs(out, 0);
    write_i32_le(out, (int32_t)jal); /* JAL x0, <entry> */

    seek_abs(out, 4);
    write_i32_le(out, base);         /* LinkBase */

    seek_abs(out, 8);
    write_i32_le(out, base + size);  /* HeapStart */

    seek_abs(out, 12);
    write_i32_le(out, size);         /* ImageSize */

    if (rs > 0) {
        seek_abs(out, 16);
        write_i32_le(out, rs);       /* RAMSize */
    }

    log_ln();
    log_puts("PatchHeaders (RV32):"); log_ln();
    log_puts("  link base: "); log_hex(base); log_ln();
    log_puts("  image size: "); log_hex(size); log_ln();
    log_puts("  heap start: "); log_hex(base + size); log_ln();
    log_puts("  entry point: "); log_hex(entry); log_ln();
    if (rs > 0) {
        log_puts("  ram size: "); log_hex(rs); log_ln();
    }
    log_ln();
}

static bool rv32_PatchMultibootHeader(FILE *out, int32_t base, int32_t entry, int32_t size) {
    (void)out; (void)base; (void)entry; (void)size;
    return false; /* Multiboot is not supported on RISC-V */
}

/* ---- ArchOps table instances ---- */

static const ArchOps arch_i386 = {
    .name               = "i386",
    .call_instr_size    = 5,    /* E8 + rel32 */
    .halt_seq_size      = 4,    /* STI; NOP; JMP $-1 */
    .PatchFunctionCall  = i386_PatchFunctionCall,
    .WriteCallInstruction = i386_WriteCallInstruction,
    .EmitHaltSequence   = i386_EmitHaltSequence,
    .EmitStackPreamble  = i386_EmitStackPreamble,
    .PatchImageHeader   = i386_PatchImageHeader,
    .PatchMultibootHeader = i386_PatchMultibootHeader,
};

static const ArchOps arch_arm32 = {
    .name               = "arm32",
    .call_instr_size    = 4,    /* ARM BL */
    .halt_seq_size      = 12,   /* CPSIE i; WFI; B . */
    .PatchFunctionCall  = arm_PatchFunctionCall,
    .WriteCallInstruction = arm_WriteCallInstruction,
    .EmitHaltSequence   = arm_EmitHaltSequence,
    .EmitStackPreamble  = arm_EmitStackPreamble,
    .PatchImageHeader   = arm_PatchImageHeader,
    .PatchMultibootHeader = arm_PatchMultibootHeader,
};

static const ArchOps arch_rv32 = {
    .name               = "rv32",
    .call_instr_size    = 4,    /* RV32 JAL ra */
    .halt_seq_size      = 8,    /* WFI; J . */
    .PatchFunctionCall  = rv32_PatchFunctionCall,
    .WriteCallInstruction = rv32_WriteCallInstruction,
    .EmitHaltSequence   = rv32_EmitHaltSequence,
    .EmitStackPreamble  = rv32_EmitStackPreamble,
    .PatchImageHeader   = rv32_PatchImageHeader,
    .PatchMultibootHeader = rv32_PatchMultibootHeader,
};

/* ------------------------------------------------------------ */
/* Generic fixup wrappers (delegate to arch) */

static void fixup_call(uint8_t *code, int32_t codeImgBase, int32_t link, int32_t target) {
    arch->PatchFunctionCall(code, codeImgBase, link, target);
}

static void fixup_var(uint8_t *code, DataLinkEntry *dataLinks, int32_t linkIndex, int32_t fixval) {
    int16_t nofFixups = dataLinks[linkIndex].nofFixups;
    for (int32_t i = 0; i < nofFixups; i++) {
        int32_t off = (int32_t)dataLinks[linkIndex].offset[i];
        int32_t val = get_dword(code, off);
        put_dword(code, off, val + fixval);
    }
}

static void fix_data_links(Module *m, DataLinkEntry *dataLinks) {
    /* global variables */
    uint8_t *codebase = m->code;
    int16_t modNo = (int16_t)dataLinks[0].mod;
    int16_t nofFixups = dataLinks[0].nofFixups;
    if (modNo == 0) {
        for (int32_t i = 0; i < nofFixups; i++) {
            int32_t off = (int32_t)dataLinks[0].offset[i];
            int32_t val = get_dword(codebase, off);
            put_dword(codebase, off, val + m->sb);
        }
    }
}

static void fix_entry(Module *m) {
    int32_t e = m->codeBase;
    for (int32_t i = 0; i < m->nofEntries; i++) m->entries[i] += (uint32_t)e;
}

static void fix_cmd(Module *m) {
    int32_t e = m->codeBase;
    for (int32_t i = 0; i < m->nofCmds; i++) m->cmds[i].adr += e;
}

static void fix_ptr(Module *m) {
    int32_t e = m->sb;
    for (int32_t i = 0; i < m->nofPtrs; i++) m->ptrTab[i] += e;
}

/* Map link table entry codes 253..246 to SysFix indices (newSF..UnlockSF).
 * Entry 253 -> newSF (0), 252 -> sysnewSF (1), ..., 246 -> UnlockSF (7). */
static int32_t sysfix_from_entry(uint8_t entry) {
    return 253 - (int32_t)entry;  /* 253->0, 252->1, ..., 246->7 */
}

static void fixup_links(Module *m, LinkEntry *linkTab, int32_t nofLinks, DataLinkEntry *dataLinks) {
    uint8_t *codebase = m->code;
    /* database is address of SB; here we model as data pointer + dataSize */
    uint8_t *database = m->data + m->dataSize;

    for (int32_t i = 0; i < nofLinks; i++) {
        if (linkTab[i].mod == 0) {
            uint8_t entry = linkTab[i].entry;
            switch (entry) {
            case 255: {
                /* case table fixup in constant area */
                uint16_t offs = linkTab[i].link;
                while (offs != 0xFFFF) {
                    int32_t val = get_dword(database, offs);
                    put_dword(database, offs, m->codeBase + lsw(val));
                    offs = (uint16_t)msw(val);
                }
                break;
            }
            case 254: {
                /* local procedure assignment */
                uint16_t offs = linkTab[i].link;
                while (offs != 0xFFFF) {
                    int32_t val = get_dword(codebase, offs);
                    put_dword(codebase, offs, (int32_t)m->entries[lsw(val)]);
                    offs = (uint16_t)msw(val);
                }
                break;
            }
            case 253: case 252: case 251: case 250:
            case 249: case 248: case 247: case 246: {
                /* SysFix call fixups: newSF through UnlockSF */
                int32_t sfIdx = sysfix_from_entry(entry);
                sysfix_warning(sfIdx);
                fixup_call(codebase, m->codeBase, linkTab[i].link, SysFix[sfIdx].adr);
                break;
            }
            default: {
                char buf[128];
                snprintf(buf, sizeof(buf), "Unknown fixup entry %u", (unsigned)entry);
                halt_msg(buf);
            }
            }
        } else {
            /* imported procedure fixups are expected to be handled via ReadUse/CheckUseBlock */
            halt_msg("Unexpected imported-procedure fixup in link table");
        }
    }

    (void)dataLinks;
}

/* ------------------------------------------------------------ */
/* Ref table parsing (FindAdr) */

static void get_num_from_refs(const uint8_t *refs, int32_t *i, int32_t *num) {
    int32_t n = 0;
    int32_t s = 0;
    uint8_t x = refs[(*i)++];
    while (x >= 128) {
        n += ((int32_t)x - 128) << s;
        s += 7;
        x = refs[(*i)++];
    }
    int32_t last = (int32_t)(x & 0x3F);
    if (x & 0x40) last -= 0x40;
    *num = n + (last << s);
}

static int32_t find_adr(Module *mod, const char *pat, int32_t type) {
    int32_t i = 0;
    int32_t m = mod->refSize;
    uint8_t ch = mod->refs[i++];

    while ((i < m) && ((ch == 0xF8) || (ch == 0xF9))) {
        int32_t ofs = 0;
        get_num_from_refs(mod->refs, &i, &ofs);
        if (ch == 0xF9) {
            int32_t t = 0;
            get_num_from_refs(mod->refs, &i, &t);
            i += 3; /* RetType, procLev, slFlag */
        }

        bool found = true;
        int32_t j = 0;
        do {
            ch = mod->refs[i++];
            found = found && (ch == (uint8_t)pat[j]);
            j++;
        } while (ch != 0);

        if (found && (type == Proc)) return ofs;

        if (i < m) {
            ch = mod->refs[i++];
            while ((i < m) && (ch >= 0x01) && (ch <= 0x03)) {
                ch = mod->refs[i++];
                if ((ch >= 0x81) || (ch == 0x16) || (ch == 0x1D)) {
                    int32_t t = 0;
                    get_num_from_refs(mod->refs, &i, &t);
                }
                int32_t vofs = 0;
                get_num_from_refs(mod->refs, &i, &vofs);
                found = true;
                j = 0;
                do {
                    ch = mod->refs[i++];
                    found = found && (ch == (uint8_t)pat[j]);
                    j++;
                } while (ch != 0);
                if (found && (type == Var)) return vofs;
                if (i < m) ch = mod->refs[i++];
            }
        }
    }

    halt_msg("FindAdr: name not found");
    return 0;
}

/* ------------------------------------------------------------ */
/* Export table utilities */

static void assign_export_sizes(ExportDesc *exp, Module *m) {
    exp->done = true;
    int32_t size = exp->nofExp;
    if ((size == 0) || exp->dsc[0].done) return;
    exp->dsc[0].Adr = m->expAdr + m->expSize + 4;
    assert((exp->dsc[0].Adr % 32) == 0);
    m->expSize += 32 * ((size * 16 + TagSize + ArrayDescSize + 31) / 32);
    for (int32_t i = 0; i < size; i++) assign_export_sizes(&exp->dsc[i], m);
}

static void set_tdesc_adr(Module *M, int32_t entry, TypeDesc *t) {
    int32_t i = 0;
    while (i < M->exportTree.nofExp) {
        ExportDesc *d = &M->exportTree.dsc[i];
        if (d->dsc && (d->dsc[0].adr == entry)) {
            d->dsc[0].type = t;
            return;
        }
        i++;
    }
}

static void find_tdesc_adr(Module *M, int32_t fp, TypeDesc **t) {
    int32_t i = 0;
    while (i < M->exportTree.nofExp && M->exportTree.dsc[i].fp != fp) i++;
    if (i < M->exportTree.nofExp) {
        *t = M->exportTree.dsc[i].dsc[0].type;
        return;
    }
    halt_msg("FindTDescAdr failed");
}

static void init_type(Module *m, int32_t idx) {
    if (!m->tdescs || idx >= m->nofTds)
        halt_msg("InitType out of bounds");
    TypeDesc *td = m->tdescs[idx];
    if (!td->initialized) {
        set_tdesc_adr(m, td->tdEntry, td);
        td->extlev = 0;
        int32_t baseModNo = td->baseMod;
        if (baseModNo != -1) {
            if (baseModNo == 0) {
                int32_t j = 0;
                while (j < m->nofTds && m->tdescs[j]->tdEntry != td->baseEntry) j++;
                init_type(m, j);
                td->baseType = m->tdescs[j];
            } else if (baseModNo > 0) {
                Module *baseMod = m->imports[baseModNo - 1];
                find_tdesc_adr(baseMod, td->baseEntry, &td->baseType);
            } else {
                halt_msg("InitType: invalid baseModNo");
            }
            assert(td->baseType);
            td->extlev = td->baseType->extlev + 1;
        }
        td->initialized = true;
    }
}

static void init_types(Module *m) {
    for (int32_t i = 0; i < m->nofTds; i++) init_type(m, i);
}

/* ------------------------------------------------------------ */
/* Object file block readers */

static void expect_tag(FILE *f, uint8_t tag, const char *modName) {
    uint8_t ch = read_u8(f);
    if (ch != tag) {
        (void)modName;
        err_msg(corruptedObjFile, modName);
    }
}

typedef struct {
    ExportDesc *ptr;
} ExportPtrWrap;

/* Context for recursive export loader (replaces nested function) */
typedef struct {
    FILE *f;
    Module *m;
    ExportDesc **structs;
    int *nofStr;
} LoaderCtx;

static void load_scope(LoaderCtx *c, ExportDesc *scope, int level, int32_t adr) {
    uint16_t nof = read_u16_le(c->f);
    scope->nofExp = (int16_t)nof;
    if (scope->nofExp != 0) {
        scope->dsc = (ExportDesc *)calloc((size_t)scope->nofExp, sizeof(ExportDesc));
        if (!scope->dsc)
            halt_msg("out of memory (export)");
        scope->dsc[0].adr = adr;
    } else {
        scope->dsc = NULL;
    }

    if (level == EUrecScope) {
        (*c->nofStr)++;
        if (*c->nofStr >= 1024)
            halt_msg("too many export structs");
        c->structs[*c->nofStr] = scope;
    }

    int32_t fp = read_num(c->f);
    int no = 0;
    int no2 = 0;

    while (fp != EUEnd) {
        if (fp == EURecord) {
            int32_t off = read_num(c->f);
            if (off < 0) {
                ExportDesc *old = c->structs[-off];
                scope->dsc[no2].nofExp = old->nofExp;
                scope->dsc[no2].dsc = old->dsc;
            } else {
                load_scope(c, &scope->dsc[no2], EUrecScope, off);
            }
        } else {
            if (level == EUobjScope) {
                scope->dsc[no].adr = read_num(c->f);
            }
            scope->dsc[no].fp = fp;
            no2 = no;
            no++;
        }
        fp = read_num(c->f);
    }
}

static void read_export(FILE *f, Module *m) {
    ExportDesc *structs[1024];
    memset(structs, 0, sizeof(structs));
    int nofStr = 0;

    expect_tag(f, 0x88, m->name);

    LoaderCtx ctx = {f, m, structs, &nofStr};
    memset(&m->exportTree, 0, sizeof(m->exportTree));
    load_scope(&ctx, &m->exportTree, EUobjScope, 0);
}

static void read_header(FILE *f, Module *m, int16_t *nofDataLinks, int16_t *nofLinks) {
    m->refSize = read_i32_le(f);
    m->nofEntries = (int32_t)read_i16_le(f);
    m->nofCmds = (int32_t)read_i16_le(f);
    m->nofPtrs = (int32_t)read_i16_le(f);
    m->nofTds = (int32_t)read_i16_le(f);
    m->nofImps = (int32_t)read_i16_le(f);
    *nofDataLinks = read_i16_le(f);
    *nofLinks = read_i16_le(f);
    m->dataSize = read_i32_le(f);
    m->conSize = (int32_t)read_i16_le(f);
    m->codeSize = (int32_t)read_u16_le(f);
    read_string(f, m->name, sizeof(m->name));

    if (Trace) {
        log_puts("refsize = "); log_hex(m->refSize); log_ln();
        log_puts("nofEntries = "); log_hex(m->nofEntries); log_ln();
        log_puts("nofCmds  = "); log_hex(m->nofCmds); log_ln();
        log_puts("nofPtrs  = "); log_hex(m->nofPtrs); log_ln();
        log_puts("nofTds  = "); log_hex(m->nofTds); log_ln();
        log_puts("nofImps  = "); log_hex(m->nofImps); log_ln();
        log_puts("nofDataLinks  = "); log_hex(*nofDataLinks); log_ln();
        log_puts("nofLinks  = "); log_hex(*nofLinks); log_ln();
        log_puts("dataSize  = "); log_hex(m->dataSize); log_ln();
        log_puts("conSize  = "); log_hex(m->conSize); log_ln();
        log_puts("codeSize  = "); log_hex(m->codeSize); log_ln();
        log_puts("name  = "); log_puts(m->name); log_ln();
    }
}

static void read_entry(FILE *f, Module *m) {
    if (m->nofEntries > 0) {
        m->entries = (uint32_t *)calloc((size_t)m->nofEntries, sizeof(uint32_t));
        if (!m->entries)
            halt_msg("out of memory (entries)");
    }
    expect_tag(f, 0x82, m->name);
    for (int32_t i = 0; i < m->nofEntries; i++)
        m->entries[i] = (uint32_t)read_u16_le(f);
}

static void read_cmd(FILE *f, Module *m) {
    if (m->nofCmds > 0) {
        m->cmds = (CommandDesc *)calloc((size_t)m->nofCmds, sizeof(CommandDesc));
        if (!m->cmds)
            halt_msg("out of memory (cmds)");
    }
    expect_tag(f, 0x83, m->name);
    for (int32_t i = 0; i < m->nofCmds; i++) {
        read_string(f, m->cmds[i].name, sizeof(m->cmds[i].name));
        m->cmds[i].adr = (int32_t)read_u16_le(f);
    }
}

static void read_ptr(FILE *f, Module *m) {
    if (m->nofPtrs > 0) {
        m->ptrTab = (int32_t *)calloc((size_t)m->nofPtrs, sizeof(int32_t));
        if (!m->ptrTab)
            halt_msg("out of memory (ptrTab)");
    }
    expect_tag(f, 0x84, m->name);
    for (int32_t i = 0; i < m->nofPtrs; i++) {
        m->ptrTab[i] = read_i32_le(f);
        m->ptrTab[i] -= (m->ptrTab[i] % 4);
    }
}

static void read_import(FILE *f, Module *m) {
    if (m->nofImps > 0) {
        m->imports = (Module **)calloc((size_t)m->nofImps, sizeof(Module *));
        if (!m->imports)
            halt_msg("out of memory (imports)");
    }
    expect_tag(f, 0x85, m->name);
    for (int32_t mno = 0; mno < m->nofImps && res == done; mno++) {
        ModuleName mname;
        read_string(f, mname, sizeof(mname));
        Module *imp = find_module(mname);
        if (!imp)
            halt_msg("Imported module not loaded");
        imp->refcnt++;
        m->imports[mno] = imp;
    }
}

static DataLinkEntry *read_data_links(FILE *f, Module *m, int16_t nofDataLinks) {
    (void)m;
    expect_tag(f, 0x8D, m->name);
    if (nofDataLinks <= 0) return NULL;
    DataLinkEntry *dataLinks = (DataLinkEntry *)calloc((size_t)nofDataLinks, sizeof(DataLinkEntry));
    if (!dataLinks)
        halt_msg("out of memory (dataLinks)");

    for (int16_t i = 0; i < nofDataLinks; i++) {
        dataLinks[i].mod = read_u8(f);
        dataLinks[i].entry = read_i16_le(f);
        dataLinks[i].nofFixups = read_i16_le(f);
        if (dataLinks[i].nofFixups > 0) {
            dataLinks[i].offset = (uint16_t *)calloc((size_t)dataLinks[i].nofFixups, sizeof(uint16_t));
            if (!dataLinks[i].offset)
                halt_msg("out of memory (dataLinks offsets)");
            for (int16_t j = 0; j < dataLinks[i].nofFixups; j++) dataLinks[i].offset[j] = read_u16_le(f);
        }
    }

    return dataLinks;
}

static LinkEntry *read_links(FILE *f, Module *m, int16_t nofLinks) {
    expect_tag(f, 0x86, m->name);
    if (nofLinks <= 0) return NULL;
    LinkEntry *links = (LinkEntry *)calloc((size_t)nofLinks, sizeof(LinkEntry));
    if (!links)
        halt_msg("out of memory (links)");
    for (int16_t i = 0; i < nofLinks; i++) {
        links[i].mod = read_u8(f);
        links[i].entry = read_u8(f);
        links[i].link = read_u16_le(f);
    }
    return links;
}

static void read_data_const(FILE *f, Module *m) {
    m->dataSize = align_up(m->dataSize, 8);
    int32_t total = m->dataSize + m->conSize;
    if (total > 0) {
        m->data = (uint8_t *)calloc((size_t)total, 1);
        if (!m->data)
            halt_msg("out of memory (data)");
    }
    expect_tag(f, 0x87, m->name);
    int32_t t = m->dataSize;
    for (int32_t i = 0; i < m->conSize; i++) {
        m->data[t++] = read_u8(f);
    }
}

static void read_code(FILE *f, Module *m) {
    if (m->codeSize > 0) {
        m->code = (uint8_t *)calloc((size_t)m->codeSize, 1);
        if (!m->code)
            halt_msg("out of memory (code)");
    }
    expect_tag(f, 0x89, m->name);
    read_bytes(f, m->code, (size_t)m->codeSize);
}

static void read_type(FILE *f, Module *m) {
    expect_tag(f, 0x8B, m->name);
    if (res != done) return;
    if (m->nofTds > 0) {
        m->tdescs = (TypeDesc **)calloc((size_t)m->nofTds, sizeof(TypeDesc *));
        if (!m->tdescs)
            halt_msg("out of memory (tdescs)");
    }

    for (int32_t i = 0; i < m->nofTds; i++) {
        TypeDesc *td = (TypeDesc *)calloc(1, sizeof(TypeDesc));
        if (!td)
            halt_msg("out of memory (TypeDesc)");
        td->initialized = false;
        td->module = m;

        td->size = read_i32_le(f);
        td->tdEntry = read_i16_le(f);
        td->baseMod = read_i16_le(f);
        td->baseEntry = read_i32_le(f);
        td->nofMethods = read_i16_le(f);
        (void)read_i16_le(f); /* nofInhMeth */
        td->nofNewMethods = read_i16_le(f);
        td->nofPtrs = read_i16_le(f);
        read_string(f, td->name, sizeof(td->name));

        if (td->nofNewMethods > 0) {
            td->newMethods = (NewMethod *)calloc((size_t)td->nofNewMethods, sizeof(NewMethod));
            if (!td->newMethods)
                halt_msg("out of memory (newMethods)");
            for (int32_t j = 0; j < td->nofNewMethods; j++) {
                td->newMethods[j].mthNo = read_i16_le(f);
                td->newMethods[j].entryNo = read_i16_le(f);
            }
        }
        if (td->nofPtrs > 0) {
            td->ptrOffset = (int32_t *)calloc((size_t)td->nofPtrs, sizeof(int32_t));
            if (!td->ptrOffset)
                halt_msg("out of memory (ptrOffset)");
            for (int32_t j = 0; j < td->nofPtrs; j++) td->ptrOffset[j] = read_i32_le(f);
        }

        /* td size calculations (as in BootLinker.Mod) */
        assert(((m->typeTableAdr + m->typeTableSize + 4) % Boundary) == 0);
        td->tdSize = 13 + td->nofMethods + ExtTabWordSize + 1;
        td->tdSize += (-td->tdSize + 2) % 4;
        td->tdAdr = td->tdSize * 4 + m->typeTableAdr + m->typeTableSize + 4;
        assert((td->tdAdr % 16) == 8);
        td->tdSize = (td->tdSize + 1 + td->nofPtrs + 1) * 4;

        /* write td address in constants section */
        put_dword(m->data + m->dataSize, td->tdEntry, td->tdAdr);

        td->padSize = (-td->tdSize - 4) % Boundary;
        if (td->padSize < 0) td->padSize += Boundary;
        m->typeTableSize += 4 + td->tdSize + td->padSize;

        assert((m->typeTableSize % 32) == 0);
        if ((strcmp(SysFix[modDescSF].module, m->name) == 0) && (strcmp(SysFix[modDescSF].command, td->name) == 0)) {
            SysFix[modDescSF].adr = td->tdAdr;
        }
        if ((strcmp(SysFix[expDescSF].module, m->name) == 0) && (strcmp(SysFix[expDescSF].command, td->name) == 0)) {
            SysFix[expDescSF].adr = td->tdAdr;
        }

        m->tdescs[i] = td;
    }
}

static void read_ref(FILE *f, Module *m) {
    if (m->refSize > 0) {
        m->refs = (uint8_t *)calloc((size_t)m->refSize, 1);
        if (!m->refs)
            halt_msg("out of memory (refs)");
    }
    expect_tag(f, 0x8C, m->name);
    read_bytes(f, m->refs, (size_t)m->refSize-1);
}

/* ------------------------------------------------------------ */
/* Use block checking (linking imported refs) */

static void check_use_block(FILE *f, Module *M, DataLinkEntry *dataLinks);

static void fixup_var_for_use(Module *M, DataLinkEntry *dataLinks, int32_t link, int32_t fixval) {
    fixup_var(M->code, dataLinks, link, fixval);
}

static void fixup_call_for_use(Module *M, int32_t link, int32_t fixval) {
    fixup_call(M->code, M->codeBase, link, fixval);
}

static void check_scope(FILE *f, ExportDesc *scope, int level, Module *M, Module *mod, DataLinkEntry *dataLinks) {
    bool tmpErr = (level == EUerrScope);
    int32_t fp = read_num(f);
    int32_t i = 0;

    while (fp != EUEnd) {
        if (fp == EURecord) {
            int32_t link = read_num(f);
            if (tmpErr) {
                check_scope(f, &scope->dsc[i], EUerrScope, M, mod, dataLinks);
            } else {
                if (scope->dsc[i].dsc) {
                    if (link != 0) {
                        ExportDesc *tadr = &scope->dsc[i].dsc[0];
                        int32_t tdadr = get_dword(mod->data + mod->dataSize, tadr->adr);
                        put_dword(M->data + M->dataSize, -link, tdadr);
                    }
                }
                check_scope(f, &scope->dsc[i], EUrecScope, M, mod, dataLinks);
            }
        } else {
            char name[256];
            read_string(f, name, sizeof(name));
            if (level >= EUobjScope) tmpErr = false;
            int32_t link = 0;
            if (level == EUobjScope) link = read_num(f);

            i = 0;
            while (i < scope->nofExp && scope->dsc[i].fp != fp) i++;
            if (i >= scope->nofExp) {
                err_msg(incompImport, mod->name);
                tmpErr = true;
                if (logFile) {
                    log_ln();
                    log_ch('\t');
                    if (strcmp(name, "@") == 0) log_puts("RECORD ");
                    else log_puts(name);
                    log_puts(" incompatible");
                    log_ln();
                }
                i = scope->nofExp - 1;
            } else if ((level == EUobjScope) && (link != 0)) {
                if ((and32(link, (int32_t)EUProcFlag) == 0)) {
                    fixup_var_for_use(M, dataLinks, link, mod->sb + scope->dsc[i].adr);
                } else {
                    fixup_call_for_use(M, link - (int32_t)EUProcFlag, scope->dsc[i].adr + mod->codeBase);
                }
            }
        }

        fp = read_num(f);
    }
}

/* Forward decl: Load */
static void load_module(Module **m, const char *name, int32_t *base);

static void check_use_block(FILE *f, Module *M, DataLinkEntry *dataLinks) {
    ModuleName name;
    read_string(f, name, sizeof(name));
    while (name[0] != 0 && res == done) {
        Module *mod = find_module(name);
        if (!mod) {
            int32_t tmpBase = imageSize;
            load_module(&mod, name, &tmpBase);
            imageSize = tmpBase;
        }
        if (res == done) {
            check_scope(f, &mod->exportTree, EUobjScope, M, mod, dataLinks);
        }
        read_string(f, name, sizeof(name));
    }
}

static void read_use(FILE *f, Module *m, DataLinkEntry *dataLinks) {
    expect_tag(f, 0x8A, m->name);
    check_use_block(f, m, dataLinks);
}

/* ------------------------------------------------------------ */
/* Dumping / image writing */

static void dump_ptr_header(FILE *out, int32_t address, int32_t size, int32_t *adrPad, int32_t *sizePad) {
    int32_t header[7];
    *adrPad = align_up(address + 4, Boundary) - 4 - address;
    *sizePad = align_up(size + 28, Boundary) - size;
    header[0] = (address + *adrPad) + 4;
    header[1] = (size + *sizePad) - 4;
    header[2] = -4;
    header[3] = 0;
    header[4] = 0;
    header[5] = 0;
    header[6] = header[0];

    if (*adrPad > 0) write_bytes(out, padding, (size_t)*adrPad);
    for (int i = 0; i < 7; i++) write_i32_le(out, header[i]);
    *sizePad -= 28;
}

static void dump_init_calls(FILE *out, int32_t *entry, int32_t stack_size, int32_t image_base, bool multiboot) {
    log_puts("Init block at "); log_hex(*entry); log_ln();
    assert(((*entry + 4) % Boundary) == 0);

    /* Compute preamble size: the arch tells us how many bytes it will emit.
     * i386:  MOV ESP,imm32 (5) + optional PUSH EBX (1) = 5 or 6
     * ARM32: MOVW+MOVT SP (8) + optional PUSH {R2} (4) = 8 or 12
     * RV32:  LUI+ADDI SP (8) + optional ADDI+SW (8) = 8 or 16 */
    int32_t preamble_size = 0;
    if (stack_size > 0) {
        if (arch == &arch_i386)
            preamble_size = multiboot ? 6 : 5;
        else if (arch == &arch_arm32)
            preamble_size = multiboot ? 12 : 8;
        else
            preamble_size = multiboot ? 16 : 8;
    }

    int32_t initCodeSize = nofEntryPoints * arch->call_instr_size + arch->halt_seq_size + preamble_size;

    int32_t adrPad = 0;
    int32_t sizePad = 0;
    dump_ptr_header(out, *entry, initCodeSize, &adrPad, &sizePad);
    *entry += 28;
    assert(adrPad == 0);

    log_puts("Init code at "); log_hex(*entry); log_ln();
    InitPointNode *ip = initPointList;
    int32_t pc = *entry;

    if (stack_size > 0) {
        /* SP must point past the entire image including init code and stack.
         * At this point imageSize covers modules + stack (set in main),
         * but not the init block we are writing now.  Add the init block:
         * 28 (ptr header) + initCodeSize + sizePad. */
        int32_t initBlockSize = 28 + initCodeSize + sizePad;
        int32_t initial_sp = image_base + imageSize + initBlockSize;
        int32_t emitted = arch->EmitStackPreamble(out, initial_sp, multiboot);
        pc += emitted;
    }

    while (ip) {
        log_puts("Body at "); log_hex(ip->entryPoint); log_ln();
        arch->WriteCallInstruction(out, ip->entryPoint, pc);
        pc += arch->call_instr_size;
        ip = ip->next;
    }

    arch->EmitHaltSequence(out);
    if (sizePad > 0) write_bytes(out, padding, (size_t)sizePad);
}

static void patch_header(FILE *out, int32_t base, int32_t entry, int32_t size) {
    arch->PatchImageHeader(out, base, entry, size, ramSize);
}

static void insert_pad(FILE *out, int32_t *pos, int32_t size, int32_t alignTo) {
    int32_t padSize = (-size) % alignTo;
    if (padSize < 0) padSize += alignTo;
    write_bytes(out, padding, (size_t)padSize);
    *pos += size + padSize;
}

static int32_t get_method_address(int32_t n, TypeDesc *t) {
    if (!t) {
        halt_msg("GetMethodAddress: NIL type");
    }
    for (int32_t i = 0; i < t->nofNewMethods; i++) {
        if (t->newMethods[i].mthNo == n) {
            return (int32_t)t->module->entries[t->newMethods[i].entryNo];
        }
    }
    return get_method_address(n, t->baseType);
}

static void dump_types(FILE *out, Module *m, int32_t *next) {
    for (int32_t i = 0; i < m->nofTds; i++) {
        assert((*next % Boundary) == 28);
        TypeDesc *t = m->tdescs[i];
        int32_t tag = *next + 4;

        write_i32_le(out, tag);
        write_i32_le(out, t->tdSize);
        write_i32_le(out, -4);
        write_i32_le(out, t->tdAdr);
        write_i32_le(out, t->extlev);
        write_bytes(out, t->name, 32);
        write_i32_le(out, m->modDescAdr);

        *next += 13 * 4 + 4;
        *next += t->nofMethods * 4 + 16 * 4;

        /* padding for methods */
        int32_t j = (-(*next) - 12) % 16;
        if (j < 0) j += 16;
        *next += j;
        assert((*next % 16) == 4);
        for (int32_t k = 0; k < j / 4; k++) write_i32_le(out, 0);

        /* methods */
        for (int32_t k = t->nofMethods - 1; k >= 0; k--) {
            write_i32_le(out, get_method_address(k, t));
        }

        /* padding for tags */
        for (int32_t k = t->extlev + 1; k <= 15; k++) write_i32_le(out, 0);

        /* tags (write tdAdr chain) */
        TypeDesc *cur = t;
        while (cur) {
            write_i32_le(out, cur->tdAdr);
            if (cur->extlev != 0) cur = cur->baseType;
            else break;
        }

        assert((*next % 16) == 4);
        write_i32_le(out, tag);
        *next += 4;

        /* record size and ptr offsets */
        write_i32_le(out, t->size);
        for (int32_t k = 0; k < t->nofPtrs; k++) write_i32_le(out, t->ptrOffset[k]);
        write_i32_le(out, -4 * (t->nofPtrs + 1));
        write_bytes(out, padding, (size_t)t->padSize);

        *next += 4 + t->nofPtrs * 4 + 4 + t->padSize;
    }
}

static void dump_export(FILE *out, ExportDesc *exp, int32_t *next, int32_t tag) {
    assert((*next % 32) == 0);
    int32_t num = exp->nofExp;
    exp->done = false;
    if ((num == 0) || !exp->dsc[0].done) return;

    /* The tag is written into the 4 bytes just before *next (pre-allocated in padding) */
    assert(exp->dsc[0].Adr == *next);
    write_i32_le(out, tag);

    ArrayDesc arrHdr;
    arrHdr.a = exp->dsc[0].Adr + (num - 1) * 16 + ArrayDescSize;
    arrHdr.b = 0;
    arrHdr.c = exp->dsc[0].Adr + ArrayDescSize;
    arrHdr.len = num;

    write_i32_le(out, arrHdr.a);
    write_i32_le(out, arrHdr.b);
    write_i32_le(out, arrHdr.c);
    write_i32_le(out, arrHdr.len);

    for (int32_t i = 0; i < num; i++) {
        write_i32_le(out, exp->dsc[i].fp);
        write_i32_le(out, exp->dsc[i].adr);
        write_u16_le(out, (uint16_t)exp->dsc[i].nofExp);
        write_u16_le(out, 0);
        if (exp->dsc[i].nofExp == 0) write_i32_le(out, 0);
        else write_i32_le(out, exp->dsc[i].dsc[0].Adr);
    }

    insert_pad(out, next, TagSize + ArrayDescSize + num * 16, 32);
    for (int32_t i = 0; i < num; i++) dump_export(out, &exp->dsc[i], next, tag);
}

static void dump_modules(FILE *out) {
    /* Fix module list tail pointer: update the kernel's 'modules' variable
   * to point to the last module's descriptor. */
    if (SysFix[listSF].adr != 0 && listSF_module) {
        Module *last = objectList;
        while (last && last->link) last = last->link;
        if (last) {
            put_dword(listSF_module->data + listSF_module->dataSize,
                      listSF_offset, last->modDescAdr);
        }
    }

    Module *m = objectList;
    int32_t prevmod = 0;

    while (m) {
        DumpModuleDesc img;
        memset(&img, 0, sizeof(img));

        img.link = prevmod;
        prevmod = m->modDescAdr;
        memcpy(img.name, m->name, sizeof(img.name));
        img.init = (uint8_t)(m->init ? 1 : 0);
        img.trapped = 0;
        img.refcnt = m->refcnt;
        if (img.refcnt == 0) img.refcnt = 1;
        img.sb = m->sb;

        int32_t next = m->base;
        int32_t tag = next + 4;

        log_ln();
        log_puts("--------- MODULE "); log_puts(m->name); log_ln();
        dump_addr(next, "Base");

        assert(((next + 4) % Boundary) == 0);
        assert(tell_abs(out) + imageBase == m->base);

        int32_t size = m->imageSize - moduleDescSize - m->typeTableSize - m->expSize - 28;

        int32_t adrPad = 0, sizePad = 0;
        dump_ptr_header(out, next, size, &adrPad, &sizePad);
        next += 28;
        assert(adrPad == 0);

        /* Entries */
        assert((next % 16) == 8);
        img.entries = next;
        int32_t num = m->nofEntries;
        ArrayDesc arrHdr = {0, 0, 0, num};
        /* hidden header */
        write_i32_le(out, arrHdr.a);
        write_i32_le(out, arrHdr.b);
        write_i32_le(out, arrHdr.c);
        write_i32_le(out, arrHdr.len);
        if (num > 0) {
            for (int32_t i = 0; i < num; i++) write_u32_le(out, m->entries[i]);
        }
        insert_pad(out, &next, TagSize + ArrayDescSize + num * 4, 16);

        /* Cmds */
        write_i32_le(out, tag);
        assert((next % 16) == 8);
        img.cmds = next;
        num = m->nofCmds;
        arrHdr.len = num;
        write_i32_le(out, arrHdr.a);
        write_i32_le(out, arrHdr.b);
        write_i32_le(out, arrHdr.c);
        write_i32_le(out, arrHdr.len);
        if (num > 0) {
            for (int32_t i = 0; i < num; i++) {
                write_bytes(out, m->cmds[i].name, 32);
                /* Oberon Files.ReadString stores 0-terminated or high-bit; here we stored as C string.
           The object image expects fixed 32 bytes already in CommandDesc.
         */
                write_i32_le(out, m->cmds[i].adr);
            }
        }
        insert_pad(out, &next, TagSize + ArrayDescSize + num * 36, 16);

        /* Ptrs */
        write_i32_le(out, tag);
        assert((next % 16) == 8);
        img.ptrTab = next;
        num = m->nofPtrs;
        arrHdr.len = num;
        write_i32_le(out, arrHdr.a);
        write_i32_le(out, arrHdr.b);
        write_i32_le(out, arrHdr.c);
        write_i32_le(out, arrHdr.len);
        if (num > 0) {
            for (int32_t i = 0; i < num; i++) write_i32_le(out, m->ptrTab[i]);
        }
        insert_pad(out, &next, TagSize + ArrayDescSize + num * 4, 16);

        /* Imports */
        write_i32_le(out, tag);
        assert((next % 16) == 8);
        img.imports = next;
        num = m->nofImps;
        arrHdr.len = num;
        write_i32_le(out, arrHdr.a);
        write_i32_le(out, arrHdr.b);
        write_i32_le(out, arrHdr.c);
        write_i32_le(out, arrHdr.len);
        for (int32_t i = 0; i < num; i++) {
            write_i32_le(out, m->imports[i]->modDescAdr);
        }
        insert_pad(out, &next, TagSize + ArrayDescSize + num * 4, 16);

        /* Data + Const */
        write_i32_le(out, tag);
        assert((next % 16) == 8);
        img.data = next;
        arrHdr.len = m->dataSize + m->conSize;
        write_i32_le(out, arrHdr.a);
        write_i32_le(out, arrHdr.b);
        write_i32_le(out, arrHdr.c);
        write_i32_le(out, arrHdr.len);
        write_bytes(out, m->data, (size_t)(m->dataSize + m->conSize));
        insert_pad(out, &next, TagSize + ArrayDescSize + m->dataSize + m->conSize, 16);

        /* Code */
        write_i32_le(out, tag);
        assert((next % 16) == 8);
        img.code = next;
        num = m->codeSize;
        arrHdr.len = num;
        write_i32_le(out, arrHdr.a);
        write_i32_le(out, arrHdr.b);
        write_i32_le(out, arrHdr.c);
        write_i32_le(out, arrHdr.len);
        write_bytes(out, m->code, (size_t)num);
        insert_pad(out, &next, TagSize + ArrayDescSize + num, 16);

        /* TDescs (array of tdAdr) */
        write_i32_le(out, tag);
        assert((next % 16) == 8);
        img.tdescs = next;
        num = m->nofTds;
        arrHdr.len = num;
        write_i32_le(out, arrHdr.a);
        write_i32_le(out, arrHdr.b);
        write_i32_le(out, arrHdr.c);
        write_i32_le(out, arrHdr.len);
        for (int32_t i = 0; i < num; i++) write_i32_le(out, m->tdescs[i]->tdAdr);
        insert_pad(out, &next, TagSize + ArrayDescSize + num * 4, 16);

        /* Refs */
        write_i32_le(out, tag);
        assert((next % 16) == 8);
        img.refs = next;
        num = m->refSize;
        arrHdr.len = num;
        write_i32_le(out, arrHdr.a);
        write_i32_le(out, arrHdr.b);
        write_i32_le(out, arrHdr.c);
        write_i32_le(out, arrHdr.len);
        if (num > 0) write_bytes(out, m->refs, (size_t)num);
        insert_pad(out, &next, TagSize + ArrayDescSize + num, 16);

        /* import array (DefMaxImport) */
        write_i32_le(out, tag);
        assert((next % 16) == 8);
        img.import = next;
        img.nofimp = m->nofimp;
        num = DefMaxImport;
        arrHdr.len = num;
        write_i32_le(out, arrHdr.a);
        write_i32_le(out, arrHdr.b);
        write_i32_le(out, arrHdr.c);
        write_i32_le(out, arrHdr.len);
        for (int32_t i = 0; i < num; i++) write_i32_le(out, 0);
        insert_pad(out, &next, TagSize + ArrayDescSize + num * 4, 16);

        /* struct array (DefMaxStruct) */
        write_i32_le(out, tag);
        assert((next % 16) == 8);
        img.strct = next;
        img.nofstrc = m->nofstrc;
        num = DefMaxStruct;
        arrHdr.len = num;
        write_i32_le(out, arrHdr.a);
        write_i32_le(out, arrHdr.b);
        write_i32_le(out, arrHdr.c);
        write_i32_le(out, arrHdr.len);
        for (int32_t i = 0; i < num; i++) write_i32_le(out, 0);
        insert_pad(out, &next, TagSize + ArrayDescSize + num * 4, 16);

        /* reimp array (DefMaxReimp) */
        write_i32_le(out, tag);
        assert((next % 16) == 8);
        img.reimp = next;
        img.nofreimp = m->nofreimp;
        num = DefMaxReimp;
        arrHdr.len = num;
        write_i32_le(out, arrHdr.a);
        write_i32_le(out, arrHdr.b);
        write_i32_le(out, arrHdr.c);
        write_i32_le(out, arrHdr.len);
        for (int32_t i = 0; i < num; i++) write_i32_le(out, 0);
        next += TagSize + ArrayDescSize + num * 4;

        /* export padding + export dump */
        write_bytes(out, padding, (size_t)(m->expPadding + 4));
        next += m->expPadding + 4;
        assert((next % 32) == 0);
        sysfix_warning(expDescSF);
        dump_export(out, &m->exportTree, &next, SysFix[expDescSF].adr | 2);
        img.exportDesc.fp = m->exportTree.fp;
        img.exportDesc.adr = m->exportTree.adr;
        img.exportDesc.nofExp = m->exportTree.nofExp;
        img.exportDesc.dsc = (m->exportTree.nofExp == 0) ? 0 : m->exportTree.dsc[0].Adr;

        /* types */
        next -= 4;
        dump_types(out, m, &next);

        /* module descriptor */
        assert((next % Boundary) == 28);
        assert(next == m->modDescAdr - 4);
        sysfix_warning(modDescSF);
        write_i32_le(out, SysFix[modDescSF].adr);

        /* Fill remaining DumpModuleDesc fields (addresses) */
        img.entries = img.entries;
        img.cmds = img.cmds;
        img.ptrTab = img.ptrTab;
        img.tdescs = img.tdescs;
        img.imports = img.imports;
        img.data = img.data;
        img.code = img.code;
        img.refs = img.refs;
        img.publics = m->publics;
        img.privates = m->privates;
        img.term = 0;

        /* Write DumpModuleDesc bytes */
        write_bytes(out, &img, sizeof(img));
        write_bytes(out, padding, (size_t)mDescPadSize);

        next += moduleDescSize;

        m = m->link;
    }
}


static void build_image(const char *fileName, int32_t entryPoint, int32_t base, bool multiboot, bool enable_stack) {
    sysfix_warning(modDescSF);
    sysfix_warning(listSF);

    log_puts("Building image : ");
    log_puts(fileName); log_puts("  "); log_ln();
    log_hex(base); log_puts(" image start, 28+32 bytes for alignment and header"); log_ln(); log_ln();

    FILE *out = fopen(fileName, "wb+");
    if (!out) {
        log_close();
        fprintf(stderr, "bootlinker: failed to create %s: %s\n", fileName, strerror(errno));
        exit(1);
    }

    /* initial header padding */
    write_bytes(out, padding, 28 + 32);

    dump_modules(out);

    int32_t ep = entryPoint;
    int32_t stack_size = enable_stack ? 8192 : 0;
    dump_init_calls(out, &ep, stack_size, base, multiboot);

    int32_t size = (int32_t)tell_abs(out);

    if (multiboot && arch->PatchMultibootHeader(out, base, ep, size)) {
        /* Multiboot header written (i386) */
    } else {
        /* Standard Native Oberon header (always for non-i386, or when --multiboot not set) */
        patch_header(out, base, ep, size);
    }
    
    fclose(out);

    /* Log sysfix summary */
    log_puts("new is "); log_puts(SysFix[newSF].module); log_puts("."); log_puts(SysFix[newSF].command); log_hex(SysFix[newSF].adr); log_ln();
    log_puts("sysnew is "); log_puts(SysFix[sysnewSF].module); log_puts("."); log_puts(SysFix[sysnewSF].command); log_hex(SysFix[sysnewSF].adr); log_ln();
    log_puts("newarr is "); log_puts(SysFix[newarrSF].module); log_puts("."); log_puts(SysFix[newarrSF].command); log_hex(SysFix[newarrSF].adr); log_ln();
    log_puts("list is "); log_puts(SysFix[listSF].module); log_puts("."); log_puts(SysFix[listSF].command); log_hex(SysFix[listSF].adr); log_ln();
    log_puts("modDesc is "); log_puts(SysFix[modDescSF].module); log_puts("."); log_puts(SysFix[modDescSF].command); log_hex(SysFix[modDescSF].adr); log_ln();
    log_puts("expDesc is "); log_puts(SysFix[expDescSF].module); log_puts("."); log_puts(SysFix[expDescSF].command); log_hex(SysFix[expDescSF].adr); log_ln();
}

/* ------------------------------------------------------------ */
/* LoadModule / Load */

static void load_module_body(FILE *f, Module *m, int32_t *base) {
    int32_t symSize = read_num(f);
    if (symSize < 0)
        halt_msg("symSize negative");
    if (fseek(f, symSize, SEEK_CUR) != 0)
        halt_msg("failed to skip sym section");

    int16_t nofDataLinks = 0;
    int16_t nofLinks = 0;

    read_header(f, m, &nofDataLinks, &nofLinks);
    read_entry(f, m);
    read_cmd(f, m);
    read_ptr(f, m);
    read_import(f, m);

    DataLinkEntry *dataLinks = read_data_links(f, m, nofDataLinks);
    LinkEntry *links = read_links(f, m, nofLinks);

    read_data_const(f, m);
    read_export(f, m);
    read_code(f, m);

    /* compute sizes */
    m->base = *base;
    m->imageSize = 28;
    insert_module_sorted(m);

    m->imageSize += 16 * ((m->nofEntries * 4 + ArrayDescSize + 4 + 15) / 16);
    m->imageSize += 16 * ((m->nofCmds * 36 + TagSize + ArrayDescSize + 15) / 16);
    m->imageSize += 16 * ((m->nofPtrs * 4 + TagSize + ArrayDescSize + 15) / 16);
    m->imageSize += 16 * ((m->nofImps * 4 + TagSize + ArrayDescSize + 15) / 16);

    m->sb = m->base + m->imageSize + ArrayDescSize + m->dataSize;
    m->imageSize += ((TagSize + ArrayDescSize + m->dataSize + m->conSize + 15) / 16) * 16;

    m->codeBase = m->base + m->imageSize + ArrayDescSize;
    m->imageSize += ((TagSize + ArrayDescSize + m->codeSize + 15) / 16) * 16;

    m->imageSize += 16 * ((m->nofTds * 4 + TagSize + ArrayDescSize + 15) / 16);

    m->refBase = m->base + m->imageSize + ArrayDescSize;
    m->imageSize += ((m->refSize + TagSize + ArrayDescSize + 15) / 16) * 16;

    m->imageSize += ((DefMaxImport * 4 + TagSize + ArrayDescSize + 15) / 16) * 16;
    m->imageSize += ((DefMaxStruct * 4 + TagSize + ArrayDescSize + 15) / 16) * 16;
    m->imageSize += DefMaxReimp * 4 + TagSize + ArrayDescSize;

    m->expAdr = align_up(m->base + m->imageSize + 4, Boundary) - 4;
    assert((m->expAdr % 32) == 28);
    m->expPadding = m->expAdr - m->base - m->imageSize;
    m->expSize = 0;
    m->imageSize += m->expPadding;

    assign_export_sizes(&m->exportTree, m);
    m->imageSize += m->expSize;

    /* ReadUse uses size info */
    read_use(f, m, dataLinks);

    /* prepare for types */
    m->typeTableAdr = m->base + m->imageSize;
    m->typeTableSize = 0;
    assert(((m->imageSize + m->base + 4) % Boundary) == 0);

    read_type(f, m);
    m->imageSize += m->typeTableSize;
    assert(((m->imageSize + m->base + 4) % Boundary) == 0);

    read_ref(f, m);
    assert(((m->imageSize + m->base + 4) % Boundary) == 0);

    m->modDescAdr = m->imageSize + m->base + 4;
    m->imageSize += moduleDescSize;

    if (res == done) {
        for (int32_t i = newSF; i <= copyarraySF; i++) {
            if (strcmp(SysFix[i].module, m->name) == 0 && SysFix[i].command[0]) {
                SysFix[i].adr = m->codeBase + find_adr(m, SysFix[i].command, Proc);
            }
        }
        if (strcmp(SysFix[CurProcSF].module, m->name) == 0 && SysFix[CurProcSF].command[0]) {
            SysFix[CurProcSF].adr = m->sb + find_adr(m, SysFix[CurProcSF].command, Var);
        }

        if (strcmp(SysFix[listSF].module, m->name) == 0 && SysFix[listSF].command[0]) {
            int32_t t = find_adr(m, SysFix[listSF].command, Var);
            SysFix[listSF].adr = m->sb + t;
            /* Store module+offset for deferred fixup in dump_modules */
            listSF_module = m;
            listSF_offset = t;
            /* write pointer to current objectList modDesc (will be overwritten in dump_modules) */
            put_dword(m->data + m->dataSize, t, objectList ? objectList->modDescAdr : 0);
        }

        fix_entry(m);
        fix_cmd(m);
        fix_ptr(m);
        fix_data_links(m, dataLinks);
        fixup_links(m, links, nofLinks, dataLinks);

        /* SELF pointer at beginning of constants */
        put_dword(m->data + m->dataSize, 0, m->modDescAdr);

        init_types(m);
        m->init = true;
        add_init_point(m->codeBase, m);

        *base = *base + m->imageSize;
    } else {
        halt_msg("LoadModule failed");
    }

    /* cleanup temporary link tables */
    if (dataLinks) {
        for (int16_t i = 0; i < nofDataLinks; i++) free(dataLinks[i].offset);
        free(dataLinks);
    }
    free(links);
}

const char *get_extension(const char *s) {
    const char *last_dot = NULL;
    const char *last_sep = NULL;
    for (const char *p = s; *p; ++p) {
        if (*p == '/' || *p == '\\') last_sep = p;
        else if (*p == '.') last_dot = p;
    }
    return (last_dot && (!last_sep || last_dot > last_sep)) ? last_dot : NULL;
}

static void load_module(Module **m_out, const char *name, int32_t *base) {
    Module *m = find_module(name);
    if (!m) {
        char fname[1024];
        if( get_extension(name) == NULL && strchr(name,'/') == NULL && strchr(name, '\\') == NULL )
        {
            if( modulePath )
            {
                const int pathLen = strlen(modulePath);
                const int nameLen = strlen(name);
                if( pathLen + 2 + nameLen + strlen(extension) > sizeof(fname) )
                    halt_msg("path + module name + extension too long");
                strcpy(fname, modulePath);
                char* str = fname + pathLen;
                if( *str != '/' && str != '\\' )
                    (*str++) = '/';
                strcpy(str, name);
                str += nameLen;
                strcpy(str, extension);
                log_puts("module "); log_puts(name); log_puts(" in file ");
                log_puts(fname); log_ln();
            }else
                str_concat(name, extension, fname, sizeof(fname));
        }else
            halt_msg("expecting module names, not file paths");

        FILE *f = fopen(fname, "rb");
        if (!f) {
            err_msg(fileNotFound, name);
            *m_out = NULL;
            return;
        }

        uint8_t tag = read_u8(f);
        if (tag != 0xBB) {
            fclose(f);
            err_msg(invalidObjFile, name);
            *m_out = NULL;
            return;
        }

        m = (Module *)calloc(1, sizeof(Module));
        if (!m)
            halt_msg("out of memory (Module)");
        m->import = (int32_t *)calloc(DefMaxImport, sizeof(int32_t));
        m->strct = (int32_t *)calloc(DefMaxStruct, sizeof(int32_t));
        m->reimp = (int32_t *)calloc(DefMaxReimp, sizeof(int32_t));
        m->nofImps = -1;

        uint8_t ver = read_u8(f);
        if (ver != OFVersion) {
            fclose(f);
            err_msg(invalidObjFile, name);
            *m_out = NULL;
            return;
        }

        load_module_body(f, m, base);
        fclose(f);
    } else {
        if (!m->init) {
            err_msg(cyclicImport, name);
            *m_out = NULL;
            return;
        }
    }

    *m_out = m;
}

/* ------------------------------------------------------------ */
/* CLI */

typedef struct {
    const char *output;
    int32_t base;
    const char *log;
    const char *obj_suffix;
    const char *command;
    const char **modules;
    int module_count;
    const char *sysfix_overrides[MaxSF];
    int multiboot;
    int enable_stack;
} Options;

static int sysfix_index_by_name(const char *name) {
    for (int i = 0; i < MaxSF; i++) {
        if (SysFix[i].name[0] && strcmp(SysFix[i].name, name) == 0) return i;
    }
    return -1;
}

static void apply_sysfix_overrides(const Options *opt) {
    for (int i = 0; i < MaxSF; i++) {
        const char *ov = opt->sysfix_overrides[i];
        if (!ov)
            continue;
        char mod[64], proc[64];
        extract_names(ov, mod, sizeof(mod), proc, sizeof(proc));
        memset(SysFix[i].module, 0, sizeof(SysFix[i].module));
        memcpy(SysFix[i].module, mod, sizeof(SysFix[i].module) - 1);
        memset(SysFix[i].command, 0, sizeof(SysFix[i].command));
        memcpy(SysFix[i].command, proc, sizeof(SysFix[i].command) - 1);
    }
}

static void usage(FILE *out) {
    fprintf(out,
            "usage: multibootlinker [options] <Module1> <Module2> ...\n"
            "\n"
            "Options:\n"
            "  --arch <target>              Target architecture: i386, arm32, rv32 (default: i386)\n"
            "  -o <output>                  Name of the output file (default: image.bin)\n"
            "  --path <path>                Path where the object files of the listed modules are (default: current directory)\n"
            "  --base <hex>                 The base address (default: 1MB in case of multiboot)\n"
            "  --obj-suffix <suffix>        Object file suffix (default: .Obj)\n"
            "  --log <path>                 Log path (default: <output>.Link)\n"
            "  --command <Module.Proc>      Extra init-call point (like /command)\n"
            "  --multiboot                  Enable boot info passing (pushes boot-info register;\n"
            "                                 Multiboot header on i386, device tree on arm32/rv32)\n"
            "  --enable-stack               Reserve and initialize the stack\n"
            "  --ram-size <bytes>           RAM size hint for image header (arm32/rv32)\n"
            "  --autofix                    Prepopulate sysfix targets from Kernel module\n"
            "  --sysfix <name>=<Mod.Proc>   Override sysfix target (e.g. new=Kernel.NewRec)\n"
            "  --trace / --no-trace         Enable/disable Trace logging\n"
            "  --trace-more                 Enable TraceMore logging\n");
}

static bool parse_hex_i32(const char *s, int32_t *out) {
    if (!s || !*s) return false;
    errno = 0;
    char *end = NULL;
    long v = strtol(s, &end, 16);
    if (errno != 0 || !end || *end != 0)
        return false;
    *out = (int32_t)v;
    return true;
}

static Options parse_args(int argc, char **argv) {
    Options opt;
    memset(&opt, 0, sizeof(opt));
    opt.base = -1;

    /* allocate module array */
    const char **mods = (const char **)calloc((size_t)argc, sizeof(const char *));
    int modCount = 0;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];

        if (strcmp(a, "--arch") == 0 && i + 1 < argc) {
            const char *name = argv[++i];
            if (strcmp(name, "i386") == 0)
                arch = &arch_i386;
            else if (strcmp(name, "arm32") == 0 )
                arch = &arch_arm32;
            else if (strcmp(name, "rv32") == 0)
                arch = &arch_rv32;
            else {
                fprintf(stderr, "Error: unknown architecture '%s'\n", name);
                fprintf(stderr, "       supported: i386, arm32, rv32\n");
                exit(2);
            }
        } else if (strcmp(a, "-o") == 0 && i + 1 < argc) {
            opt.output = argv[++i];
        } else if (strcmp(a, "--base") == 0 && i + 1 < argc) {
            if (!parse_hex_i32(argv[++i], &opt.base))
                halt_msg("invalid --base");
        } else if (strcmp(a, "--log") == 0 && i + 1 < argc) {
            opt.log = argv[++i];
        } else if (strcmp(a, "--path") == 0 && i + 1 < argc) {
            modulePath = argv[++i];
        } else if (strcmp(a, "--obj-suffix") == 0 && i + 1 < argc) {
            opt.obj_suffix = argv[++i];
        } else if (strcmp(a, "--command") == 0 && i + 1 < argc) {
            opt.command = argv[++i];
        } else if (strcmp(a, "--multiboot") == 0) {
            opt.multiboot = true;
        } else if (strcmp(a, "--enable-stack") == 0) {
            opt.enable_stack = true;
        } else if (strcmp(a, "--ram-size") == 0 && i + 1 < argc) {
            errno = 0;
            char *end = NULL;
            long v = strtol(argv[++i], &end, 0);
            if (errno != 0 || !end || *end != 0 || v <= 0)
                halt_msg("invalid --ram-size");
            ramSize = (int32_t)v;
        } else if (strcmp(a, "--sysfix") == 0 && i + 1 < argc) {
            const char *kv = argv[++i];
            const char *eq = strchr(kv, '=');
            if (!eq)
                halt_msg("--sysfix expects name=Module.Proc");
            char key[64];
            size_t klen = (size_t)(eq - kv);
            if (klen >= sizeof(key))
                klen = sizeof(key) - 1;
            memcpy(key, kv, klen);
            key[klen] = 0;
            int idx = sysfix_index_by_name(key);
            if (idx < 0)
                halt_msg("unknown sysfix name");
            opt.sysfix_overrides[idx] = eq + 1;
        } else if (strcmp(a, "--no-refs") == 0) {
            includeRefs = false;
        } else if (strcmp(a, "--trace") == 0) {
            Trace = true;
        } else if (strcmp(a, "--no-trace") == 0) {
            Trace = false;
        } else if (strcmp(a, "--trace-more") == 0) {
            TraceMore = true;
        } else if (strcmp(a, "-h") == 0 || strcmp(a, "--help") == 0) {
            usage(stdout);
            exit(0);
        } else if (a[0] == '-') {
            usage(stderr);
            halt_msg("unknown option");
        } else {
            mods[modCount++] = a;
        }
    }

    if( opt.multiboot && opt.base < 0 )
        opt.base = 0x100000; // default to 1MB
    else if (opt.base < 0)
        fprintf(stderr, "Error: --base is required when not using --multiboot\n");

    if( opt.output == 0 )
        opt.output = "image.bin";

    opt.modules = mods;
    opt.module_count = modCount;

    return opt;
}

/* ------------------------------------------------------------ */
/* Main */

int main(int argc, char **argv) {
    /* Endianness check: DumpModuleDesc is written as raw bytes, must be LE */
    {
        uint32_t endian_test = 1;
        if (*(uint8_t *)&endian_test != 1) {
            fprintf(stderr, "multibootlinker: this tool requires a little-endian host\n");
            return 1;
        }
    }

    bool autofix = false;
    for (int i = 1; i < argc; i++ )
        if (strcmp(argv[i],"--autofix") == 0)
        {
            autofix = true;
            break;
        }
    initialise(autofix);

    Options opt = parse_args(argc, argv);
    if (!opt.output || opt.base < 0 || opt.module_count == 0) {
        usage(stderr);
        return 2;
    }

    if (opt.obj_suffix) {
        snprintf(extension, sizeof(extension), "%s", opt.obj_suffix);
    }

    if ((opt.base % PageSize) != 0) {
        halt_msg("Image base must be a multiple of machine memory page size");
    }

    if (opt.multiboot && !opt.enable_stack) {
        fprintf(stderr, "Error: --multiboot requires --enable-stack\n");
        return 2;
    }

    apply_sysfix_overrides(&opt);

    /* Open log early if requested */
    if (opt.log) {
        log_open(opt.log);
    } else {
        /* Open default log file if none was specified */
        log_stdout();
    }

    imageBase = opt.base;
    imageSize = 0;

    int32_t base = imageBase + 28 + 32;

    /* load modules in the provided order */
    for (int i = 0; i < opt.module_count; i++) {
        Module *m = NULL;
        load_module(&m, opt.modules[i], &base);
        if (res != done) {
            log_close();
            return 1;
        }
    }

    /* optional extra init-call (/command equivalent) */
    if (opt.command) {
        char mod[64], proc[64];
        extract_names(opt.command, mod, sizeof(mod), proc, sizeof(proc));
        Module *object = find_module(mod);
        if (!object)
            halt_msg("Module in --command not included in image");
        int32_t i = 0;
        while (i < object->nofCmds && strcmp(object->cmds[i].name, proc) != 0) i++;
        if (i < object->nofCmds) {
            add_init_point(object->cmds[i].adr, NULL);
        } else {
            halt_msg("Procedure in --command not found");
        }
    }

    /* imageSize tracks total image extent relative to imageBase.
     * load_module_body updates *base but not the global imageSize,
     * so we must sync it here from the running base pointer. */
    imageSize = base - imageBase;

    int32_t stack_size = 0;
    if (opt.enable_stack) {
        stack_size = 8192; // 8 KB stack, TODO: consider this as an additional option
        imageSize += stack_size;
    }

    /* Build the output image */
    build_image(opt.output, base, imageBase, opt.multiboot, opt.enable_stack);

    log_close();
    free((void *)opt.modules);
    return 0;
}
