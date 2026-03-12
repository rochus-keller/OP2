/*
 * Oberon Object File Dump Tool
 * Reads an Oberon .Obj file and dumps its contents in text format,
 * including ARM disassembly of the code section.
 *
 * Object file format (from OPL.Mod):
 *   OFtag(0xBB) OFversion(0xAF) sfsize(num) symdata refsize(4)
 *   Header Entries Commands Pointers Imports VarConsLinks Links
 *   Data Export Code Use Types
 *
 * Enhancements over original:
 *   - Fixed decoder ordering: specific instruction patterns checked before
 *     generic Data Processing (BX, MUL, halfword, etc. no longer shadowed)
 *   - Added: SDIV, UDIV, UDF, NOP/hints, MOVW, MOVT, LDREX, STREX,
 *     BLX immediate, DMB/DSB/ISB, PLD, CDP, LDC/STC
 *   - Added: VFP instruction decoding (VLDR, VSTR, VADD, VSUB, VMUL,
 *     VDIV, VABS, VNEG, VSQRT, VCMP, VMOV, VMRS, VCVT, VCVTM)
 *   - Hex representation in offset lists (Entries, Pointers, Links, etc.)
 *   - Procedure boundary markers in code disassembly using entry table
 *   - Instruction statistics summary
 *   - Large immediates shown in hex alongside decimal
 *
 * Copyright 2025 Rochus Keller <mailto:me@rochus-keller.ch>
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* Object file tags */
#define OFTAG    0xBB
#define OFNATIVE 0xAF
#define OFNEW    0xB0

#define EntryTag      0x82
#define CommandTag    0x83
#define PointerTag    0x84
#define ImportTag     0x85
#define LinkTag       0x86
#define DataTag       0x87
#define ExportTag     0x88
#define CodeTag       0x89
#define UseTag        0x8A
#define TypeTag       0x8B
#define RefTag        0x8C
#define VarConsLinkTag 0x8D

#define EUEnd    0
#define EURecord 1
#define EUProcFlag 0x4000

#define MAX_ENTRIES 512
#define MAX_PROCS  1024

static FILE *f;
static int verbose = 0;

/* Entry table for procedure boundary markers */
static int16_t entry_offsets[MAX_ENTRIES];
static int nof_entries_stored = 0;

/* Procedure name table (populated from Ref section) */
typedef struct {
    int32_t offset;          /* code offset (from OutRefPoint) */
    char    name[256];       /* procedure name */
} ProcEntry;
static ProcEntry proc_table[MAX_PROCS];
static int nof_procs = 0;

/* Instruction statistics */
static int stat_dp = 0, stat_branch = 0, stat_load = 0, stat_store = 0;
static int stat_ldm_stm = 0, stat_mul = 0, stat_vfp = 0, stat_other = 0;

/* ---- File reading primitives ---- */

static int read_byte(void) {
    int ch = fgetc(f);
    if (ch == EOF) {
        fprintf(stderr, "Unexpected end of file\n");
        exit(1);
    }
    return ch;
}

static int16_t read_int16(void) {
    int lo = read_byte();
    int hi = read_byte();
    return (int16_t)(lo | (hi << 8));
}

static uint16_t read_uint16(void) {
    int lo = read_byte();
    int hi = read_byte();
    return (uint16_t)(lo | (hi << 8));
}

static int32_t read_int32(void) {
    int b0 = read_byte();
    int b1 = read_byte();
    int b2 = read_byte();
    int b3 = read_byte();
    return (int32_t)(b0 | (b1 << 8) | (b2 << 16) | (b3 << 24));
}

static int32_t read_num(void) {
    int32_t x = 0;
    int shift = 0;
    int b;
    do {
        b = read_byte();
        x |= (int32_t)(b & 0x7F) << shift;
        shift += 7;
    } while (b & 0x80);
    if ((shift < 32) && (b & 0x40))
        x |= -(1 << shift);
    return x;
}

static void read_string(char *buf, int maxlen) {
    int i = 0;
    int ch;
    do {
        ch = read_byte();
        if (i < maxlen - 1) buf[i++] = (char)ch;
    } while (ch != 0);
    buf[i] = 0;
}

static void expect_tag(int expected) {
    int tag = read_byte();
    if (tag != expected) {
        fprintf(stderr, "Expected tag 0x%02X, got 0x%02X\n", expected, tag);
        exit(1);
    }
}

/* Check if an offset is an entry point; returns entry index or -1 */
static int find_entry(int offset) {
    for (int i = 0; i < nof_entries_stored; i++) {
        if (entry_offsets[i] == offset) return i;
    }
    return -1;
}

/* Find procedure name for a code offset; returns NULL if not found */
static const char *find_proc_name(int offset) {
    for (int i = 0; i < nof_procs; i++) {
        if (proc_table[i].offset == offset) return proc_table[i].name;
    }
    return NULL;
}

/* ---- Ref section parser ----
 *
 * Parse the Ref section to extract procedure names and code offsets.
 * Ref data is a sequence of procedure blocks:
 *
 * NewRef format (0xF9 marker):
 *   0xF9  offset(num)  nParams(num)  retType(byte)  level(byte)  slFlag(byte)
 *   name(string)  { varRef }*
 *
 * OldRef format (0xF8 marker):
 *   0xF8  offset(num)
 *   name(string)  { varRef }*
 *
 * Module body uses: RefTag(0x8C) 0xF8 0 name="$$" { varRef }*
 *
 * Variable refs (varRef): byte(1 or 3) [type info] offset(num) name(string)
 */
static void parse_ref_data(const uint8_t *ref, int refSize) {
    int pos = 0;
    nof_procs = 0;

    /* Helper: read a num from ref buffer */
    #define REF_NUM(result) do { \
        int32_t _x = 0; int _shift = 0; int _b; \
        do { \
            if (pos >= refSize) goto done; \
            _b = ref[pos++]; \
            _x |= (int32_t)(_b & 0x7F) << _shift; \
            _shift += 7; \
        } while (_b & 0x80); \
        if ((_shift < 32) && (_b & 0x40)) _x |= -(1 << _shift); \
        (result) = _x; \
    } while(0)

    while (pos < refSize) {
        int marker = ref[pos];
        if (marker == 0x8C) {
            /* RefTag - module body sentinel */
            pos++;
            if (pos >= refSize) break;
            marker = ref[pos];
        }
        if (marker == 0xF9) {
            /* NewRef format */
            pos++;
            int32_t offset; REF_NUM(offset);
            int32_t nParams; REF_NUM(nParams);
            if (pos >= refSize) break;
            pos++; /* retType byte */
            if (pos >= refSize) break;
            pos++; /* level byte */
            if (pos >= refSize) break;
            pos++; /* slFlag byte */
            /* Read name (zero-terminated string) */
            char name[256];
            int ni = 0;
            while (pos < refSize) {
                char ch = (char)ref[pos++];
                if (ni < 255) name[ni++] = ch;
                if (ch == 0) break;
            }
            name[ni] = 0;
            /* Store in proc table */
            if (nof_procs < MAX_PROCS && name[0] != 0) {
                proc_table[nof_procs].offset = offset;
                strncpy(proc_table[nof_procs].name, name, 255);
                proc_table[nof_procs].name[255] = 0;
                nof_procs++;
            }
            /* Skip variable refs: each starts with byte 1 or 3 */
            while (pos < refSize) {
                int vb = ref[pos];
                if (vb != 1 && vb != 3) break;
                pos++; /* mode byte */
                if (pos >= refSize) break;
                int tb = ref[pos++]; /* type byte */
                if (tb & 0x80) {
                    /* array type: skip element count num */
                    int32_t dummy; REF_NUM(dummy);
                } else if (tb >= 0x10) {
                    /* record/pointer type: skip tdadr num */
                    int32_t dummy; REF_NUM(dummy);
                }
                /* skip offset num */
                { int32_t dummy; REF_NUM(dummy); }
                /* skip name string */
                while (pos < refSize && ref[pos] != 0) pos++;
                if (pos < refSize) pos++; /* skip null terminator */
            }
        } else if (marker == 0xF8) {
            /* OldRef format */
            pos++;
            int32_t offset; REF_NUM(offset);
            /* Read name */
            char name[256];
            int ni = 0;
            while (pos < refSize) {
                char ch = (char)ref[pos++];
                if (ni < 255) name[ni++] = ch;
                if (ch == 0) break;
            }
            name[ni] = 0;
            if (nof_procs < MAX_PROCS && name[0] != 0) {
                proc_table[nof_procs].offset = offset;
                strncpy(proc_table[nof_procs].name, name, 255);
                proc_table[nof_procs].name[255] = 0;
                nof_procs++;
            }
            /* Skip variable refs */
            while (pos < refSize) {
                int vb = ref[pos];
                if (vb != 1 && vb != 3) break;
                pos++;
                if (pos >= refSize) break;
                int tb = ref[pos++];
                if (tb & 0x80) {
                    int32_t dummy; REF_NUM(dummy);
                }
                { int32_t dummy; REF_NUM(dummy); }
                while (pos < refSize && ref[pos] != 0) pos++;
                if (pos < refSize) pos++;
            }
        } else {
            /* Unknown marker - stop parsing */
            break;
        }
    }
done:;
    #undef REF_NUM
}

/* ---- Export section recursive parser ----
 *
 * The Export section format (from OPL.Mod Export/ExportRecord):
 *
 *   ExportTag nofExp(int16)
 *   -- exactly nofExp exported objects, each:
 *     fp(num) adr(num) [ExportRecord if Typ/Var with Record type]
 *   -- then items from tree traversal that are EURecord or fp+adr pairs
 *   EUEnd(byte 0)
 *
 * ExportRecord (recursive):
 *   EURecord(byte 1) link(num)
 *   IF link < 0 THEN  -- back-reference to already-seen record type; done
 *   ELSE              -- new record definition:
 *     nofld(int16)    -- count of items in this record scope
 *     { item }*       -- items until EUEnd, each is:
 *                        EURecord -> nested ExportRecord (recursive)
 *                        num      -> field/method fingerprint
 *     EUEnd(byte 0)
 *   END
 *
 * The top-level loop reads num values. Value 0 = EUEnd (terminator).
 * Value 1 = EURecord (start of record type info). Any other value is
 * a fingerprint (fp) followed by an address (num). After fp+adr, if
 * the next byte is EURecord, a record type description follows.
 */
static void skip_export_record(int depth);

/* Skip an ExportRecord body after EURecord byte has been consumed */
static void skip_export_record(int depth) {
    int32_t link = read_num();
    if (verbose) {
        for (int i = 0; i < depth; i++) printf("  ");
        printf("  EURecord link=%d\n", link);
    }
    if (link < 0) {
        /* Back-reference to already-seen record type; no body */
        return;
    }
    /* New record: read nofld(int16), then items until EUEnd.
     * Items inside a record scope are a mix of:
     *   - EURecord(1) -> nested ExportRecord
     *   - num values (field/method fps), possibly followed by EURecord
     *   - EUEnd(0) -> end of this record scope
     */
    int16_t nofld = read_int16();
    if (verbose) {
        for (int i = 0; i < depth; i++) printf("  ");
        printf("  nofld=%d\n", nofld);
    }
    /* Read items until EUEnd */
    for (;;) {
        int32_t val = read_num();
        if (val == EUEnd) break;
        if (val == EURecord) {
            skip_export_record(depth + 1);
        }
        /* else: num value (fp) - just consumed */
    }
}

/* ---- ARM Disassembler ---- */

static const char *arm_cond[16] = {
    "eq", "ne", "cs", "cc", "mi", "pl", "vs", "vc",
    "hi", "ls", "ge", "lt", "gt", "le", "",   "nv"
};

static const char *arm_reg[16] = {
    "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7",
    "r8", "r9", "r10", "r11", "r12", "sp", "lr", "pc"
};

static const char *arm_shift[4] = { "lsl", "lsr", "asr", "ror" };

static const char *arm_dp_op[16] = {
    "and", "eor", "sub", "rsb", "add", "adc", "sbc", "rsc",
    "tst", "teq", "cmp", "cmn", "orr", "mov", "bic", "mvn"
};

static void format_shifter(uint32_t instr, char *buf, int is_imm) {
    if (is_imm) {
        uint32_t imm8 = instr & 0xFF;
        uint32_t rot = ((instr >> 8) & 0xF) * 2;
        uint32_t val;
        if (rot == 0)
            val = imm8;
        else
            val = (imm8 >> rot) | (imm8 << (32 - rot));
        if (val > 255)
            sprintf(buf, "#%u\t; 0x%x", val, val);
        else
            sprintf(buf, "#%u", val);
    } else {
        int rm = instr & 0xF;
        int shift_type = (instr >> 5) & 3;
        int shift_by_reg = (instr >> 4) & 1;
        if (shift_by_reg) {
            int rs = (instr >> 8) & 0xF;
            sprintf(buf, "%s, %s %s", arm_reg[rm], arm_shift[shift_type], arm_reg[rs]);
        } else {
            int shift_amt = (instr >> 7) & 0x1F;
            if (shift_amt == 0 && shift_type == 0)
                sprintf(buf, "%s", arm_reg[rm]);
            else if (shift_amt == 0 && shift_type == 3)
                sprintf(buf, "%s, rrx", arm_reg[rm]);
            else
                sprintf(buf, "%s, %s #%d", arm_reg[rm], arm_shift[shift_type], shift_amt);
        }
    }
}

static void reglist_str(uint32_t reglist, char *buf) {
    int first = 1;
    buf[0] = '{';
    buf[1] = 0;
    for (int i = 0; i < 16; i++) {
        if (reglist & (1 << i)) {
            if (!first) strcat(buf, ", ");
            strcat(buf, arm_reg[i]);
            first = 0;
        }
    }
    strcat(buf, "}");
}

/* VFP register helpers */
static void vfp_dreg_str(char *buf, int reg) { sprintf(buf, "d%d", reg); }
static void vfp_sreg_str(char *buf, int reg) { sprintf(buf, "s%d", reg); }

/* Decode VFP Dd register: for double {D,Vd}, for single {Vd,D} */
static int vfp_d_reg(uint32_t instr, int is_double) {
    int Vd = (instr >> 12) & 0xF;
    int D = (instr >> 22) & 1;
    return is_double ? ((D << 4) | Vd) : ((Vd << 1) | D);
}

static int vfp_n_reg(uint32_t instr, int is_double) {
    int Vn = (instr >> 16) & 0xF;
    int N = (instr >> 7) & 1;
    return is_double ? ((N << 4) | Vn) : ((Vn << 1) | N);
}

static int vfp_m_reg(uint32_t instr, int is_double) {
    int Vm = instr & 0xF;
    int M = (instr >> 5) & 1;
    return is_double ? ((M << 4) | Vm) : ((Vm << 1) | M);
}

static void vfp_reg_str(char *buf, int reg, int is_double) {
    if (is_double) vfp_dreg_str(buf, reg);
    else vfp_sreg_str(buf, reg);
}

/* Format VFP VLDR/VSTR offset */
static void format_vfp_memop(char *buf, const char *op, const char *cond_str,
                              const char *reg_name, const char *rn, int U, int imm8) {
    int offset = imm8 * 4;
    if (offset == 0)
        sprintf(buf, "%s%s\t%s, [%s]", op, cond_str, reg_name, rn);
    else
        sprintf(buf, "%s%s\t%s, [%s, #%s%d]", op, cond_str, reg_name, rn,
                U ? "" : "-", offset);
}

static void disasm_arm(uint32_t addr, uint32_t instr, char *buf) {
    int cond = (instr >> 28) & 0xF;

    /* ================================================================
     * UNCONDITIONAL instructions (cond == 0xF)
     * ================================================================ */
    if (cond == 0xF) {
        int bits27_25 = (instr >> 25) & 7;

        /* BLX immediate: 1111 101H imm24 */
        if (bits27_25 == 5) {
            int H = (instr >> 24) & 1;
            int32_t offset = ((int32_t)(instr << 8) >> 6) | (H << 1);
            uint32_t target = addr + 8 + offset;
            sprintf(buf, "blx\t0x%08x", target);
            stat_branch++;
            return;
        }

        /* Memory barriers: DMB, DSB, ISB  (0xF57FF0xx) */
        if ((instr & 0xFFFFFFF0) == 0xF57FF050) {
            int opt = instr & 0xF;
            const char *optname = "";
            switch (opt) {
            case 0xF: optname = "sy"; break;
            case 0xE: optname = "st"; break;
            case 0xB: optname = "ish"; break;
            case 0xA: optname = "ishst"; break;
            case 0x7: optname = "nsh"; break;
            case 0x6: optname = "nshst"; break;
            case 0x3: optname = "osh"; break;
            case 0x2: optname = "oshst"; break;
            default:  optname = NULL; break;
            }
            if (optname) sprintf(buf, "dmb\t%s", optname);
            else sprintf(buf, "dmb\t#%d", opt);
            stat_other++;
            return;
        }
        if ((instr & 0xFFFFFFF0) == 0xF57FF040) {
            int opt = instr & 0xF;
            sprintf(buf, "dsb\t#%d", opt);
            stat_other++;
            return;
        }
        if ((instr & 0xFFFFFFF0) == 0xF57FF060) {
            sprintf(buf, "isb");
            stat_other++;
            return;
        }

        /* PLD: 1111 0101 x1x1 Rn 1111 imm12 */
        if ((instr & 0xFD70F000) == 0xF550F000) {
            int U = (instr >> 23) & 1;
            int rn = (instr >> 16) & 0xF;
            int I = (instr >> 25) & 1;
            if (!I) {
                int imm12 = instr & 0xFFF;
                if (imm12 == 0)
                    sprintf(buf, "pld\t[%s]", arm_reg[rn]);
                else
                    sprintf(buf, "pld\t[%s, #%s%d]", arm_reg[rn], U ? "" : "-", imm12);
            } else {
                sprintf(buf, "pld\t[%s, ...]", arm_reg[rn]);
            }
            stat_other++;
            return;
        }

        /* CPSID/CPSIE: 1111 0001 0000 ... */
        if ((instr & 0xFFF00020) == 0xF1000000) {
            int imod = (instr >> 18) & 3;
            int A = (instr >> 8) & 1;
            int I = (instr >> 7) & 1;
            int F = (instr >> 6) & 1;
            char flags[4] = {0};
            int fi = 0;
            if (A) flags[fi++] = 'a';
            if (I) flags[fi++] = 'i';
            if (F) flags[fi++] = 'f';
            sprintf(buf, "cps%s\t%s", (imod == 3) ? "id" : "ie", flags);
            stat_other++;
            return;
        }

        /* VCVTM/VCVTA/VCVTN/VCVTP (ARMv8 unconditional VFP) */
        /* Pattern: 1111 1110 1x11 1111 Vd 101s 01M0 Vm */
        if ((instr & 0xFEB80E50) == 0xFEB80A40) {
            int is_double = ((instr >> 8) & 1);
            int D_bit = (instr >> 22) & 1;
            int Vd_bits = (instr >> 12) & 0xF;
            /* Destination is always a single (S32/U32) */
            int Sd = (Vd_bits << 1) | D_bit;
            int Sm_or_Dm;
            char src_name[8];
            if (is_double) {
                int Vm = instr & 0xF;
                int M = (instr >> 5) & 1;
                Sm_or_Dm = (M << 4) | Vm;
                vfp_dreg_str(src_name, Sm_or_Dm);
            } else {
                int Vm = instr & 0xF;
                int M = (instr >> 5) & 1;
                Sm_or_Dm = (Vm << 1) | M;
                vfp_sreg_str(src_name, Sm_or_Dm);
            }
            char dst_name[8];
            vfp_sreg_str(dst_name, Sd);
            /* Decode rounding mode from bits[17:16] */
            int rm = (instr >> 16) & 3;
            const char *rmname;
            switch (rm) {
            case 0: rmname = "vcvta"; break;
            case 1: rmname = "vcvtn"; break;
            case 2: rmname = "vcvtp"; break;
            case 3: rmname = "vcvtm"; break;
            default: rmname = "vcvt?"; break;
            }
            /* bit[7] = op: 0=unsigned, 1=signed */
            int is_signed = (instr >> 7) & 1;
            sprintf(buf, "%s.%s.%s\t%s, %s", rmname,
                    is_signed ? "s32" : "u32",
                    is_double ? "f64" : "f32",
                    dst_name, src_name);
            stat_vfp++;
            return;
        }

        sprintf(buf, ".word\t0x%08x\t; unconditional", instr);
        stat_other++;
        return;
    }

    /* ================================================================
     * CONDITIONAL instructions (cond != 0xF)
     * ================================================================ */

    int bits27_25 = (instr >> 25) & 7;
    int bits27_24 = (instr >> 24) & 0xF;

    /* ---- SVC/SWI: bits[27:24] = 1111 ---- */
    if (bits27_24 == 0xF) {
        uint32_t svc_num = instr & 0x00FFFFFF;
        if (svc_num > 0xFFFF)
            sprintf(buf, "svc%s\t#%u\t; 0x%x", arm_cond[cond], svc_num, svc_num);
        else
            sprintf(buf, "svc%s\t#%u", arm_cond[cond], svc_num);
        stat_other++;
        return;
    }

    /* ---- Branch B/BL: bits[27:25] = 101 ---- */
    if (bits27_25 == 5) {
        int L = (instr >> 24) & 1;
        int32_t offset = (int32_t)(instr << 8) >> 6;
        uint32_t target = addr + 8 + offset;
        sprintf(buf, "b%s%s\t0x%08x", L ? "l" : "", arm_cond[cond], target);
        stat_branch++;
        return;
    }

    /* ---- Coprocessor register transfer: MCR/MRC / VFP VMOV/VMRS ---- */
    /* bits[27:24] = 1110, bit[4] = 1 */
    if ((bits27_24 == 0xE) && ((instr & 0x10) == 0x10)) {
        int cpnum = (instr >> 8) & 0xF;
        int L = (instr >> 20) & 1;
        int rd = (instr >> 12) & 0xF;

        if (cpnum == 10 || cpnum == 11) {
            /* VFP single register transfer */
            int opc1 = (instr >> 21) & 7;

            /* VMRS APSR_nzcv, FPSCR: opc1=111, L=1 */
            if (opc1 == 7 && L == 1) {
                if (rd == 15)
                    sprintf(buf, "vmrs%s\tAPSR_nzcv, fpscr", arm_cond[cond]);
                else
                    sprintf(buf, "vmrs%s\t%s, fpscr", arm_cond[cond], arm_reg[rd]);
                stat_vfp++;
                return;
            }
            /* VMSR FPSCR, Rt: opc1=111, L=0 */
            if (opc1 == 7 && L == 0) {
                sprintf(buf, "vmsr%s\tfpscr, %s", arm_cond[cond], arm_reg[rd]);
                stat_vfp++;
                return;
            }
            /* VMOV between ARM core reg and VFP single */
            if (opc1 == 0) {
                int Vn = (instr >> 16) & 0xF;
                int N = (instr >> 7) & 1;
                int sreg = (Vn << 1) | N;
                char sname[8];
                vfp_sreg_str(sname, sreg);
                if (L)
                    sprintf(buf, "vmov%s\t%s, %s", arm_cond[cond], arm_reg[rd], sname);
                else
                    sprintf(buf, "vmov%s\t%s, %s", arm_cond[cond], sname, arm_reg[rd]);
                stat_vfp++;
                return;
            }
        }

        /* Generic MCR/MRC */
        {
            int opc1g = (instr >> 21) & 7;
            int crn = (instr >> 16) & 0xF;
            int opc2 = (instr >> 5) & 7;
            int crm = instr & 0xF;
            sprintf(buf, "%s%s\tp%d, %d, %s, c%d, c%d, %d",
                    L ? "mrc" : "mcr", arm_cond[cond], cpnum, opc1g,
                    arm_reg[rd], crn, crm, opc2);
        }
        stat_other++;
        return;
    }

    /* ---- Coprocessor data processing: CDP / VFP data proc ---- */
    /* bits[27:24] = 1110, bit[4] = 0 */
    if ((bits27_24 == 0xE) && ((instr & 0x10) == 0x00)) {
        int cpnum = (instr >> 8) & 0xF;

        if (cpnum == 10 || cpnum == 11) {
            /* VFP data processing */
            int is_double = (cpnum == 11);
            const char *sz = is_double ? ".f64" : ".f32";
            int p = (instr >> 23) & 1;
            int q = (instr >> 21) & 1;
            int r = (instr >> 20) & 1;
            int o = (instr >> 6) & 1;

            int Dd = vfp_d_reg(instr, is_double);
            int Dn = vfp_n_reg(instr, is_double);
            int Dm = vfp_m_reg(instr, is_double);

            char dname[8], nname[8], mname[8];
            vfp_reg_str(dname, Dd, is_double);
            vfp_reg_str(nname, Dn, is_double);
            vfp_reg_str(mname, Dm, is_double);

            if (!p) {
                /* Two-register: index = q*4 + r*2 + o */
                static const char *vfp_two_ops[8] = {
                    "vmla", "vmls", "vnmls", "vnmla",
                    "vmul", "vnmul", "vadd", "vsub"
                };
                int idx = (q << 2) | (r << 1) | o;
                sprintf(buf, "%s%s%s\t%s, %s, %s",
                        vfp_two_ops[idx], arm_cond[cond], sz,
                        dname, nname, mname);
                stat_vfp++;
                return;
            }

            if (p && !q) {
                /* VDIV */
                sprintf(buf, "vdiv%s%s\t%s, %s, %s",
                        arm_cond[cond], sz, dname, nname, mname);
                stat_vfp++;
                return;
            }

            if (p && q) {
                /* Extension register operations */
                int opc2_ext = (instr >> 16) & 0xF;
                int op76 = (instr >> 6) & 3;

                switch (opc2_ext) {
                case 0: /* VMOV reg / VABS */
                    if (op76 == 1) {
                        sprintf(buf, "vmov%s%s\t%s, %s",
                                arm_cond[cond], sz, dname, mname);
                    } else if (op76 == 3) {
                        sprintf(buf, "vabs%s%s\t%s, %s",
                                arm_cond[cond], sz, dname, mname);
                    } else {
                        sprintf(buf, "vfp%s\t; ext op 0x%08x", arm_cond[cond], instr & 0x0FFFFFFF);
                    }
                    stat_vfp++;
                    return;

                case 1: /* VNEG / VSQRT */
                    if (op76 == 1) {
                        sprintf(buf, "vneg%s%s\t%s, %s",
                                arm_cond[cond], sz, dname, mname);
                    } else if (op76 == 3) {
                        sprintf(buf, "vsqrt%s%s\t%s, %s",
                                arm_cond[cond], sz, dname, mname);
                    } else {
                        sprintf(buf, "vfp%s\t; ext op 0x%08x", arm_cond[cond], instr & 0x0FFFFFFF);
                    }
                    stat_vfp++;
                    return;

                case 4: /* VCMP */
                    sprintf(buf, "vcmp%s%s\t%s, %s",
                            arm_cond[cond], sz, dname, mname);
                    stat_vfp++;
                    return;

                case 5: /* VCMP with zero */
                    sprintf(buf, "vcmp%s%s\t%s, #0.0",
                            arm_cond[cond], sz, dname);
                    stat_vfp++;
                    return;

                case 7: {
                    /* VCVT between double and single */
                    if (is_double) {
                        /* VCVT.F32.F64 Sd, Dm: source is double, dest is single */
                        int D = (instr >> 22) & 1;
                        int Vd = (instr >> 12) & 0xF;
                        int Sd = (Vd << 1) | D;
                        char sdname[8];
                        vfp_sreg_str(sdname, Sd);
                        sprintf(buf, "vcvt%s.f32.f64\t%s, %s",
                                arm_cond[cond], sdname, mname);
                    } else {
                        /* VCVT.F64.F32 Dd, Sm: source is single, dest is double */
                        int D = (instr >> 22) & 1;
                        int Vd = (instr >> 12) & 0xF;
                        int Dd_reg = (D << 4) | Vd;
                        char ddname[8];
                        vfp_dreg_str(ddname, Dd_reg);
                        sprintf(buf, "vcvt%s.f64.f32\t%s, %s",
                                arm_cond[cond], ddname, mname);
                    }
                    stat_vfp++;
                    return;
                }

                case 8: {
                    /* VCVT from integer to float */
                    /* bit[7] (o bit): 0=unsigned, 1=signed */
                    int is_signed = (instr >> 7) & 1;
                    /* Source is always single-precision register holding int */
                    int Vm_raw = instr & 0xF;
                    int M_raw = (instr >> 5) & 1;
                    int Sm = (Vm_raw << 1) | M_raw;
                    char smname[8];
                    vfp_sreg_str(smname, Sm);
                    sprintf(buf, "vcvt%s%s.%s\t%s, %s",
                            arm_cond[cond], sz,
                            is_signed ? "s32" : "u32",
                            dname, smname);
                    stat_vfp++;
                    return;
                }

                case 12: case 13: {
                    /* VCVT from float to integer (12=unsigned, 13=signed, round to zero) */
                    int is_signed = (opc2_ext == 13);
                    /* Dest is always single-precision register holding int */
                    int D_bit = (instr >> 22) & 1;
                    int Vd_bits = (instr >> 12) & 0xF;
                    int Sd = (Vd_bits << 1) | D_bit;
                    char sdname[8];
                    vfp_sreg_str(sdname, Sd);
                    sprintf(buf, "vcvt%s.%s%s\t%s, %s",
                            arm_cond[cond],
                            is_signed ? "s32" : "u32",
                            sz,
                            sdname, mname);
                    stat_vfp++;
                    return;
                }

                default:
                    sprintf(buf, "vfp%s\t; ext opc2=%d op=0x%08x", arm_cond[cond], opc2_ext, instr & 0x0FFFFFFF);
                    stat_vfp++;
                    return;
                }
            }

            /* VFP fallback */
            sprintf(buf, "vfp%s\t; op=0x%08x", arm_cond[cond], instr & 0x0FFFFFFF);
            stat_vfp++;
            return;
        }

        /* Generic CDP */
        {
            int opc1 = (instr >> 20) & 0xF;
            int crn = (instr >> 16) & 0xF;
            int crd = (instr >> 12) & 0xF;
            int opc2 = (instr >> 5) & 7;
            int crm = instr & 0xF;
            sprintf(buf, "cdp%s\tp%d, %d, c%d, c%d, c%d, %d",
                    arm_cond[cond], cpnum, opc1, crd, crn, crm, opc2);
        }
        stat_other++;
        return;
    }

    /* ---- Coprocessor load/store: LDC/STC / VLDR/VSTR ---- */
    /* bits[27:25] = 110 */
    if (bits27_25 == 6) {
        int P = (instr >> 24) & 1;
        int U = (instr >> 23) & 1;
        int W = (instr >> 21) & 1;
        int L = (instr >> 20) & 1;
        int rn = (instr >> 16) & 0xF;
        int cpnum = (instr >> 8) & 0xF;
        int imm8 = instr & 0xFF;

        if (cpnum == 10 || cpnum == 11) {
            /* VLDR/VSTR */
            int is_double = (cpnum == 11);
            int Vd = vfp_d_reg(instr, is_double);
            char regname[8];
            vfp_reg_str(regname, Vd, is_double);
            const char *op = L ? "vldr" : "vstr";

            if (P && !W) {
                /* Offset addressing: VLDR/VSTR Fd, [Rn, #imm] */
                format_vfp_memop(buf, op, arm_cond[cond], regname, arm_reg[rn], U, imm8);
            } else if (P && W) {
                /* Pre-indexed */
                int offset = imm8 * 4;
                sprintf(buf, "%s%s\t%s, [%s, #%s%d]!", op, arm_cond[cond],
                        regname, arm_reg[rn], U ? "" : "-", offset);
            } else {
                /* Post-indexed */
                int offset = imm8 * 4;
                sprintf(buf, "%s%s\t%s, [%s], #%s%d", op, arm_cond[cond],
                        regname, arm_reg[rn], U ? "" : "-", offset);
            }
            stat_vfp++;
            return;
        }

        /* Generic LDC/STC */
        {
            int crd = (instr >> 12) & 0xF;
            int offset = imm8 * 4;
            if (P)
                sprintf(buf, "%s%s\tp%d, c%d, [%s, #%s%d]%s",
                        L ? "ldc" : "stc", arm_cond[cond], cpnum, crd,
                        arm_reg[rn], U ? "" : "-", offset, W ? "!" : "");
            else
                sprintf(buf, "%s%s\tp%d, c%d, [%s], #%s%d",
                        L ? "ldc" : "stc", arm_cond[cond], cpnum, crd,
                        arm_reg[rn], U ? "" : "-", offset);
        }
        stat_other++;
        return;
    }

    /* ---- Block Data Transfer: LDM/STM ---- */
    /* bits[27:25] = 100 */
    if (bits27_25 == 4) {
        int P = (instr >> 24) & 1;
        int U = (instr >> 23) & 1;
        int S = (instr >> 22) & 1;
        int W = (instr >> 21) & 1;
        int L = (instr >> 20) & 1;
        int rn = (instr >> 16) & 0xF;
        uint16_t reglist = instr & 0xFFFF;
        const char *mode;
        if (L) {
            if (P && U) mode = "ldmed";
            else if (!P && U) mode = "ldmfd";
            else if (P && !U) mode = "ldmea";
            else mode = "ldmfa";
        } else {
            if (P && U) mode = "stmfa";
            else if (!P && U) mode = "stmea";
            else if (P && !U) mode = "stmfd";
            else mode = "stmed";
        }
        char rl[128];
        reglist_str(reglist, rl);
        sprintf(buf, "%s%s\t%s%s, %s%s", mode, arm_cond[cond],
                arm_reg[rn], W ? "!" : "", rl, S ? "^" : "");
        stat_ldm_stm++;
        return;
    }

    /* ---- Single Data Transfer: LDR/STR ---- */
    /* bits[27:26] = 01 */
    if ((bits27_25 & 6) == 2) {
        int I = (instr >> 25) & 1;
        int P = (instr >> 24) & 1;
        int U = (instr >> 23) & 1;
        int B = (instr >> 22) & 1;
        int W = (instr >> 21) & 1;
        int L = (instr >> 20) & 1;
        int rn = (instr >> 16) & 0xF;
        int rd = (instr >> 12) & 0xF;

        /* Check for UDF (permanently undefined): 0xE7F000Fx */
        if ((instr & 0xFFF000F0) == 0xE7F000F0) {
            int trapNr = instr & 0xF;
            sprintf(buf, "udf\t#%d\t; trap %d", trapNr, trapNr);
            stat_other++;
            return;
        }

        /* When I=1 (register offset) and bit[4]=1, this is a media instruction
         * (ARMv5TE+), NOT a standard LDR/STR.  Check SDIV/UDIV here. */
        if (I && (instr & 0x10)) {
            /* SDIV: cond 0111 0001 Rd 1111 Rm 0001 Rn */
            if ((instr & 0x0FF0F0F0) == 0x0710F010) {
                int drd = (instr >> 16) & 0xF;
                int drm = (instr >> 8) & 0xF;
                int drn = instr & 0xF;
                sprintf(buf, "sdiv%s\t%s, %s, %s", arm_cond[cond],
                        arm_reg[drd], arm_reg[drn], arm_reg[drm]);
                stat_dp++;
                return;
            }
            /* UDIV: cond 0111 0011 Rd 1111 Rm 0001 Rn */
            if ((instr & 0x0FF0F0F0) == 0x0730F010) {
                int drd = (instr >> 16) & 0xF;
                int drm = (instr >> 8) & 0xF;
                int drn = instr & 0xF;
                sprintf(buf, "udiv%s\t%s, %s, %s", arm_cond[cond],
                        arm_reg[drd], arm_reg[drn], arm_reg[drm]);
                stat_dp++;
                return;
            }
            /* Other media instructions: decode as .word */
            sprintf(buf, ".word\t0x%08x\t; media", instr);
            stat_other++;
            return;
        }

        const char *op = L ? "ldr" : "str";
        const char *b_suffix = B ? "b" : "";
        char offset_str[64];

        if (!I) {
            uint32_t imm12 = instr & 0xFFF;
            if (imm12 == 0)
                offset_str[0] = 0;
            else
                sprintf(offset_str, ", #%s%u", U ? "" : "-", imm12);
        } else {
            char shifter[64];
            format_shifter(instr & 0xFFF, shifter, 0);
            sprintf(offset_str, ", %s%.32s", U ? "" : "-", shifter);
        }

        if (P && !W) {
            sprintf(buf, "%s%s%s\t%s, [%s%s]", op, arm_cond[cond], b_suffix,
                    arm_reg[rd], arm_reg[rn], offset_str);
        } else if (P && W) {
            sprintf(buf, "%s%s%s\t%s, [%s%s]!", op, arm_cond[cond], b_suffix,
                    arm_reg[rd], arm_reg[rn], offset_str);
        } else {
            sprintf(buf, "%s%s%s\t%s, [%s]%s", op, arm_cond[cond], b_suffix,
                    arm_reg[rd], arm_reg[rn], offset_str);
        }
        if (L) stat_load++; else stat_store++;
        return;
    }

    /* ================================================================
     * bits[27:26] = 00: Data Processing and misc instructions
     * Check specific patterns BEFORE the generic DP catch-all!
     * ================================================================ */

    /* ---- MRS: cond 0001 0x00 1111 Rd 0000 0000 0000 ---- */
    if ((instr & 0x0FBF0FFF) == 0x010F0000) {
        int R = (instr >> 22) & 1;
        int rd = (instr >> 12) & 0xF;
        sprintf(buf, "mrs%s\t%s, %s", arm_cond[cond], arm_reg[rd], R ? "spsr" : "cpsr");
        stat_other++;
        return;
    }

    /* ---- MSR register: cond 0001 0x10 mask 1111 0000 0000 Rm ---- */
    if ((instr & 0x0FB0FFF0) == 0x0120F000) {
        int R = (instr >> 22) & 1;
        int mask = (instr >> 16) & 0xF;
        int rm = instr & 0xF;
        char fields[5] = {0};
        int fi = 0;
        if (mask & 8) fields[fi++] = 'f';
        if (mask & 4) fields[fi++] = 's';
        if (mask & 2) fields[fi++] = 'x';
        if (mask & 1) fields[fi++] = 'c';
        sprintf(buf, "msr%s\t%s_%s, %s", arm_cond[cond],
                R ? "spsr" : "cpsr", fields, arm_reg[rm]);
        stat_other++;
        return;
    }

    /* ---- BX: cond 0001 0010 1111 1111 1111 0001 Rm ---- */
    if ((instr & 0x0FFFFFF0) == 0x012FFF10) {
        int rm = instr & 0xF;
        sprintf(buf, "bx%s\t%s", arm_cond[cond], arm_reg[rm]);
        stat_branch++;
        return;
    }

    /* ---- BLX register: cond 0001 0010 1111 1111 1111 0011 Rm ---- */
    if ((instr & 0x0FFFFFF0) == 0x012FFF30) {
        int rm = instr & 0xF;
        sprintf(buf, "blx%s\t%s", arm_cond[cond], arm_reg[rm]);
        stat_branch++;
        return;
    }

    /* ---- CLZ: cond 0001 0110 1111 Rd 1111 0001 Rm ---- */
    if ((instr & 0x0FFF0FF0) == 0x016F0F10) {
        int rd = (instr >> 12) & 0xF;
        int rm = instr & 0xF;
        sprintf(buf, "clz%s\t%s, %s", arm_cond[cond], arm_reg[rd], arm_reg[rm]);
        stat_dp++;
        return;
    }

    /* ---- BKPT: 1110 0001 0010 imm12 0111 imm4 ---- */
    if ((instr & 0xFFF000F0) == 0xE1200070) {
        uint32_t imm = ((instr >> 4) & 0xFFF0) | (instr & 0xF);
        sprintf(buf, "bkpt\t#%u", imm);
        stat_other++;
        return;
    }

    /* ---- SWP/SWPB: cond 0001 0B00 Rn Rd 0000 1001 Rm ---- */
    if ((instr & 0x0FB00FF0) == 0x01000090) {
        int B = (instr >> 22) & 1;
        int rn = (instr >> 16) & 0xF;
        int rd = (instr >> 12) & 0xF;
        int rm = instr & 0xF;
        sprintf(buf, "swp%s%s\t%s, %s, [%s]", arm_cond[cond], B ? "b" : "",
                arm_reg[rd], arm_reg[rm], arm_reg[rn]);
        stat_other++;
        return;
    }

    /* ---- LDREX: cond 0001 1001 Rn Rd 1111 1001 1111 ---- */
    if ((instr & 0x0FF00FFF) == 0x01900F9F) {
        int rn = (instr >> 16) & 0xF;
        int rd = (instr >> 12) & 0xF;
        sprintf(buf, "ldrex%s\t%s, [%s]", arm_cond[cond], arm_reg[rd], arm_reg[rn]);
        stat_load++;
        return;
    }

    /* ---- STREX: cond 0001 1000 Rn Rd 1111 1001 Rm ---- */
    if ((instr & 0x0FF00FF0) == 0x01800F90) {
        int rn = (instr >> 16) & 0xF;
        int rd = (instr >> 12) & 0xF;
        int rm = instr & 0xF;
        sprintf(buf, "strex%s\t%s, %s, [%s]", arm_cond[cond],
                arm_reg[rd], arm_reg[rm], arm_reg[rn]);
        stat_store++;
        return;
    }

    /* NOTE: SDIV/UDIV are now decoded in the LDR/STR section above
     * (they have bits[27:25]=011, bit[4]=1 which falls in the media
     * instruction space within the LDR/STR encoding region). */

    /* ---- MOVW: cond 0011 0000 imm4 Rd imm12 ---- */
    if ((instr & 0x0FF00000) == 0x03000000) {
        int rd = (instr >> 12) & 0xF;
        uint32_t imm4 = (instr >> 16) & 0xF;
        uint32_t imm12 = instr & 0xFFF;
        uint32_t imm16 = (imm4 << 12) | imm12;
        sprintf(buf, "movw%s\t%s, #%u\t; 0x%x", arm_cond[cond],
                arm_reg[rd], imm16, imm16);
        stat_dp++;
        return;
    }

    /* ---- MOVT: cond 0011 0100 imm4 Rd imm12 ---- */
    if ((instr & 0x0FF00000) == 0x03400000) {
        int rd = (instr >> 12) & 0xF;
        uint32_t imm4 = (instr >> 16) & 0xF;
        uint32_t imm12 = instr & 0xFFF;
        uint32_t imm16 = (imm4 << 12) | imm12;
        sprintf(buf, "movt%s\t%s, #%u\t; 0x%x", arm_cond[cond],
                arm_reg[rd], imm16, imm16);
        stat_dp++;
        return;
    }

    /* ---- NOP / hints: cond 0011 0010 0000 1111 0000 0000 option ---- */
    if ((instr & 0x0FFFFFFF) == 0x0320F000) {
        sprintf(buf, "nop%s", arm_cond[cond]);
        stat_other++;
        return;
    }
    if ((instr & 0x0FFFFFF0) == 0x0320F000) {
        int hint = instr & 0xF;
        switch (hint) {
        case 1: sprintf(buf, "yield%s", arm_cond[cond]); break;
        case 2: sprintf(buf, "wfe%s", arm_cond[cond]); break;
        case 3: sprintf(buf, "wfi%s", arm_cond[cond]); break;
        case 4: sprintf(buf, "sev%s", arm_cond[cond]); break;
        default: sprintf(buf, "hint%s\t#%d", arm_cond[cond], hint); break;
        }
        stat_other++;
        return;
    }

    /* ---- MSR immediate: cond 0011 0x10 mask 1111 rotate imm8 ---- */
    /* Must come after MOVW/MOVT and NOP/hints */
    if ((instr & 0x0FB0F000) == 0x0320F000) {
        int R = (instr >> 22) & 1;
        int mask = (instr >> 16) & 0xF;
        uint32_t imm8 = instr & 0xFF;
        uint32_t rot = ((instr >> 8) & 0xF) * 2;
        uint32_t val;
        if (rot == 0)
            val = imm8;
        else
            val = (imm8 >> rot) | (imm8 << (32 - rot));
        char fields[5] = {0};
        int fi = 0;
        if (mask & 8) fields[fi++] = 'f';
        if (mask & 4) fields[fi++] = 's';
        if (mask & 2) fields[fi++] = 'x';
        if (mask & 1) fields[fi++] = 'c';
        sprintf(buf, "msr%s\t%s_%s, #%u", arm_cond[cond],
                R ? "spsr" : "cpsr", fields, val);
        stat_other++;
        return;
    }

    /* ---- Long Multiply: UMULL/SMULL/UMLAL/SMLAL ---- */
    /* cond 0000 1UAS RdHi RdLo Rs 1001 Rm */
    if ((instr & 0x0F8000F0) == 0x00800090) {
        int op2 = (instr >> 21) & 3;
        int S = (instr >> 20) & 1;
        int rdhi = (instr >> 16) & 0xF;
        int rdlo = (instr >> 12) & 0xF;
        int rs = (instr >> 8) & 0xF;
        int rm = instr & 0xF;
        const char *ops[] = { "umull", "umlal", "smull", "smlal" };
        sprintf(buf, "%s%s%s\t%s, %s, %s, %s", ops[op2], arm_cond[cond], S ? "s" : "",
                arm_reg[rdlo], arm_reg[rdhi], arm_reg[rm], arm_reg[rs]);
        stat_mul++;
        return;
    }

    /* ---- Multiply: MUL/MLA ---- */
    /* cond 0000 00AS Rd Rn Rs 1001 Rm */
    if ((instr & 0x0FC000F0) == 0x00000090) {
        int A = (instr >> 21) & 1;
        int S = (instr >> 20) & 1;
        int rd = (instr >> 16) & 0xF;
        int rn = (instr >> 12) & 0xF;
        int rs = (instr >> 8) & 0xF;
        int rm = instr & 0xF;
        if (A)
            sprintf(buf, "mla%s%s\t%s, %s, %s, %s", arm_cond[cond], S ? "s" : "",
                    arm_reg[rd], arm_reg[rm], arm_reg[rs], arm_reg[rn]);
        else
            sprintf(buf, "mul%s%s\t%s, %s, %s", arm_cond[cond], S ? "s" : "",
                    arm_reg[rd], arm_reg[rm], arm_reg[rs]);
        stat_mul++;
        return;
    }

    /* ---- Halfword load/store ---- */
    /* cond 000x xxxx xxxx xxxx xxxx 1xx1 xxxx  (bit[7]=1, bit[4]=1, bits[6:5]!=00) */
    if (((instr & 0x0E000090) == 0x00000090) && ((instr & 0x60) != 0)) {
        int P = (instr >> 24) & 1;
        int U = (instr >> 23) & 1;
        int I = (instr >> 22) & 1;
        int W = (instr >> 21) & 1;
        int L = (instr >> 20) & 1;
        int rn = (instr >> 16) & 0xF;
        int rd = (instr >> 12) & 0xF;
        int sh = (instr >> 5) & 3;
        int rm_hw = instr & 0xF;
        const char *ops[4] = { "???", "h", "sb", "sh" };
        const char *op = L ? "ldr" : "str";
        char offset_str[64];
        if (I) {
            int imm = ((instr >> 4) & 0xF0) | (instr & 0xF);
            if (imm == 0) offset_str[0] = 0;
            else sprintf(offset_str, ", #%s%d", U ? "" : "-", imm);
        } else {
            sprintf(offset_str, ", %s%s", U ? "" : "-", arm_reg[rm_hw]);
        }
        if (P)
            sprintf(buf, "%s%s%s\t%s, [%s%s]%s", op, arm_cond[cond], ops[sh],
                    arm_reg[rd], arm_reg[rn], offset_str, W ? "!" : "");
        else
            sprintf(buf, "%s%s%s\t%s, [%s]%s", op, arm_cond[cond], ops[sh],
                    arm_reg[rd], arm_reg[rn], offset_str);
        if (L) stat_load++; else stat_store++;
        return;
    }

    /* ---- Generic Data Processing (catch-all for bits[27:26]=00) ---- */
    if ((bits27_25 & 6) == 0) {
        int I = (instr >> 25) & 1;
        int opcode = (instr >> 21) & 0xF;
        int S = (instr >> 20) & 1;
        int rn = (instr >> 16) & 0xF;
        int rd = (instr >> 12) & 0xF;
        char shifter[64];
        format_shifter(instr, shifter, I);

        /* Special case: MOV R0, R0 = NOP */
        if (opcode == 13 && !S && rd == 0 && !I && (instr & 0xFFF) == 0) {
            sprintf(buf, "mov%s\t%s, %s\t; nop", arm_cond[cond], arm_reg[rd], shifter);
            stat_dp++;
            return;
        }

        if (opcode >= 8 && opcode <= 11) {
            /* TST, TEQ, CMP, CMN - no Rd, must have S=1 */
            sprintf(buf, "%s%s\t%s, %s", arm_dp_op[opcode], arm_cond[cond],
                    arm_reg[rn], shifter);
        } else if (opcode == 13 || opcode == 15) {
            /* MOV, MVN - no Rn */
            sprintf(buf, "%s%s%s\t%s, %s", arm_dp_op[opcode], arm_cond[cond],
                    S ? "s" : "", arm_reg[rd], shifter);
        } else {
            sprintf(buf, "%s%s%s\t%s, %s, %s", arm_dp_op[opcode], arm_cond[cond],
                    S ? "s" : "", arm_reg[rd], arm_reg[rn], shifter);
        }
        stat_dp++;
        return;
    }

    /* ---- Fallback ---- */
    sprintf(buf, ".word\t0x%08x", instr);
    stat_other++;
}


/* ---- Main dump logic ---- */

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s [-v] <objectfile.Obj>\n", argv[0]);
        return 1;
    }

    int argidx = 1;
    if (argc > 2 && strcmp(argv[1], "-v") == 0) {
        verbose = 1;
        argidx = 2;
    }

    f = fopen(argv[argidx], "rb");
    if (!f) {
        fprintf(stderr, "Cannot open %s\n", argv[argidx]);
        return 1;
    }

    /* Read file tag */
    int tag = read_byte();
    if (tag != OFTAG) {
        fprintf(stderr, "Not an Oberon object file (tag=0x%02X, expected 0x%02X)\n", tag, OFTAG);
        return 1;
    }
    int version = read_byte();
    printf("=== Oberon Object File ===\n");
    printf("Tag: 0x%02X  Version: 0x%02X", OFTAG, version);
    if (version == OFNATIVE) printf(" (native)\n");
    else if (version == OFNEW) printf(" (new)\n");
    else printf(" (unknown)\n");

    /* Skip symbol file section */
    int32_t sfsize;
    if (version == OFNEW) {
        sfsize = read_num();
        printf("Symbol file size: %d (includes flags)\n", sfsize);
    } else {
        sfsize = read_num();
        printf("Symbol file size: %d\n", sfsize);
    }
    for (int32_t i = 0; i < sfsize; i++) read_byte();

    /* Read header */
    int32_t refSize = read_int32();
    int16_t nofEntries = read_int16();
    int16_t nofCmds = read_int16();
    int16_t nofPtrs = read_int16();
    int16_t nofTypes = read_int16();
    int16_t nofImps = read_int16();
    int16_t nofVarCons = read_int16();
    int16_t nofLinks = read_int16();
    int32_t dataSize = read_int32();
    int16_t constSize = read_int16();
    uint16_t codeSize = read_uint16();
    char modName[256];
    read_string(modName, sizeof(modName));

    printf("\n--- Header ---\n");
    printf("Module:        %s\n", modName);
    printf("RefSize:       %d\n", refSize);
    printf("Entries:       %d\n", nofEntries);
    printf("Commands:      %d\n", nofCmds);
    printf("Pointers:      %d\n", nofPtrs);
    printf("Types:         %d\n", nofTypes);
    printf("Imports:       %d\n", nofImps);
    printf("VarConsLinks:  %d\n", nofVarCons);
    printf("Links:         %d\n", nofLinks);
    printf("DataSize:      %d (0x%x)\n", dataSize, dataSize);
    printf("ConstSize:     %d (0x%x)\n", constSize, constSize);
    printf("CodeSize:      %d (0x%x)\n", codeSize, codeSize);

    /* Entries - read and store (printed later with procedure names from Ref) */
    expect_tag(EntryTag);
    nof_entries_stored = 0;
    for (int i = 0; i < nofEntries; i++) {
        int16_t entry = read_int16();
        if (nof_entries_stored < MAX_ENTRIES)
            entry_offsets[nof_entries_stored++] = entry;
    }

    /* Commands */
    expect_tag(CommandTag);
    printf("\n--- Commands ---\n");
    for (int i = 0; i < nofCmds; i++) {
        char name[256];
        int ch = read_byte();
        int has_param = 0;
        if (ch == '$') {
            has_param = 1;
            read_string(name, sizeof(name));
        } else {
            name[0] = (char)ch;
            if (ch != 0) {
                int j = 1;
                do {
                    ch = read_byte();
                    if (j < 255) name[j++] = (char)ch;
                } while (ch != 0);
                name[j] = 0;
            }
        }
        int16_t entry = read_int16();
        printf("  %s%s  entry=%d (0x%x)\n", has_param ? "$" : "", name, entry, (unsigned)entry);
    }

    /* Pointers */
    expect_tag(PointerTag);
    printf("\n--- Pointers ---\n");
    for (int i = 0; i < nofPtrs; i++) {
        int32_t offset = read_int32();
        printf("  [%d] offset=%d (0x%x)\n", i, offset, (unsigned)offset);
    }

    /* Imports */
    expect_tag(ImportTag);
    printf("\n--- Imports ---\n");
    for (int i = 0; i < nofImps; i++) {
        char name[256];
        read_string(name, sizeof(name));
        printf("  [%d] %s\n", i + 1, name);
    }

    /* VarConsLinks */
    expect_tag(VarConsLinkTag);
    printf("\n--- VarConsLinks ---\n");
    for (int i = 0; i < nofVarCons; i++) {
        int mod = read_byte();
        int16_t entry = read_int16();
        int16_t nofFixups = read_int16();
        printf("  mod=%d entry=%d nofFixups=%d:", mod, entry, nofFixups);
        for (int j = 0; j < nofFixups; j++) {
            int16_t offset = read_int16();
            printf(" %d(0x%x)", offset, (unsigned)(uint16_t)offset);
        }
        printf("\n");
    }

    /* Links */
    expect_tag(LinkTag);
    printf("\n--- Links ---\n");
    for (int i = 0; i < nofLinks; i++) {
        int mod = read_byte();
        int entry = read_byte();
        int16_t offset = read_int16();
        printf("  mod=%d entry=%d offset=%d (0x%x)\n", mod, entry, offset, (unsigned)(uint16_t)offset);
    }

    /* Data (constants) */
    expect_tag(DataTag);
    printf("\n--- Data (Constants, %d bytes) ---\n", constSize);
    uint8_t *constData = NULL;
    if (constSize > 0) {
        constData = (uint8_t *)malloc(constSize);
        for (int i = 0; i < constSize; i++)
            constData[i] = (uint8_t)read_byte();
        for (int i = 0; i < constSize; i += 16) {
            printf("  %04X:", i);
            for (int j = 0; j < 16 && i + j < constSize; j++)
                printf(" %02X", constData[i + j]);
            printf("  ");
            for (int j = 0; j < 16 && i + j < constSize; j++) {
                uint8_t c = constData[i + j];
                printf("%c", (c >= 32 && c < 127) ? c : '.');
            }
            printf("\n");
        }
    }

    /* Export */
    expect_tag(ExportTag);
    printf("\n--- Export ---\n");
    {
        int16_t nofExp = read_int16();
        printf("  nofExports=%d\n", nofExp);
        /* Parse export data using recursive parser.
         *
         * Format (from OPL.Mod lines 2603-2639, 2863-2868):
         *   ExportTag nofExp(int16)
         *   { fp(num) adr(num) [ExportRecord] }*
         *   EUEnd(byte 0)
         *
         * Each export writes:
         *   1. fp(num) - fingerprint (never 0, so 0 = EUEnd terminator)
         *   2. adr(num) - address (CAN be 0 for Typ exports via ObjW(0X))
         *   3. optionally ExportRecord if type is Record
         *
         * We must read fp+adr as PAIRS because adr=0 is valid and must
         * not be confused with EUEnd. Only fp=0 means EUEnd.
         */
        for (;;) {
            int32_t fp = read_num();
            if (fp == EUEnd) break;  /* fp is never 0, so 0 = terminator */
            int32_t adr = read_num(); /* address - can be 0 */
            if (verbose) printf("  export fp=%d adr=%d\n", fp, adr);
            /* Check if followed by ExportRecord */
            int peek = fgetc(f);
            if (peek == EURecord) {
                skip_export_record(0);
            } else {
                ungetc(peek, f);
            }
        }
    }

    /* Code - read into buffer (disassembly printed after Ref parsing) */
    expect_tag(CodeTag);

    uint8_t *codeData = NULL;
    if (codeSize > 0) {
        codeData = (uint8_t *)malloc(codeSize);
        for (uint16_t i = 0; i < codeSize; i++)
            codeData[i] = (uint8_t)read_byte();
    }

    /* Read remaining sections (Use, Types, Ref) into buffer.
     * The last refSize bytes of the file are the Ref section
     * (appended by OPM.CloseObj without a tag byte). */
    long afterCode = ftell(f);
    fseek(f, 0, SEEK_END);
    long fileEnd = ftell(f);
    fseek(f, afterCode, SEEK_SET);
    long remaining = fileEnd - afterCode;

    uint8_t *restData = NULL;
    if (remaining > 0) {
        restData = (uint8_t *)malloc(remaining);
        fread(restData, 1, remaining, f);
    }

    /* Parse Ref section for procedure names.
     * Ref data occupies the last refSize bytes of the file. */
    if (restData && refSize > 0 && refSize <= remaining) {
        const uint8_t *refData = restData + (remaining - refSize);
        parse_ref_data(refData, refSize);
    }

    /* Print Entries with procedure names */
    printf("\n--- Entries ---\n");
    for (int i = 0; i < nof_entries_stored; i++) {
        const char *pname = find_proc_name(entry_offsets[i]);
        if (pname)
            printf("  [%d] offset=%d (0x%x)  %s\n", i, entry_offsets[i],
                   (unsigned)entry_offsets[i], pname);
        else
            printf("  [%d] offset=%d (0x%x)\n", i, entry_offsets[i],
                   (unsigned)entry_offsets[i]);
    }

    /* Print Code disassembly with procedure names */
    printf("\n--- Code (%d bytes, %d words) ---\n", codeSize, codeSize / 4);

    /* Reset statistics */
    stat_dp = stat_branch = stat_load = stat_store = 0;
    stat_ldm_stm = stat_mul = stat_vfp = stat_other = 0;

    if (codeSize > 0) {
        /* Check if code looks like ARM (4-byte aligned words) */
        if (codeSize >= 4 && (codeSize % 4 == 0)) {
            for (uint16_t i = 0; i < codeSize; i += 4) {
                /* Check for procedure boundary */
                int entry_idx = find_entry(i);
                if (entry_idx >= 0) {
                    const char *pname = find_proc_name(i);
                    if (pname)
                        printf("\n  ; ---- entry[%d] %s (0x%04X) ----\n", entry_idx, pname, i);
                    else
                        printf("\n  ; ---- entry[%d] at 0x%04X ----\n", entry_idx, i);
                } else {
                    /* Check if this offset has a proc name but no entry (local proc) */
                    const char *pname = find_proc_name(i);
                    if (pname)
                        printf("\n  ; ---- %s (0x%04X) ----\n", pname, i);
                }

                uint32_t instr = (uint32_t)codeData[i] |
                                 ((uint32_t)codeData[i+1] << 8) |
                                 ((uint32_t)codeData[i+2] << 16) |
                                 ((uint32_t)codeData[i+3] << 24);
                char dis[256];
                disasm_arm(i, instr, dis);
                printf("  %04X: %08X  %s\n", i, instr, dis);
            }
        } else {
            /* Hex dump for non-ARM code */
            for (uint16_t i = 0; i < codeSize; i += 16) {
                printf("  %04X:", i);
                for (int j = 0; j < 16 && i + j < codeSize; j++)
                    printf(" %02X", codeData[i + j]);
                printf("\n");
            }
        }

        /* Instruction statistics */
        int total = stat_dp + stat_branch + stat_load + stat_store +
                    stat_ldm_stm + stat_mul + stat_vfp + stat_other;
        printf("\n  ; --- Instruction Statistics ---\n");
        printf("  ;   Data Processing: %d\n", stat_dp);
        printf("  ;   Branches:        %d\n", stat_branch);
        printf("  ;   Loads:           %d\n", stat_load);
        printf("  ;   Stores:          %d\n", stat_store);
        printf("  ;   LDM/STM:         %d\n", stat_ldm_stm);
        printf("  ;   Multiply:        %d\n", stat_mul);
        printf("  ;   VFP:             %d\n", stat_vfp);
        printf("  ;   Other:           %d\n", stat_other);
        printf("  ;   Total:           %d\n", total);
    }

    /* Remaining sections summary */
    printf("\n--- Remaining sections (Use/Types/Refs) ---\n");
    printf("  %ld bytes total, %d bytes Ref (%d procedures)\n",
           remaining, refSize, nof_procs);

    if (constData) free(constData);
    if (codeData) free(codeData);
    if (restData) free(restData);
    fclose(f);
    return 0;
}
