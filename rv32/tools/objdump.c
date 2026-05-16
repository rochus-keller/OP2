/*
 * Oberon Object File Dump Tool — RV32 edition
 * Reads an Oberon .Obj file and dumps its contents in text format,
 * including RV32 disassembly of the code section.
 * Copyright 2026 Rochus Keller <mailto:me@rochus-keller.ch>
 *
 * Object file format (from OPL.Mod):
 *   OFtag(0xBB) OFversion(0xAF) sfsize(num) symdata refsize(4)
 *   Header Entries Commands Pointers Imports VarConsLinks Links
 *   Data Export Code Use Types
 *
 * Supported RV32 instruction decoding:
 *   - R-type: ADD, SUB, AND, OR, XOR, SLL, SRL, SRA, SLT, SLTU
 *   - M extension: MUL, MULH, MULHSU, MULHU, DIV, DIVU, REM, REMU
 *   - I-type: ADDI, ANDI, ORI, XORI, SLTI, SLTIU, SLLI, SRLI, SRAI
 *   - U-type: LUI, AUIPC
 *   - J-type: JAL
 *   - JALR
 *   - B-type: BEQ, BNE, BLT, BGE, BLTU, BGEU
 *   - Load: LB, LH, LW, LBU, LHU
 *   - Store: SB, SH, SW
 *   - F extension: FLW, FSW, FADD.S, FSUB.S, FMUL.S, FDIV.S,
 *     FSGNJ.S, FSGNJN.S, FSGNJX.S, FEQ.S, FLT.S, FLE.S,
 *     FCVT.W.S, FCVT.S.W, FMV.X.W, FMV.W.X, FSQRT.S
 *   - System: ECALL, EBREAK, FENCE, WFI
 *   - Pseudo-instruction recognition: NOP, MV, LI, J, RET, etc.
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

static FILE *f;
static int verbose = 0;

/* Entry table for procedure boundary markers */
static int16_t entry_offsets[MAX_ENTRIES];
static int nof_entries_stored = 0;

/* Instruction statistics */
static int stat_alu = 0, stat_branch = 0, stat_load = 0, stat_store = 0;
static int stat_mul = 0, stat_fpu = 0, stat_system = 0, stat_other = 0;


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


static const char *rv_xreg[32] = {
    "zero", "ra", "sp", "gp", "tp", "t0", "t1", "t2",
    "s0",   "s1", "a0", "a1", "a2", "a3", "a4", "a5",
    "a6",   "a7", "s2", "s3", "s4", "s5", "s6", "s7",
    "s8",   "s9", "s10","s11","t3", "t4", "t5", "t6"
};

static const char *rv_freg[32] = {
    "ft0", "ft1", "ft2", "ft3", "ft4", "ft5", "ft6", "ft7",
    "fs0", "fs1", "fa0", "fa1", "fa2", "fa3", "fa4", "fa5",
    "fa6", "fa7", "fs2", "fs3", "fs4", "fs5", "fs6", "fs7",
    "fs8", "fs9", "fs10","fs11","ft8", "ft9", "ft10","ft11"
};

/* Sign-extend a value from bit_width bits to 32 bits */
static int32_t sign_extend(uint32_t val, int bit_width) {
    uint32_t sign_bit = 1u << (bit_width - 1);
    return (int32_t)((val ^ sign_bit) - sign_bit);
}

/* Extract I-type immediate */
static int32_t imm_i(uint32_t instr) {
    return sign_extend(instr >> 20, 12);
}

/* Extract S-type immediate */
static int32_t imm_s(uint32_t instr) {
    uint32_t lo = (instr >> 7) & 0x1F;
    uint32_t hi = (instr >> 25) & 0x7F;
    return sign_extend((hi << 5) | lo, 12);
}

/* Extract B-type immediate */
static int32_t imm_b(uint32_t instr) {
    uint32_t b11  = (instr >> 7)  & 1;
    uint32_t b4_1 = (instr >> 8)  & 0xF;
    uint32_t b10_5= (instr >> 25) & 0x3F;
    uint32_t b12  = (instr >> 31) & 1;
    uint32_t imm = (b12 << 12) | (b11 << 11) | (b10_5 << 5) | (b4_1 << 1);
    return sign_extend(imm, 13);
}

/* Extract U-type immediate (already shifted left 12) */
static int32_t imm_u(uint32_t instr) {
    return (int32_t)(instr & 0xFFFFF000);
}

/* Extract J-type immediate */
static int32_t imm_j(uint32_t instr) {
    uint32_t b19_12 = (instr >> 12) & 0xFF;
    uint32_t b11    = (instr >> 20) & 1;
    uint32_t b10_1  = (instr >> 21) & 0x3FF;
    uint32_t b20    = (instr >> 31) & 1;
    uint32_t imm = (b20 << 20) | (b19_12 << 12) | (b11 << 11) | (b10_1 << 1);
    return sign_extend(imm, 21);
}

static void disasm_rv32(uint32_t addr, uint32_t instr, char *buf) {
    uint32_t opcode = instr & 0x7F;
    int rd   = (instr >> 7)  & 0x1F;
    int rs1  = (instr >> 15) & 0x1F;
    int rs2  = (instr >> 20) & 0x1F;
    int funct3 = (instr >> 12) & 7;
    int funct7 = (instr >> 25) & 0x7F;

    /* NOP: ADDI x0, x0, 0 */
    if (instr == 0x00000013) {
        sprintf(buf, "nop");
        stat_alu++;
        return;
    }

    /* Semihosting markers */
    if (instr == 0x01F01013) {
        sprintf(buf, "slli\tzero, zero, 0x1f\t; semihosting entry");
        stat_system++;
        return;
    }
    if (instr == 0x40700013) {
        sprintf(buf, "srai\tzero, zero, 7\t; semihosting exit");
        stat_system++;
        return;
    }

    switch (opcode) {

    case 0x33: {
        const char *mne = "???";
        if (funct7 == 0x00) {
            switch (funct3) {
            case 0: mne = "add"; break;
            case 1: mne = "sll"; break;
            case 2: mne = "slt"; break;
            case 3: mne = "sltu"; break;
            case 4: mne = "xor"; break;
            case 5: mne = "srl"; break;
            case 6: mne = "or"; break;
            case 7: mne = "and"; break;
            }
            stat_alu++;
        } else if (funct7 == 0x20) {
            switch (funct3) {
            case 0: mne = "sub"; break;
            case 5: mne = "sra"; break;
            default: mne = "???"; break;
            }
            stat_alu++;
        } else if (funct7 == 0x01) {
            /* M extension */
            switch (funct3) {
            case 0: mne = "mul"; break;
            case 1: mne = "mulh"; break;
            case 2: mne = "mulhsu"; break;
            case 3: mne = "mulhu"; break;
            case 4: mne = "div"; break;
            case 5: mne = "divu"; break;
            case 6: mne = "rem"; break;
            case 7: mne = "remu"; break;
            }
            stat_mul++;
        }
        /* Pseudo: MV = ADD rd, rs1, zero */
        if (funct7 == 0x00 && funct3 == 0 && rs2 == 0) {
            sprintf(buf, "mv\t%s, %s", rv_xreg[rd], rv_xreg[rs1]);
        } else {
            sprintf(buf, "%s\t%s, %s, %s", mne, rv_xreg[rd], rv_xreg[rs1], rv_xreg[rs2]);
        }
        return;
    }

    case 0x13: {
        int32_t imm = imm_i(instr);
        int shamt = rs2; /* bits [24:20] for shift amount */

        if (funct3 == 1 && funct7 == 0x00) {
            sprintf(buf, "slli\t%s, %s, %d", rv_xreg[rd], rv_xreg[rs1], shamt);
        } else if (funct3 == 5 && funct7 == 0x00) {
            sprintf(buf, "srli\t%s, %s, %d", rv_xreg[rd], rv_xreg[rs1], shamt);
        } else if (funct3 == 5 && funct7 == 0x20) {
            sprintf(buf, "srai\t%s, %s, %d", rv_xreg[rd], rv_xreg[rs1], shamt);
        } else {
            const char *mne;
            switch (funct3) {
            case 0: mne = "addi"; break;
            case 2: mne = "slti"; break;
            case 3: mne = "sltiu"; break;
            case 4: mne = "xori"; break;
            case 6: mne = "ori"; break;
            case 7: mne = "andi"; break;
            default: mne = "???"; break;
            }
            /* Pseudo: LI = ADDI rd, zero, imm */
            if (funct3 == 0 && rs1 == 0 && rd != 0) {
                sprintf(buf, "li\t%s, %d", rv_xreg[rd], imm);
            }
            /* Pseudo: MV = ADDI rd, rs1, 0 */
            else if (funct3 == 0 && imm == 0 && rd != 0) {
                sprintf(buf, "mv\t%s, %s", rv_xreg[rd], rv_xreg[rs1]);
            }
            /* Pseudo: SEQZ = SLTIU rd, rs1, 1 */
            else if (funct3 == 3 && imm == 1) {
                sprintf(buf, "seqz\t%s, %s", rv_xreg[rd], rv_xreg[rs1]);
            }
            /* Pseudo: NOT = XORI rd, rs1, -1 */
            else if (funct3 == 4 && imm == -1) {
                sprintf(buf, "not\t%s, %s", rv_xreg[rd], rv_xreg[rs1]);
            } else {
                if (imm > 255 || imm < -256)
                    sprintf(buf, "%s\t%s, %s, %d\t; 0x%x", mne, rv_xreg[rd], rv_xreg[rs1], imm, (uint32_t)imm & 0xFFF);
                else
                    sprintf(buf, "%s\t%s, %s, %d", mne, rv_xreg[rd], rv_xreg[rs1], imm);
            }
        }
        stat_alu++;
        return;
    }

    case 0x37: { // LUI
        int32_t imm = imm_u(instr);
        sprintf(buf, "lui\t%s, 0x%x", rv_xreg[rd], ((uint32_t)imm) >> 12);
        stat_alu++;
        return;
    }

    case 0x17: { // AUIPC
        int32_t imm = imm_u(instr);
        sprintf(buf, "auipc\t%s, 0x%x", rv_xreg[rd], ((uint32_t)imm) >> 12);
        stat_alu++;
        return;
    }

    case 0x6F: { // JAL
        int32_t offset = imm_j(instr);
        uint32_t target = addr + offset;
        /* Pseudo: J = JAL zero, offset */
        if (rd == 0) {
            sprintf(buf, "j\t0x%x", target);
        }
        /* Pseudo: JAL = JAL ra, offset */
        else if (rd == 1) {
            sprintf(buf, "jal\t0x%x", target);
        } else {
            sprintf(buf, "jal\t%s, 0x%x", rv_xreg[rd], target);
        }
        stat_branch++;
        return;
    }

    case 0x67: { // JALR
        int32_t imm = imm_i(instr);
        /* Pseudo: RET = JALR zero, ra, 0 */
        if (rd == 0 && rs1 == 1 && imm == 0) {
            sprintf(buf, "ret");
        }
        /* Pseudo: JR = JALR zero, rs1, 0 */
        else if (rd == 0 && imm == 0) {
            sprintf(buf, "jr\t%s", rv_xreg[rs1]);
        } else if (imm == 0) {
            sprintf(buf, "jalr\t%s, %s", rv_xreg[rd], rv_xreg[rs1]);
        } else {
            sprintf(buf, "jalr\t%s, %s, %d", rv_xreg[rd], rv_xreg[rs1], imm);
        }
        stat_branch++;
        return;
    }

    case 0x63: { // Branch
        int32_t offset = imm_b(instr);
        uint32_t target = addr + offset;
        const char *mne;
        switch (funct3) {
        case 0: mne = "beq"; break;
        case 1: mne = "bne"; break;
        case 4: mne = "blt"; break;
        case 5: mne = "bge"; break;
        case 6: mne = "bltu"; break;
        case 7: mne = "bgeu"; break;
        default: mne = "b???"; break;
        }
        /* Pseudo: BEQZ = BEQ rs1, zero, offset */
        if (funct3 == 0 && rs2 == 0) {
            sprintf(buf, "beqz\t%s, 0x%x", rv_xreg[rs1], target);
        }
        /* Pseudo: BNEZ = BNE rs1, zero, offset */
        else if (funct3 == 1 && rs2 == 0) {
            sprintf(buf, "bnez\t%s, 0x%x", rv_xreg[rs1], target);
        } else {
            sprintf(buf, "%s\t%s, %s, 0x%x", mne, rv_xreg[rs1], rv_xreg[rs2], target);
        }
        stat_branch++;
        return;
    }

    case 0x03: { // Load
        int32_t imm = imm_i(instr);
        const char *mne;
        switch (funct3) {
        case 0: mne = "lb"; break;
        case 1: mne = "lh"; break;
        case 2: mne = "lw"; break;
        case 4: mne = "lbu"; break;
        case 5: mne = "lhu"; break;
        default: mne = "l???"; break;
        }
        sprintf(buf, "%s\t%s, %d(%s)", mne, rv_xreg[rd], imm, rv_xreg[rs1]);
        stat_load++;
        return;
    }

    case 0x23: { // Store
        int32_t imm = imm_s(instr);
        const char *mne;
        switch (funct3) {
        case 0: mne = "sb"; break;
        case 1: mne = "sh"; break;
        case 2: mne = "sw"; break;
        default: mne = "s???"; break;
        }
        sprintf(buf, "%s\t%s, %d(%s)", mne, rv_xreg[rs2], imm, rv_xreg[rs1]);
        stat_store++;
        return;
    }

    case 0x07: { // FLW
        if (funct3 == 2) {
            int32_t imm = imm_i(instr);
            sprintf(buf, "flw\t%s, %d(%s)", rv_freg[rd], imm, rv_xreg[rs1]);
        } else {
            sprintf(buf, ".word\t0x%08x\t; unknown float load", instr);
        }
        stat_load++;
        return;
    }

    case 0x27: { // FSW
        if (funct3 == 2) {
            int32_t imm = imm_s(instr);
            sprintf(buf, "fsw\t%s, %d(%s)", rv_freg[rs2], imm, rv_xreg[rs1]);
        } else {
            sprintf(buf, ".word\t0x%08x\t; unknown float store", instr);
        }
        stat_store++;
        return;
    }

    case 0x53: { // Float
        int rs2_f  = (instr >> 20) & 0x1F;
        int rm     = (instr >> 12) & 7;   /* rounding mode or funct3 */
        int funct5 = (instr >> 27) & 0x1F;
        int fmt    = (instr >> 25) & 3;    /* 00=S, 01=D */

        if (fmt == 0) {
            /* Single-precision */
            switch (funct5) {
            case 0x00: /* FADD.S */
                sprintf(buf, "fadd.s\t%s, %s, %s", rv_freg[rd], rv_freg[rs1], rv_freg[rs2_f]);
                break;
            case 0x01: /* FSUB.S */
                sprintf(buf, "fsub.s\t%s, %s, %s", rv_freg[rd], rv_freg[rs1], rv_freg[rs2_f]);
                break;
            case 0x02: /* FMUL.S */
                sprintf(buf, "fmul.s\t%s, %s, %s", rv_freg[rd], rv_freg[rs1], rv_freg[rs2_f]);
                break;
            case 0x03: /* FDIV.S */
                sprintf(buf, "fdiv.s\t%s, %s, %s", rv_freg[rd], rv_freg[rs1], rv_freg[rs2_f]);
                break;
            case 0x04: /* FSGNJ/FSGNJN/FSGNJX */
                switch (rm) {
                case 0:
                    if (rs1 == rs2_f)
                        sprintf(buf, "fmv.s\t%s, %s", rv_freg[rd], rv_freg[rs1]);
                    else
                        sprintf(buf, "fsgnj.s\t%s, %s, %s", rv_freg[rd], rv_freg[rs1], rv_freg[rs2_f]);
                    break;
                case 1:
                    if (rs1 == rs2_f)
                        sprintf(buf, "fneg.s\t%s, %s", rv_freg[rd], rv_freg[rs1]);
                    else
                        sprintf(buf, "fsgnjn.s\t%s, %s, %s", rv_freg[rd], rv_freg[rs1], rv_freg[rs2_f]);
                    break;
                case 2:
                    if (rs1 == rs2_f)
                        sprintf(buf, "fabs.s\t%s, %s", rv_freg[rd], rv_freg[rs1]);
                    else
                        sprintf(buf, "fsgnjx.s\t%s, %s, %s", rv_freg[rd], rv_freg[rs1], rv_freg[rs2_f]);
                    break;
                default:
                    sprintf(buf, "fsgnj?.s\t%s, %s, %s", rv_freg[rd], rv_freg[rs1], rv_freg[rs2_f]);
                    break;
                }
                break;
            case 0x05: /* FMIN/FMAX */
                sprintf(buf, "%s.s\t%s, %s, %s",
                        rm == 0 ? "fmin" : "fmax",
                        rv_freg[rd], rv_freg[rs1], rv_freg[rs2_f]);
                break;
            case 0x0B: /* FSQRT.S (rs2=0) */
                sprintf(buf, "fsqrt.s\t%s, %s", rv_freg[rd], rv_freg[rs1]);
                break;
            case 0x14: /* FEQ/FLT/FLE */
                switch (rm) {
                case 0: sprintf(buf, "fle.s\t%s, %s, %s", rv_xreg[rd], rv_freg[rs1], rv_freg[rs2_f]); break;
                case 1: sprintf(buf, "flt.s\t%s, %s, %s", rv_xreg[rd], rv_freg[rs1], rv_freg[rs2_f]); break;
                case 2: sprintf(buf, "feq.s\t%s, %s, %s", rv_xreg[rd], rv_freg[rs1], rv_freg[rs2_f]); break;
                default: sprintf(buf, "fcmp?.s\t%s, %s, %s", rv_xreg[rd], rv_freg[rs1], rv_freg[rs2_f]); break;
                }
                break;
            case 0x18: /* FCVT.W.S / FCVT.WU.S */
                if (rs2_f == 0)
                    sprintf(buf, "fcvt.w.s\t%s, %s", rv_xreg[rd], rv_freg[rs1]);
                else if (rs2_f == 1)
                    sprintf(buf, "fcvt.wu.s\t%s, %s", rv_xreg[rd], rv_freg[rs1]);
                else
                    sprintf(buf, "fcvt.?.s\t%s, %s", rv_xreg[rd], rv_freg[rs1]);
                break;
            case 0x1A: /* FCVT.S.W / FCVT.S.WU */
                if (rs2_f == 0)
                    sprintf(buf, "fcvt.s.w\t%s, %s", rv_freg[rd], rv_xreg[rs1]);
                else if (rs2_f == 1)
                    sprintf(buf, "fcvt.s.wu\t%s, %s", rv_freg[rd], rv_xreg[rs1]);
                else
                    sprintf(buf, "fcvt.s.?\t%s, %s", rv_freg[rd], rv_xreg[rs1]);
                break;
            case 0x1C: /* FMV.X.W / FCLASS.S */
                if (rm == 0)
                    sprintf(buf, "fmv.x.w\t%s, %s", rv_xreg[rd], rv_freg[rs1]);
                else if (rm == 1)
                    sprintf(buf, "fclass.s\t%s, %s", rv_xreg[rd], rv_freg[rs1]);
                else
                    sprintf(buf, "fmv/fclass?.s\t%s, %s", rv_xreg[rd], rv_freg[rs1]);
                break;
            case 0x1E: /* FMV.W.X */
                sprintf(buf, "fmv.w.x\t%s, %s", rv_freg[rd], rv_xreg[rs1]);
                break;
            default:
                sprintf(buf, "fop?.s\t0x%08x", instr);
                break;
            }
        } else {
            sprintf(buf, ".word\t0x%08x\t; float fmt=%d", instr, fmt);
        }
        stat_fpu++;
        return;
    }

    case 0x73: { // SYSTEM
        if (instr == 0x00000073) {
            sprintf(buf, "ecall");
        } else if (instr == 0x00100073) {
            sprintf(buf, "ebreak");
        } else if (instr == 0x10500073) {
            sprintf(buf, "wfi");
        } else if ((instr & 0xFE00707F) == 0x00001073) {
            /* CSRRW */
            int32_t csr = (instr >> 20) & 0xFFF;
            sprintf(buf, "csrrw\t%s, 0x%x, %s", rv_xreg[rd], csr, rv_xreg[rs1]);
        } else if ((instr & 0xFE00707F) == 0x00002073) {
            /* CSRRS */
            int32_t csr = (instr >> 20) & 0xFFF;
            if (rs1 == 0)
                sprintf(buf, "csrr\t%s, 0x%x", rv_xreg[rd], csr);
            else
                sprintf(buf, "csrrs\t%s, 0x%x, %s", rv_xreg[rd], csr, rv_xreg[rs1]);
        } else if ((instr & 0xFE00707F) == 0x00003073) {
            /* CSRRC */
            int32_t csr = (instr >> 20) & 0xFFF;
            sprintf(buf, "csrrc\t%s, 0x%x, %s", rv_xreg[rd], csr, rv_xreg[rs1]);
        } else {
            sprintf(buf, "system\t0x%08x", instr);
        }
        stat_system++;
        return;
    }

    case 0x0F: {
        sprintf(buf, "fence");
        stat_system++;
        return;
    }

    case 0x2F: {
        int funct5_a = (instr >> 27) & 0x1F;
        int aq = (instr >> 26) & 1;
        int rl = (instr >> 25) & 1;
        const char *mne;
        switch (funct5_a) {
        case 0x02: mne = "lr.w"; break;
        case 0x03: mne = "sc.w"; break;
        case 0x01: mne = "amoswap.w"; break;
        case 0x00: mne = "amoadd.w"; break;
        case 0x04: mne = "amoxor.w"; break;
        case 0x0C: mne = "amoand.w"; break;
        case 0x08: mne = "amoor.w"; break;
        case 0x10: mne = "amomin.w"; break;
        case 0x14: mne = "amomax.w"; break;
        case 0x18: mne = "amominu.w"; break;
        case 0x1C: mne = "amomaxu.w"; break;
        default: mne = "amo?.w"; break;
        }
        if (funct5_a == 0x02) {
            /* LR.W has no rs2 */
            sprintf(buf, "%s%s%s\t%s, (%s)", mne,
                    aq ? ".aq" : "", rl ? ".rl" : "",
                    rv_xreg[rd], rv_xreg[rs1]);
        } else {
            sprintf(buf, "%s%s%s\t%s, %s, (%s)", mne,
                    aq ? ".aq" : "", rl ? ".rl" : "",
                    rv_xreg[rd], rv_xreg[rs2], rv_xreg[rs1]);
        }
        stat_other++;
        return;
    }

    default:
        break;
    }

    /* Fallback */
    sprintf(buf, ".word\t0x%08x", instr);
    stat_other++;
}


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
    printf("=== Oberon Object File (RV32) ===\n");
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

    /* Entries */
    expect_tag(EntryTag);
    printf("\n--- Entries ---\n");
    nof_entries_stored = 0;
    for (int i = 0; i < nofEntries; i++) {
        int16_t entry = read_int16();
        printf("  [%d] offset=%d (0x%x)\n", i, entry, (unsigned)entry);
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

    expect_tag(ExportTag);
    printf("\n--- Export ---\n");
    {
        int16_t nofExp = read_int16();
        printf("  nofExports=%d\n", nofExp);
        /* Skip export data - complex nested format */
        int32_t fp;
        fp = read_num();
        while (fp != EUEnd) {
            if (fp == EURecord) {
                int32_t link = read_num();
                if (verbose) printf("  EURecord link=%d\n", link);
                /* Skip to end of record scope */
                if (link >= 0) {
                    int16_t nof = read_int16();
                    for (int j = 0; j < nof; j++)
                        read_num();
                }
            } else {
                /* object export */
                if (verbose) printf("  export fp=%d\n", fp);
                read_num(); /* adr or entry offset */
            }
            fp = read_num();
        }
    }

    /* Code */
    expect_tag(CodeTag);
    printf("\n--- Code (%d bytes, %d words) ---\n", codeSize, codeSize / 4);

    /* Reset statistics */
    stat_alu = stat_branch = stat_load = stat_store = 0;
    stat_mul = stat_fpu = stat_system = stat_other = 0;

    uint8_t *codeData = NULL;
    if (codeSize > 0) {
        codeData = (uint8_t *)malloc(codeSize);
        for (uint16_t i = 0; i < codeSize; i++)
            codeData[i] = (uint8_t)read_byte();

        /* RV32 instructions are 4-byte aligned words */
        if (codeSize >= 4 && (codeSize % 4 == 0)) {
            for (uint16_t i = 0; i < codeSize; i += 4) {
                /* Check for procedure boundary */
                int entry_idx = find_entry(i);
                if (entry_idx >= 0) {
                    printf("\n  ; ---- entry[%d] at 0x%04X ----\n", entry_idx, i);
                }

                uint32_t instr = (uint32_t)codeData[i] |
                                 ((uint32_t)codeData[i+1] << 8) |
                                 ((uint32_t)codeData[i+2] << 16) |
                                 ((uint32_t)codeData[i+3] << 24);
                char dis[256];
                disasm_rv32(i, instr, dis);
                printf("  %04X: %08X  %s\n", i, instr, dis);
            }
        } else {
            /* Hex dump for non-aligned code */
            for (uint16_t i = 0; i < codeSize; i += 16) {
                printf("  %04X:", i);
                for (int j = 0; j < 16 && i + j < codeSize; j++)
                    printf(" %02X", codeData[i + j]);
                printf("\n");
            }
        }

        /* Instruction statistics */
        int total = stat_alu + stat_branch + stat_load + stat_store +
                    stat_mul + stat_fpu + stat_system + stat_other;
        printf("\n  ; --- Instruction Statistics ---\n");
        printf("  ;   ALU/Immediate:   %d\n", stat_alu);
        printf("  ;   Branches/Jumps:  %d\n", stat_branch);
        printf("  ;   Loads:           %d\n", stat_load);
        printf("  ;   Stores:          %d\n", stat_store);
        printf("  ;   Multiply/Divide: %d\n", stat_mul);
        printf("  ;   Float (F ext):   %d\n", stat_fpu);
        printf("  ;   System:          %d\n", stat_system);
        printf("  ;   Other:           %d\n", stat_other);
        printf("  ;   Total:           %d\n", total);
    }

    /* Skip Use, Types, and Refs sections - just dump remaining bytes */
    printf("\n--- Remaining sections (Use/Types/Refs) ---\n");
    {
        long pos = ftell(f);
        fseek(f, 0, SEEK_END);
        long end = ftell(f);
        fseek(f, pos, SEEK_SET);
        long remaining = end - pos;
        printf("  %ld bytes remaining\n", remaining);
        if (verbose && remaining > 0) {
            uint8_t *rest = (uint8_t *)malloc(remaining);
            fread(rest, 1, remaining, f);
            for (long i = 0; i < remaining; i += 16) {
                printf("  %04lX:", i);
                for (int j = 0; j < 16 && i + j < remaining; j++)
                    printf(" %02X", rest[i + j]);
                printf("\n");
            }
            free(rest);
        }
    }

    if (constData) free(constData);
    if (codeData) free(codeData);
    fclose(f);
    return 0;
}
