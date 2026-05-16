(* OPO - RV32 Instruction Encoding Primitives 
   Provides low-level code emission for the RV32 backend 

  RV32 encoding: all instructions are 32-bit (4 bytes), little-endian.
  No compressed (C/Zc) extensions are used.

  RV32 instruction formats:
    R-type: funct7[31:25] | rs2[24:20] | rs1[19:15] | funct3[14:12] | rd[11:7] | opcode[6:0]
    I-type: imm[31:20] | rs1[19:15] | funct3[14:12] | rd[11:7] | opcode[6:0]
    S-type: imm[31:25] | rs2[24:20] | rs1[19:15] | funct3[14:12] | imm[11:7] | opcode[6:0]
    B-type: imm[12|10:5] | rs2[24:20] | rs1[19:15] | funct3[14:12] | imm[4:1|11] | opcode[6:0]
    U-type: imm[31:12] | rd[11:7] | opcode[6:0]
    J-type: imm[20|10:1|11|19:12] | rd[11:7] | opcode[6:0]
 
   Copyright 2026 Rochus Keller <mailto:me@rochus-keller.ch>

   GNU General Public License Usage
   This file may be used under the terms of the GNU General Public
   License (GPL) versions 2.0 or 3.0 as published by the Free Software
   Foundation and appearing in the file LICENSE.GPL included in
   the packaging of this file. Please review the following information
   to ensure GNU General Public Licensing requirements will be met:
   http://www.fsf.org/licensing/licenses/info/GPLv2.html and
   http://www.gnu.org/copyleft/gpl.html.
*)

MODULE OPO;
 IMPORT OPT, OPM, SYSTEM;

 CONST

 (* item modes for RV32 (must not overlap item basemodes, > 13) *)
  Reg* = 15; Abs* = 16; RegRel* = 17; Coc* = 18;

 (* mode and scale factors *)
  noScale* = 0; Scale1* = 0; Scale2* = 1; Scale4* = 2; Scale8* = 3;
  RegReg*  = 0; (* register to register *)
  RegMem*  = 1; (* register to memory *)
  MemReg*  = 2; (* memory to register *)
  ImmReg*  = 3; (* immediate to register *)
  ImmMem*  = 4; (* immediate to memory *)

 (* aliases *)
  Regs*  = RegReg;
  Mem*  = MemReg;
  Imme*  = ImmReg;

 (* code and data length per module *)
  CodeLength*  = 65000;
  MaxConstLength* = 64*1024;

 (* RV32 GPR numbers (x0..x31) *)
  X0* = 0;  (* hardwired zero *)
  X1* = 1;  RA* = 1;   (* return address *)
  X2* = 2;  SP* = 2;   (* stack pointer *)
  X3* = 3;  GP* = 3;   (* global pointer, reserved *)
  X4* = 4;  TP* = 4;   (* thread pointer, reserved *)
  X5* = 5;  T0* = 5;   (* scratch register, like ARM's IP *)
  X6* = 6;  T1* = 6;   (* temporary *)
  X7* = 7;  T2* = 7;   (* temporary *)
  X8* = 8;  S0* = 8; FP* = 8;  (* frame pointer *)
  X9* = 9;  S1* = 9;   (* saved register *)
  X10* = 10; A0* = 10;  (* argument/return value *)
  X11* = 11; A1* = 11;
  X12* = 12; A2* = 12;
  X13* = 13; A3* = 13;
  X14* = 14; A4* = 14;
  X15* = 15; A5* = 15;
  X16* = 16; A6* = 16;
  X17* = 17; A7* = 17;
  X18* = 18; S2* = 18;
  X19* = 19; S3* = 19;
  X20* = 20; S4* = 20;
  X21* = 21; S5* = 21;
  X22* = 22; S6* = 22;
  X23* = 23; S7* = 23;
  X24* = 24; S8* = 24;
  X25* = 25; S9* = 25;
  X26* = 26; S10* = 26;
  X27* = 27; S11* = 27;
  X28* = 28; T3* = 28;
  X29* = 29; T4* = 29;
  X30* = 30; T5* = 30;  (* comparison scratch 1 *)
  X31* = 31; T6* = 31;  (* comparison scratch 2 *)

 (* register/memory size indicators - match ARM32/i386 convention *)
  Bit8* = 1; Bit16* = 2; Bit32* = 0; Bit64* = 5;

 noDisp* = 0; none = -1;
 noBase* = none; noInx* = none; noImm* = 0;

 BUG = 42;

 (* RV32 opcodes, bits [6:0] *)
  opLUI*    = 037H;  (* U-type: load upper immediate *)
  opAUIPC*  = 017H;  (* U-type: add upper immediate to PC *)
  opJAL*    = 06FH;  (* J-type: jump and link *)
  opJALR*   = 067H;  (* I-type: jump and link register *)
  opBRANCH* = 063H;  (* B-type: conditional branch *)
  opLOAD*   = 003H;  (* I-type: load *)
  opSTORE*  = 023H;  (* S-type: store *)
  opOPIMM*  = 013H;  (* I-type: integer register-immediate *)
  opOP*     = 033H;  (* R-type: integer register-register *)
  opFLOAT*  = 007H;  (* I-type: float load (FLW) *)
  opFSTORE* = 027H;  (* S-type: float store (FSW) *)
  opFMADD*  = 043H;  (* R4-type: fused multiply-add *)
  opFOP*    = 053H;  (* R-type: float operation *)
  opSYSTEM* = 073H;  (* I-type: system (ECALL, EBREAK) *)
  opFENCE*  = 00FH;  (* I-type: fence *)
  opAMO*    = 02FH;  (* R-type: atomic memory operation *)

 (* Branch funct3 codes *)
  fBEQ*  = 0;  (* branch equal *)
  fBNE*  = 1;  (* branch not equal *)
  fBLT*  = 4;  (* branch less than, signed *)
  fBGE*  = 5;  (* branch greater or equal, signed *)
  fBLTU* = 6;  (* branch less than, unsigned *)
  fBGEU* = 7;  (* branch greater or equal, unsigned *)

 (* Load funct3 codes *)
  fLB*  = 0;  (* load byte, sign-extend *)
  fLH*  = 1;  (* load halfword, sign-extend *)
  fLW*  = 2;  (* load word *)
  fLBU* = 4;  (* load byte, zero-extend *)
  fLHU* = 5;  (* load halfword, zero-extend *)

 (* Store funct3 codes *)
  fSB* = 0;  (* store byte *)
  fSH* = 1;  (* store halfword *)
  fSW* = 2;  (* store word *)

 (* ALU funct3 codes (for OP-IMM and OP) *)
  fADD*  = 0;  (* add (also SUB with funct7=0x20) *)
  fSLL*  = 1;  (* shift left logical *)
  fSLT*  = 2;  (* set less than, signed *)
  fSLTU* = 3;  (* set less than, unsigned *)
  fXOR*  = 4;
  fSRL*  = 5;  (* shift right logical (also SRA with funct7=0x20) *)
  fOR*   = 6;
  fAND*  = 7;

 (* funct7 values *)
  f7ZERO* = 000H;  (* normal ALU ops *)
  f7SUB*  = 020H;  (* SUB, SRA *)
  f7MUL*  = 001H;  (* M extension: MUL, DIV, REM *)

 (* M extension funct3 codes (funct7 = 0x01) *)
  fMUL*    = 0;
  fMULH*   = 1;
  fMULHSU* = 2;
  fMULHU*  = 3;
  fDIV*    = 4;
  fDIVU*   = 5;
  fREM*    = 6;
  fREMU*   = 7;

 (* F extension funct7/funct5/rm codes *)
  f7FADDS*  = 000H;  (* FADD.S *)
  f7FSUBS*  = 004H;  (* FSUB.S *)
  f7FMULS*  = 008H;  (* FMUL.S *)
  f7FDIVS*  = 00CH;  (* FDIV.S *)
  f7FSQRTS* = 02CH;  (* FSQRT.S *)
  f7FSGN*   = 010H;  (* FSGNJ/FSGNJN/FSGNJX *)
  f7FMINMAX* = 014H; (* FMIN/FMAX *)
  f7FCVTWS* = 060H;  (* FCVT.W.S / FCVT.WU.S *)
  f7FMVXW*  = 070H;  (* FMV.X.W / FCLASS.S *)
  f7FCMPS*  = 050H;  (* FEQ/FLT/FLE *)
  f7FCVTSW* = 068H;  (* FCVT.S.W / FCVT.S.WU *)
  f7FMVWX*  = 078H;  (* FMV.W.X *)

 (* Float rounding modes (rm field, bits [14:12]) *)
  rmRNE* = 0;  (* round to nearest, ties to even *)
  rmRTZ* = 1;  (* round towards zero *)
  rmRDN* = 2;  (* round down (toward -infinity) *)
  rmRUP* = 3;  (* round up (toward +infinity) *)
  rmRMM* = 4;  (* round to nearest, ties to max magnitude *)
  rmDYN* = 7;  (* dynamic rounding mode from FCSR *)

 (* Internal condition codes for comparison/branch mechanism.
    These encode what RV32 branch instruction to emit.
    Used in forward branch fixups. *)
  ccEQ*  = 0;   (* BEQ t5, t6 *)
  ccNE*  = 1;   (* BNE t5, t6 *)
  ccLT*  = 2;   (* BLT t5, t6 *)
  ccGE*  = 3;   (* BGE t5, t6 *)
  ccGT*  = 4;   (* BLT t6, t5 ? swapped *)
  ccLE*  = 5;   (* BGE t6, t5 ? swapped *)
  ccHI*  = 6;   (* BLTU t6, t5 ? unsigned higher, swapped *)
  ccHS*  = 7;   (* BGEU t5, t6 ? unsigned higher or same *)
  ccLO*  = 8;   (* BLTU t5, t6 ? unsigned lower *)
  ccLS*  = 9;   (* BGEU t6, t5 ? unsigned lower or same, swapped *)
  ccCS*  = 10;  (* BLTU t5, t6 ? carry set = unsigned lower *)
  ccCC*  = 11;  (* BGEU t5, t6 ? carry clear = unsigned higher or same *)
  ccAL*  = 255; (* unconditional: JAL x0 *)

 TYPE
  ConstArray* = POINTER TO ARRAY OF CHAR;

 VAR
 pc*, dsize*: LONGINT;   (* code size in bytes, data size *)
 csize*: LONGINT;  (* constant size *)
 lastImmSize*: SHORTINT;
 constant*: ConstArray;
 code*: ARRAY CodeLength OF CHAR;
 CodeErr*: BOOLEAN;


 PROCEDURE PutByte*(b: LONGINT);
 BEGIN
  IF pc < CodeLength THEN
   code[pc] := CHR(b MOD 256); INC(pc)
  ELSE
   IF ~CodeErr THEN OPM.err(210); CodeErr := TRUE END
  END
 END PutByte;

 PROCEDURE PutWord*(w: LONGINT);
 (* Emit a 32-bit word in little-endian byte order *)
 BEGIN
  PutByte(w MOD 100H);
  PutByte(w DIV 100H MOD 100H);
  PutByte(w DIV 10000H MOD 100H);
  PutByte(w DIV 1000000H MOD 100H)
 END PutWord;

 PROCEDURE PutWordAt*(pos: LONGINT; w: LONGINT);
 (* Patch a 32-bit word at a given position *)
 BEGIN
  code[pos] := CHR(w MOD 100H);
  code[pos+1] := CHR(w DIV 100H MOD 100H);
  code[pos+2] := CHR(w DIV 10000H MOD 100H);
  code[pos+3] := CHR(w DIV 1000000H MOD 100H)
 END PutWordAt;

 PROCEDURE GetWord*(pos: LONGINT; VAR w: LONGINT);
 (* Read a 32-bit word from a given position (little-endian) *)
 BEGIN
  w := ORD(code[pos]) + ORD(code[pos+1]) * 100H +
       ORD(code[pos+2]) * 10000H + ORD(code[pos+3]) * 1000000H
 END GetWord;

 PROCEDURE PutByteAt*(pos: LONGINT; b: INTEGER);
 BEGIN
  code[pos] := CHR(b MOD 256)
 END PutByteAt;

 PROCEDURE PutDWord*(w: LONGINT);
 BEGIN PutWord(w)
 END PutDWord;

 PROCEDURE PutDWordAt*(pos: LONGINT; w: LONGINT);
 BEGIN PutWordAt(pos, w)
 END PutDWordAt;

 PROCEDURE GetDWord*(pos: LONGINT; VAR w: LONGINT);
 BEGIN GetWord(pos, w)
 END GetDWord;


 PROCEDURE PutConsDWord*(pos: LONGINT; val: LONGINT);
 BEGIN
  constant[pos] := CHR(val MOD 100H);
  constant[pos+1] := CHR(val DIV 100H MOD 100H);
  constant[pos+2] := CHR(val DIV 10000H MOD 100H);
  constant[pos+3] := CHR(val DIV 1000000H MOD 100H)
 END PutConsDWord;

 PROCEDURE GetConsDWord*(pos: LONGINT; VAR val: LONGINT);
 BEGIN
  val := ORD(constant[pos]) + ORD(constant[pos+1]) * 100H +
         ORD(constant[pos+2]) * 10000H + ORD(constant[pos+3]) * 1000000H
 END GetConsDWord;


 PROCEDURE GenRType*(opcode, rd, funct3, rs1, rs2, funct7: LONGINT);
 BEGIN
  PutWord(
   (funct7 MOD 80H) * 2000000H +
   (rs2 MOD 20H) * 100000H +
   (rs1 MOD 20H) * 8000H +
   (funct3 MOD 8) * 1000H +
   (rd MOD 20H) * 80H +
   (opcode MOD 80H)
  )
 END GenRType;

 PROCEDURE GenIType*(opcode, rd, funct3, rs1, imm12: LONGINT);
 BEGIN
  PutWord(
   (imm12 MOD 1000H) * 100000H +
   (rs1 MOD 20H) * 8000H +
   (funct3 MOD 8) * 1000H +
   (rd MOD 20H) * 80H +
   (opcode MOD 80H)
  )
 END GenIType;

 PROCEDURE GenSType*(opcode, funct3, rs1, rs2, imm12: LONGINT);
  VAR immLo, immHi: LONGINT;
 BEGIN
  immLo := imm12 MOD 20H;        (* bits [4:0] *)
  immHi := (imm12 DIV 20H) MOD 80H; (* bits [11:5] *)
  PutWord(
   immHi * 2000000H +
   (rs2 MOD 20H) * 100000H +
   (rs1 MOD 20H) * 8000H +
   (funct3 MOD 8) * 1000H +
   immLo * 80H +
   (opcode MOD 80H)
  )
 END GenSType;

 PROCEDURE GenBType*(opcode, funct3, rs1, rs2, imm13: LONGINT);
  VAR b12, b11, bA, bB: LONGINT;
 BEGIN
  b12 := (imm13 DIV 1000H) MOD 2;   (* bit 12 *)
  b11 := (imm13 DIV 800H) MOD 2;    (* bit 11 *)
  bA  := (imm13 DIV 20H) MOD 40H;   (* bits 10:5 *)
  bB  := (imm13 DIV 2) MOD 10H;     (* bits 4:1 *)
  PutWord(
   b12 * 80000000H +
   bA * 2000000H +
   (rs2 MOD 20H) * 100000H +
   (rs1 MOD 20H) * 8000H +
   (funct3 MOD 8) * 1000H +
   bB * 100H +
   b11 * 80H +
   (opcode MOD 80H)
  )
 END GenBType;

 PROCEDURE GenUType*(opcode, rd, imm20: LONGINT);
 BEGIN
  PutWord(
   (imm20 MOD 100000H) * 1000H +
   (rd MOD 20H) * 80H +
   (opcode MOD 80H)
  )
 END GenUType;

 PROCEDURE GenJType*(opcode, rd, imm21: LONGINT);
  VAR b20, bC, b11, bD: LONGINT;
 BEGIN
  b20 := (imm21 DIV 100000H) MOD 2;  (* bit 20 *)
  bC  := (imm21 DIV 1000H) MOD 100H; (* bits 19:12 *)
  b11 := (imm21 DIV 800H) MOD 2;     (* bit 11 *)
  bD  := (imm21 DIV 2) MOD 400H;     (* bits 10:1 *)
  PutWord(
   b20 * 80000000H +
   bD * 200000H +
   b11 * 100000H +
   bC * 1000H +
   (rd MOD 20H) * 80H +
   (opcode MOD 80H)
  )
 END GenJType;


 PROCEDURE GenADD*(rd, rs1, rs2: LONGINT);
 BEGIN GenRType(opOP, rd, fADD, rs1, rs2, f7ZERO)
 END GenADD;

 PROCEDURE GenSUB*(rd, rs1, rs2: LONGINT);
 BEGIN GenRType(opOP, rd, fADD, rs1, rs2, f7SUB)
 END GenSUB;

 PROCEDURE GenAND*(rd, rs1, rs2: LONGINT);
 BEGIN GenRType(opOP, rd, fAND, rs1, rs2, f7ZERO)
 END GenAND;

 PROCEDURE GenOR*(rd, rs1, rs2: LONGINT);
 BEGIN GenRType(opOP, rd, fOR, rs1, rs2, f7ZERO)
 END GenOR;

 PROCEDURE GenXOR*(rd, rs1, rs2: LONGINT);
 BEGIN GenRType(opOP, rd, fXOR, rs1, rs2, f7ZERO)
 END GenXOR;

 PROCEDURE GenSLL*(rd, rs1, rs2: LONGINT);
 BEGIN GenRType(opOP, rd, fSLL, rs1, rs2, f7ZERO)
 END GenSLL;

 PROCEDURE GenSRL*(rd, rs1, rs2: LONGINT);
 BEGIN GenRType(opOP, rd, fSRL, rs1, rs2, f7ZERO)
 END GenSRL;

 PROCEDURE GenSRA*(rd, rs1, rs2: LONGINT);
 BEGIN GenRType(opOP, rd, fSRL, rs1, rs2, f7SUB)
 END GenSRA;

 PROCEDURE GenSLT*(rd, rs1, rs2: LONGINT);
 BEGIN GenRType(opOP, rd, fSLT, rs1, rs2, f7ZERO)
 END GenSLT;

 PROCEDURE GenSLTU*(rd, rs1, rs2: LONGINT);
 BEGIN GenRType(opOP, rd, fSLTU, rs1, rs2, f7ZERO)
 END GenSLTU;


 PROCEDURE GenADDI*(rd, rs1, imm: LONGINT);
 BEGIN GenIType(opOPIMM, rd, fADD, rs1, imm)
 END GenADDI;

 PROCEDURE GenANDI*(rd, rs1, imm: LONGINT);
 BEGIN GenIType(opOPIMM, rd, fAND, rs1, imm)
 END GenANDI;

 PROCEDURE GenORI*(rd, rs1, imm: LONGINT);
 BEGIN GenIType(opOPIMM, rd, fOR, rs1, imm)
 END GenORI;

 PROCEDURE GenXORI*(rd, rs1, imm: LONGINT);
 BEGIN GenIType(opOPIMM, rd, fXOR, rs1, imm)
 END GenXORI;

 PROCEDURE GenSLTI*(rd, rs1, imm: LONGINT);
 BEGIN GenIType(opOPIMM, rd, fSLT, rs1, imm)
 END GenSLTI;

 PROCEDURE GenSLTIU*(rd, rs1, imm: LONGINT);
 BEGIN GenIType(opOPIMM, rd, fSLTU, rs1, imm)
 END GenSLTIU;

 PROCEDURE GenSLLI*(rd, rs1, shamt: LONGINT);
 BEGIN GenIType(opOPIMM, rd, fSLL, rs1, shamt MOD 20H)
 END GenSLLI;

 PROCEDURE GenSRLI*(rd, rs1, shamt: LONGINT);
 BEGIN GenIType(opOPIMM, rd, fSRL, rs1, shamt MOD 20H)
 END GenSRLI;

 PROCEDURE GenSRAI*(rd, rs1, shamt: LONGINT);
 BEGIN GenIType(opOPIMM, rd, fSRL, rs1, 400H + shamt MOD 20H)
 END GenSRAI;


 PROCEDURE GenLUI*(rd, imm20: LONGINT);
 BEGIN GenUType(opLUI, rd, imm20)
 END GenLUI;

 PROCEDURE GenAUIPC*(rd, imm20: LONGINT);
 BEGIN GenUType(opAUIPC, rd, imm20)
 END GenAUIPC;


 PROCEDURE GenJAL*(rd, offset: LONGINT);
 BEGIN GenJType(opJAL, rd, offset)
 END GenJAL;

 PROCEDURE GenJALR*(rd, rs1, offset: LONGINT);
 BEGIN GenIType(opJALR, rd, 0, rs1, offset)
 END GenJALR;


 PROCEDURE GenBEQ*(rs1, rs2, offset: LONGINT);
 BEGIN GenBType(opBRANCH, fBEQ, rs1, rs2, offset)
 END GenBEQ;

 PROCEDURE GenBNE*(rs1, rs2, offset: LONGINT);
 BEGIN GenBType(opBRANCH, fBNE, rs1, rs2, offset)
 END GenBNE;

 PROCEDURE GenBLT*(rs1, rs2, offset: LONGINT);
 BEGIN GenBType(opBRANCH, fBLT, rs1, rs2, offset)
 END GenBLT;

 PROCEDURE GenBGE*(rs1, rs2, offset: LONGINT);
 BEGIN GenBType(opBRANCH, fBGE, rs1, rs2, offset)
 END GenBGE;

 PROCEDURE GenBLTU*(rs1, rs2, offset: LONGINT);
 BEGIN GenBType(opBRANCH, fBLTU, rs1, rs2, offset)
 END GenBLTU;

 PROCEDURE GenBGEU*(rs1, rs2, offset: LONGINT);
 BEGIN GenBType(opBRANCH, fBGEU, rs1, rs2, offset)
 END GenBGEU;


 PROCEDURE GenLW*(rd, rs1, offset: LONGINT);
 BEGIN GenIType(opLOAD, rd, fLW, rs1, offset)
 END GenLW;

 PROCEDURE GenLH*(rd, rs1, offset: LONGINT);
 BEGIN GenIType(opLOAD, rd, fLH, rs1, offset)
 END GenLH;

 PROCEDURE GenLHU*(rd, rs1, offset: LONGINT);
 BEGIN GenIType(opLOAD, rd, fLHU, rs1, offset)
 END GenLHU;

 PROCEDURE GenLB*(rd, rs1, offset: LONGINT);
 BEGIN GenIType(opLOAD, rd, fLB, rs1, offset)
 END GenLB;

 PROCEDURE GenLBU*(rd, rs1, offset: LONGINT);
 BEGIN GenIType(opLOAD, rd, fLBU, rs1, offset)
 END GenLBU;


 PROCEDURE GenSW*(rs2, rs1, offset: LONGINT);
 BEGIN GenSType(opSTORE, fSW, rs1, rs2, offset)
 END GenSW;

 PROCEDURE GenSH*(rs2, rs1, offset: LONGINT);
 BEGIN GenSType(opSTORE, fSH, rs1, rs2, offset)
 END GenSH;

 PROCEDURE GenSB*(rs2, rs1, offset: LONGINT);
 BEGIN GenSType(opSTORE, fSB, rs1, rs2, offset)
 END GenSB;


 PROCEDURE GenMUL*(rd, rs1, rs2: LONGINT);
 BEGIN GenRType(opOP, rd, fMUL, rs1, rs2, f7MUL)
 END GenMUL;

 PROCEDURE GenMULH*(rd, rs1, rs2: LONGINT);
 BEGIN GenRType(opOP, rd, fMULH, rs1, rs2, f7MUL)
 END GenMULH;

 PROCEDURE GenDIV*(rd, rs1, rs2: LONGINT);
 BEGIN GenRType(opOP, rd, fDIV, rs1, rs2, f7MUL)
 END GenDIV;

 PROCEDURE GenDIVU*(rd, rs1, rs2: LONGINT);
 BEGIN GenRType(opOP, rd, fDIVU, rs1, rs2, f7MUL)
 END GenDIVU;

 PROCEDURE GenREM*(rd, rs1, rs2: LONGINT);
 BEGIN GenRType(opOP, rd, fREM, rs1, rs2, f7MUL)
 END GenREM;

 PROCEDURE GenREMU*(rd, rs1, rs2: LONGINT);
 BEGIN GenRType(opOP, rd, fREMU, rs1, rs2, f7MUL)
 END GenREMU;


 PROCEDURE GenFLW*(rd, rs1, offset: LONGINT);
 BEGIN GenIType(opFLOAT, rd, fLW, rs1, offset)
 END GenFLW;

 PROCEDURE GenFSW*(rs2, rs1, offset: LONGINT);
 BEGIN GenSType(opFSTORE, fSW, rs1, rs2, offset)
 END GenFSW;

 PROCEDURE GenFADDS*(rd, rs1, rs2: LONGINT);
 BEGIN GenRType(opFOP, rd, rmDYN, rs1, rs2, f7FADDS)
 END GenFADDS;

 PROCEDURE GenFSUBS*(rd, rs1, rs2: LONGINT);
 BEGIN GenRType(opFOP, rd, rmDYN, rs1, rs2, f7FSUBS)
 END GenFSUBS;

 PROCEDURE GenFMULS*(rd, rs1, rs2: LONGINT);
 BEGIN GenRType(opFOP, rd, rmDYN, rs1, rs2, f7FMULS)
 END GenFMULS;

 PROCEDURE GenFDIVS*(rd, rs1, rs2: LONGINT);
 BEGIN GenRType(opFOP, rd, rmDYN, rs1, rs2, f7FDIVS)
 END GenFDIVS;

 PROCEDURE GenFSGNJS*(rd, rs1, rs2: LONGINT);
 BEGIN GenRType(opFOP, rd, 0, rs1, rs2, f7FSGN)
 END GenFSGNJS;

 PROCEDURE GenFSGNJNS*(rd, rs1, rs2: LONGINT);
 BEGIN GenRType(opFOP, rd, 1, rs1, rs2, f7FSGN)
 END GenFSGNJNS;

 PROCEDURE GenFSGNJXS*(rd, rs1, rs2: LONGINT);
 BEGIN GenRType(opFOP, rd, 2, rs1, rs2, f7FSGN)
 END GenFSGNJXS;

 PROCEDURE GenFEQS*(rd, rs1, rs2: LONGINT);
 BEGIN GenRType(opFOP, rd, 2, rs1, rs2, f7FCMPS)
 END GenFEQS;

 PROCEDURE GenFLTS*(rd, rs1, rs2: LONGINT);
 BEGIN GenRType(opFOP, rd, 1, rs1, rs2, f7FCMPS)
 END GenFLTS;

 PROCEDURE GenFLES*(rd, rs1, rs2: LONGINT);
 BEGIN GenRType(opFOP, rd, 0, rs1, rs2, f7FCMPS)
 END GenFLES;

 PROCEDURE GenFCVTWS*(rd, rs1, rm: LONGINT);
 BEGIN GenRType(opFOP, rd, rm, rs1, 0, f7FCVTWS)
 END GenFCVTWS;

 PROCEDURE GenFCVTSW*(rd, rs1, rm: LONGINT);
 BEGIN GenRType(opFOP, rd, rm, rs1, 0, f7FCVTSW)
 END GenFCVTSW;

 PROCEDURE GenFMVXW*(rd, rs1: LONGINT);
 BEGIN GenRType(opFOP, rd, 0, rs1, 0, f7FMVXW)
 END GenFMVXW;

 PROCEDURE GenFMVWX*(rd, rs1: LONGINT);
 BEGIN GenRType(opFOP, rd, 0, rs1, 0, f7FMVWX)
 END GenFMVWX;


 PROCEDURE GenECALL*;
 BEGIN GenIType(opSYSTEM, 0, 0, 0, 0)
 END GenECALL;

 PROCEDURE GenEBREAK*;
 BEGIN GenIType(opSYSTEM, 0, 0, 0, 1)
 END GenEBREAK;

 PROCEDURE GenFENCE*;
 BEGIN GenIType(opFENCE, 0, 0, 0, 0FFH)
 END GenFENCE;

 PROCEDURE GenWFI*;
 BEGIN PutWord(010500073H)
 END GenWFI;


 PROCEDURE GenNOP*;
 BEGIN GenADDI(X0, X0, 0)
 END GenNOP;


 PROCEDURE GenMOV*(rd, rs: LONGINT);
 BEGIN
  IF rd # rs THEN GenADDI(rd, rs, 0) END
 END GenMOV;


 PROCEDURE LoadImm32*(rd, imm: LONGINT);
  VAR lo12, hi20: LONGINT;
 BEGIN
  IF (imm >= -2048) & (imm <= 2047) THEN
   (* Fits in 12-bit signed immediate *)
   GenADDI(rd, X0, imm)
  ELSE
   (* Split into upper 20 and lower 12 bits *)
   lo12 := imm MOD 1000H;
   IF lo12 >= 800H THEN lo12 := lo12 - 1000H END; (* sign-extend lower 12 *)
   hi20 := (imm - lo12) DIV 1000H;
   (* hi20 is the upper 20 bits; lo12 is the signed lower 12 *)
   GenLUI(rd, hi20 MOD 100000H);
   IF lo12 # 0 THEN
    GenADDI(rd, rd, lo12)
   END
  END
 END LoadImm32;

 PROCEDURE EmitAbsLoad*(rd, disp: LONGINT; VAR slotOffset: LONGINT);
 (* Load a relocatable absolute address into register rd. *)
 BEGIN
  GenAUIPC(rd, 0);
  GenLW(rd, rd, 12);
  GenJAL(X0, 8);
  PutWord(disp);
  slotOffset := pc - 4
 END EmitAbsLoad;


 PROCEDURE EmitCondBranch*(cc: LONGINT; offset: LONGINT);
 BEGIN
  CASE cc OF
   ccEQ: GenBEQ(T5, T6, offset)
  | ccNE: GenBNE(T5, T6, offset)
  | ccLT: GenBLT(T5, T6, offset)
  | ccGE: GenBGE(T5, T6, offset)
  | ccGT: GenBLT(T6, T5, offset)      (* swapped *)
  | ccLE: GenBGE(T6, T5, offset)      (* swapped *)
  | ccHI: GenBLTU(T6, T5, offset)     (* unsigned higher, swapped *)
  | ccHS: GenBGEU(T5, T6, offset)     (* unsigned higher or same *)
  | ccLO: GenBLTU(T5, T6, offset)     (* unsigned lower *)
  | ccLS: GenBGEU(T6, T5, offset)     (* unsigned lower or same, swapped *)
  | ccCS: GenBLTU(T5, T6, offset)     (* carry set *)
  | ccCC: GenBGEU(T5, T6, offset)     (* carry clear *)
  ELSE HALT(BUG)
  END
 END EmitCondBranch;

 PROCEDURE InvertCC*(cc: LONGINT): LONGINT;
 BEGIN
  CASE cc OF
   ccEQ: RETURN ccNE
  | ccNE: RETURN ccEQ
  | ccLT: RETURN ccGE
  | ccGE: RETURN ccLT
  | ccGT: RETURN ccLE
  | ccLE: RETURN ccGT
  | ccHI: RETURN ccLS
  | ccHS: RETURN ccLO
  | ccLO: RETURN ccHS
  | ccLS: RETURN ccHI
  | ccCS: RETURN ccCC
  | ccCC: RETURN ccCS
  ELSE HALT(BUG); RETURN ccEQ
  END
 END InvertCC;

 PROCEDURE EmitCondBranchAt*(pos: LONGINT; cc: LONGINT; offset: LONGINT);
  VAR savedPC: LONGINT;
 BEGIN
  savedPC := pc;
  pc := pos;
  EmitCondBranch(cc, offset);
  pc := savedPC
 END EmitCondBranchAt;

  PROCEDURE ExtractJImm*(pos: LONGINT; VAR imm: LONGINT);
  VAR w, b31: LONGINT;
 BEGIN
  GetWord(pos, w);
  (* Extract bit 31 using SET to avoid fragile "w DIV 80000000H" which
     breaks when o2c promotes to int64 via OBERON$DIV *)
  IF 31 IN SYSTEM.VAL(SET, w) THEN b31 := 1 ELSE b31 := 0 END;
  imm := b31 * 100000H                            (* bit 31 -> imm[20] *)
       + ((w DIV 200000H) MOD 400H) * 2          (* bits 30:21 -> imm[10:1] *)
       + ((w DIV 100000H) MOD 2) * 800H          (* bit 20 -> imm[11] *)
       + ((w DIV 1000H) MOD 100H) * 1000H;       (* bits 19:12 -> imm[19:12] *)
  IF imm >= 100000H THEN imm := imm - 200000H END  (* sign extend 21 bits *)
 END ExtractJImm;

  PROCEDURE EmitJALAt*(pos: LONGINT; rd, offset: LONGINT);
  VAR savedPC: LONGINT;
 BEGIN
  savedPC := pc;
  pc := pos;
  GenJAL(rd, offset);
  pc := savedPC
 END EmitJALAt;

 PROCEDURE EmitChainJAL*(rd, chainVal: LONGINT);
 (* Store chain value in raw bits[31:12] of a JAL instruction.
    Chain values are internal compiler bookkeeping, NOT real code offsets.
    They must NOT go through J-type encoding which scrambles bits. *)
 BEGIN
  PutWord(ASH(chainVal MOD 100000H, 12) + (rd MOD 20H) * 80H + 6FH)
 END EmitChainJAL;

 PROCEDURE EmitChainJALAt*(pos: LONGINT; rd, chainVal: LONGINT);
  VAR savedPC: LONGINT;
 BEGIN
  savedPC := pc;
  pc := pos;
  EmitChainJAL(rd, chainVal);
  pc := savedPC
 END EmitChainJALAt;

 PROCEDURE ExtractChainVal*(pos: LONGINT; VAR val: LONGINT);
 (* Read chain value from raw bits[31:12] of instruction at pos.
    Returns the sign-extended 20-bit chain value. *)
  VAR w: LONGINT;
 BEGIN
  GetWord(pos, w);
  val := w DIV 1000H;
  IF val >= 80000H THEN val := val - 100000H END
 END ExtractChainVal;

 PROCEDURE EmitNOPAt*(pos: LONGINT);
  VAR savedPC: LONGINT;
 BEGIN
  savedPC := pc;
  pc := pos;
  GenNOP;
  pc := savedPC
 END EmitNOPAt;


 PROCEDURE InlineCode*(VAR asmCode: ARRAY OF CHAR; parSize: INTEGER);
  VAR i, n: INTEGER;
 BEGIN
  n := ORD(asmCode[0]); i := 1;
  WHILE i <= n DO PutByte(ORD(asmCode[i])); INC(i) END
 END InlineCode;

BEGIN
 NEW(constant, 1024)
END OPO.
