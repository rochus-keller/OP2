(* OPL - RV32 Code Generator (translation from Pseudo RISC to RV32)
   RV32 backend for the OP2 Oberon-90 compiler

   Architecture: RV32IMAF (32-bit RISC-V with Integer, Multiply, Atomic, Float extensions)
   for the Olimex ESP32-P4-PC board
   FPU: Single-precision hardware (f0-f31), double-precision soft-float via SysFix
   Calling convention: stack-based, callee-cleans
     - All parameters on stack, right-to-left
     - Prologue: ADDI sp,sp,-8; SW ra,4(sp); SW s0,0(sp); MV s0,sp; ADDI sp,sp,-locSize
     - Epilogue: MV sp,s0; LW s0,0(sp); LW ra,4(sp); ADDI sp,sp,8+parSize; JALR zero,ra,0
     - Return values: a0 (int/ptr), fa0 (REAL), a0+a1 (LONGREAL)
  Register allocation:
    - Allocatable GPRs: a0-a7 (x10-x17), t1-t4 (x6-x7, x28-x29), s1 (x9)
    - s0/FP (x8): frame pointer - dedicated
    - t0 (x5): scratch - used for large immediates/indexed addressing
    - t5/t6 (x30-x31): comparison scratch registers
    - sp (x2): stack pointer - dedicated
    - ra (x1): return address - dedicated
  FPU registers: f0-f31 (single-precision)
    - Allocate from f1 upward (f0/fa0 reserved for return values)

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

MODULE OPL; (** non-portable *)
 IMPORT OPT, OPIR, OPO, OPM, SYSTEM;

 CONST
  NewRef = TRUE;

  (* Aliases for OPIR opcodes - short form (divided by 32) *)
  Ld = OPIR.ld DIV 32; Ldbdw = OPIR.ldbdw DIV 32; Ldwdw = OPIR.ldwdw DIV 32;
  Ldbw = OPIR.ldbw DIV 32;
  Ldbdwu* = OPIR.ldbdwu DIV 32; Ldwdwu* = OPIR.ldwdwu DIV 32;
  Ldbwu* = OPIR.ldbwu DIV 32; GETreg* = OPIR.getReg DIV 32;
  PUTreg* = OPIR.putReg DIV 32; LdProc = OPIR.ldProc DIV 32;
  LdXProc = OPIR.ldXProc DIV 32; Lea = OPIR.lea DIV 32;
  Sto = OPIR.store DIV 32; Push = OPIR.push DIV 32; Pop = OPIR.pop DIV 32;
  Add = OPIR.add DIV 32; Sub = OPIR.sub DIV 32; Mul = OPIR.mul DIV 32;
  Div = OPIR.div DIV 32; Mod = OPIR.mod DIV 32;
  Neg = OPIR.neg DIV 32; Abso = OPIR.abs DIV 32; Cmp = OPIR.cmp DIV 32;
  Je = OPIR.je DIV 32; Jne = OPIR.jne DIV 32; Jl = OPIR.jl DIV 32;
  Jle = OPIR.jle DIV 32; Jg = OPIR.jg DIV 32; Jge = OPIR.jge DIV 32;
  Ja = OPIR.ja DIV 32; Jae = OPIR.jae DIV 32; Jb = OPIR.jb DIV 32;
  Jbe = OPIR.jbe DIV 32; Jc = OPIR.jc DIV 32; Jnc = OPIR.jnc DIV 32;
  Jmp = OPIR.jmp DIV 32; JmpReg = OPIR.jmpReg DIV 32;
  Sete = OPIR.sete DIV 32; Setne = OPIR.setne DIV 32;
  Setl = OPIR.setl DIV 32; Setle = OPIR.setle DIV 32;
  Setg = OPIR.setg DIV 32; Setge = OPIR.setge DIV 32;
  Seta = OPIR.seta DIV 32; Setae = OPIR.setae DIV 32;
  Setb = OPIR.setb DIV 32; Setbe = OPIR.setbe DIV 32;
  Setc = OPIR.setc DIV 32; Setnc = OPIR.setnc DIV 32;
  Te = OPIR.te DIV 32; Tne = OPIR.tne DIV 32; Tle = OPIR.tle DIV 32;
  Ta = OPIR.ta DIV 32; Tae = OPIR.tae DIV 32; To = OPIR.to DIV 32;
  Trap = OPIR.trap DIV 32;
  oR = OPIR.or DIV 32; Xor = OPIR.xor DIV 32; And = OPIR.and DIV 32;
  Not = OPIR.not DIV 32; Bt = OPIR.bt DIV 32; Btr = OPIR.btr DIV 32;
  Bts = OPIR.bts DIV 32; Test = OPIR.test DIV 32;
  Call = OPIR.call DIV 32; CallReg = OPIR.callReg DIV 32;
  Xcall = OPIR.xcall DIV 32; Ret = OPIR.ret DIV 32;
  Enter = OPIR.enter DIV 32; Leave = OPIR.leave DIV 32;
  Sal = OPIR.sal DIV 32; Sar = OPIR.sar DIV 32;
  Shr = OPIR.shr DIV 32; Rol = OPIR.rol DIV 32;
  Cld = OPIR.cld DIV 32; RepMovs = OPIR.repMovs DIV 32;
  CmpString = OPIR.cmpString DIV 32;
  PushReg = OPIR.pushReg DIV 32; PopReg = OPIR.popReg DIV 32;
  Case = OPIR.case DIV 32;
  Short* = OPIR.short DIV 32; Phi = OPIR.phi DIV 32;
  Label = OPIR.label DIV 32; Entier = OPIR.entier DIV 32;
  Cli = OPIR.cli DIV 32; Sti = OPIR.sti DIV 32;
  In = OPIR.in DIV 32; Out = OPIR.out DIV 32;
  Assembler = OPIR.assembler DIV 32;
  Clear = OPIR.clear DIV 32; Std = OPIR.std DIV 32;
  Dmb = OPIR.dmb DIV 32;
  FLoad = OPIR.fload DIV 32; FStore = OPIR.fstore DIV 32;
  Fist = OPIR.fist DIV 32; Fild = OPIR.fild DIV 32;
  Fadd = OPIR.fadd DIV 32; Fsub = OPIR.fsub DIV 32;
  Fmul = OPIR.fmul DIV 32; Fdiv = OPIR.fdiv DIV 32;
  Fabs = OPIR.fabs DIV 32; Fchs = OPIR.fchs DIV 32;
  Fcmp = OPIR.fcmp DIV 32;
  NewStat = OPIR.newStat DIV 32;

  (* Full opcode aliases for exported use *)
  ld* = OPIR.ld; ldbdw* = OPIR.ldbdw; ldwdw* = OPIR.ldwdw; ldbw* = OPIR.ldbw;
  ldbdwu* = OPIR.ldbdwu; ldwdwu* = OPIR.ldwdwu; ldbwu* = OPIR.ldbwu;
  getReg* = OPIR.getReg; putReg* = OPIR.putReg;
  ldProc* = OPIR.ldProc; ldXProc* = OPIR.ldXProc; lea* = OPIR.lea;
  store* = OPIR.store; push* = OPIR.push; pop* = OPIR.pop;
  add* = OPIR.add; sub* = OPIR.sub; mul* = OPIR.mul;
  div* = OPIR.div; mod* = OPIR.mod;
  neg* = OPIR.neg; abs* = OPIR.abs; cmp* = OPIR.cmp;
  je* = OPIR.je; jne* = OPIR.jne; jl* = OPIR.jl; jle* = OPIR.jle;
  jg* = OPIR.jg; jge* = OPIR.jge; ja* = OPIR.ja; jae* = OPIR.jae;
  jb* = OPIR.jb; jbe* = OPIR.jbe; jc* = OPIR.jc; jnc* = OPIR.jnc;
  jmp* = OPIR.jmp; jmpReg* = OPIR.jmpReg;
  sete* = OPIR.sete; setne* = OPIR.setne; setl* = OPIR.setl;
  setle* = OPIR.setle; setg* = OPIR.setg; setge* = OPIR.setge;
  seta* = OPIR.seta; setae* = OPIR.setae; setb* = OPIR.setb;
  setbe* = OPIR.setbe; setc* = OPIR.setc; setnc* = OPIR.setnc;
  te* = OPIR.te; tne* = OPIR.tne; tle* = OPIR.tle;
  ta* = OPIR.ta; tae* = OPIR.tae; to* = OPIR.to;
  trap* = OPIR.trap; or* = OPIR.or; xor* = OPIR.xor; and* = OPIR.and;
  not* = OPIR.not; bt* = OPIR.bt; btr* = OPIR.btr; bts* = OPIR.bts;
  test* = OPIR.test;
  call* = OPIR.call; callReg* = OPIR.callReg; xcall* = OPIR.xcall;
  ret* = OPIR.ret; enter* = OPIR.enter; leave* = OPIR.leave;
  sal* = OPIR.sal; sar* = OPIR.sar; shr* = OPIR.shr; rol* = OPIR.rol;
  cld* = OPIR.cld; repMovs* = OPIR.repMovs; cmpString* = OPIR.cmpString;
  pushReg* = OPIR.pushReg; popReg* = OPIR.popReg; case* = OPIR.case;
  short* = OPIR.short; phi* = OPIR.phi; label* = OPIR.label;
  entier* = OPIR.entier;
  cli* = OPIR.cli; sti* = OPIR.sti; in* = OPIR.in; out* = OPIR.out;
  assembler* = OPIR.assembler;
  clear* = OPIR.clear; std* = OPIR.std; dmb* = OPIR.dmb;
  fload* = OPIR.fload; fstore* = OPIR.fstore; fist* = OPIR.fist;
  fild* = OPIR.fild; fadd* = OPIR.fadd; fsub* = OPIR.fsub;
  fmul* = OPIR.fmul; fdiv* = OPIR.fdiv; fabs* = OPIR.fabs;
  fchs* = OPIR.fchs; fcmp* = OPIR.fcmp;
  newStat* = OPIR.newStat;

  (* Pseudo-register constants from OPIR *)
  none* = OPIR.none; RiscFP* = OPIR.FP; RiscSP* = OPIR.SP;
  noScale = OPIR.noScale; Scale1 = OPIR.Scale1;
  Scale2 = OPIR.Scale2; Scale4 = OPIR.Scale4;
  RegReg = OPIR.RegReg; RegMem = OPIR.RegMem;
  MemReg = OPIR.MemReg; ImmReg = OPIR.ImmReg; ImmMem = OPIR.ImmMem;
  Nil* = OPIR.Nil;

  (* Traps *)
  WithTrap* = OPIR.WithTrap; CaseTrap* = OPIR.CaseTrap;
  FuncTrap* = OPIR.FuncTrap; OverflowTrap* = OPIR.OverflowTrap;
  EqualGuardTrap* = OPIR.EqualGuardTrap; GuardTrap* = OPIR.GuardTrap;
  RangeTrap* = OPIR.RangeTrap; DimTrap* = OPIR.DimTrap;
  nofTrapFixups = 10;

  (* Hints from OPIR *)
  noHint* = OPIR.noHint;
  useR0* = OPIR.useReg0; useR1* = OPIR.useReg1;
  useR2* = OPIR.useReg2; useR3* = OPIR.useReg3;
  useR4* = OPIR.useReg4; useR5* = OPIR.useReg5;
  useR6* = OPIR.useReg6; useR7* = OPIR.useReg7;
  useFReg* = OPIR.useFReg;
  tryR0* = OPIR.tryReg0; tryR1* = OPIR.tryReg1;
  tryR2* = OPIR.tryReg2; tryR3* = OPIR.tryReg3;
  tryR6* = OPIR.tryReg6; tryR7* = OPIR.tryReg7;

  useReg = {useR0, useR1, useR2, useR3, useR4, useR5, useR6, useR7};
  tryReg = {tryR0, tryR1, tryR2, tryR3, tryR6, tryR7};

  (* RV32 GPR numbers (from OPO) *)
  X0 = OPO.X0; RA = OPO.RA; SP = OPO.SP; GP = OPO.GP; TP = OPO.TP;
  T0 = OPO.T0; T1 = OPO.T1; T2 = OPO.T2;
  S0 = OPO.S0; FP = OPO.FP; S1 = OPO.S1;
  A0 = OPO.A0; A1 = OPO.A1; A2 = OPO.A2; A3 = OPO.A3;
  A4 = OPO.A4; A5 = OPO.A5; A6 = OPO.A6; A7 = OPO.A7;
  S2 = OPO.S2; S3 = OPO.S3; S4 = OPO.S4; S5 = OPO.S5;
  S6 = OPO.S6; S7 = OPO.S7; S8 = OPO.S8; S9 = OPO.S9;
  S10 = OPO.S10; S11 = OPO.S11;
  T3 = OPO.T3; T4 = OPO.T4; T5 = OPO.T5; T6 = OPO.T6;

  (* RV32 condition codes (from OPO) *)
  ccEQ = OPO.ccEQ; ccNE = OPO.ccNE;
  ccLT = OPO.ccLT; ccGE = OPO.ccGE;
  ccGT = OPO.ccGT; ccLE = OPO.ccLE;
  ccHI = OPO.ccHI; ccHS = OPO.ccHS;
  ccLO = OPO.ccLO; ccLS = OPO.ccLS;
  ccCS = OPO.ccCS; ccCC = OPO.ccCC;
  ccAL = OPO.ccAL;

  (* Size constants *)
  Bit8 = OPIR.Bit8; Bit16 = OPIR.Bit16;
  Bit32 = OPIR.Bit32; Bit64 = OPIR.Bit64;

  noBase = OPO.noBase; noInx = -1; noImm = OPO.noImm;
  noDisp = OPO.noDisp;

  (* Register allocation states *)
  free = -1; Occupied = MIN(INTEGER);

  BUG = 41;

  (* Object file tags *)
  VarEntryTag = 8CX;
  EntryTag = 82X;
  commandTag = 83X;
  pointerTag = 84X;
  importTag = 85X;
  VarConsLinkTag = 8DX;
  LinkTag = 86X;
  DataTag = 87X;
  ExportTag = 88X;
  CodeTag = 89X;
  UseTag = 8AX;
  TypeTag = 8BX;
  RefTag = 8CX;

  (* Export/Use section *)
  EUEnd = 0X; EURecord = 1X; EUProcFlag = 080000000H;

  (* sysflag *)
  notag = 1; stdcall = 2; cdecl = 3; untraced = 4; delegate = 5;

  (* Object modes *)
  Var = 1; VarPar = 2; Con = 3; Fld = 4; Typ = 5;
  LProc = 6; XProc = 7; CProc = 9; IProc = 10; Module = 11; TProc = 13;

  (* Structure forms *)
  Undef = 0; Byte = 1; Bool = 2; Char = 3; SInt = 4; Int = 5; LInt = 6;
  Real = 7; LReal = 8; Set = 9; String = 10; NilTyp = 11; NoTyp = 12;
  Pointer = 13; ProcTyp = 14; Comp = 15; HInt = 16;

  (* Composite structure forms *)
  Basic = 1; StaticArr = 2; SDynArr = 3; DynArr = 4; OpenArr = 5; Record = 6;

  (* Module visibility *)
  internal = 0; external = 1; externalR = 2;

  (* Object type flags *)
  hasBody = 1; slNeeded = 3; activeObj = 5;

  false = 0; true = 1;
  noEntry = -1;

  (* Predefined entry numbers and link indices *)
  CaseTabelIndex = 0; CaseTableEntryNr = 255;
  LocProcAssIndex = 1; LocProcAssEntryNr = 254;
  NewLinkIndex* = OPIR.NewLinkIndex; NewEntryNr* = OPIR.NewEntryNr;
  NewSysLinkIndex* = OPIR.NewSysLinkIndex; NewSysEntryNr* = OPIR.NewSysEntryNr;
  NewArrayLinkIndex* = OPIR.NewArrayLinkIndex; NewArrayEntryNr* = OPIR.NewArrayEntryNr;
  StartIndex* = OPIR.StartIndex; StartEntryNr* = OPIR.StartEntryNr;
  AwaitIndex* = OPIR.AwaitIndex; AwaitEntryNr* = OPIR.AwaitEntryNr;
  LockIndex* = OPIR.LockIndex; LockEntryNr* = OPIR.LockEntryNr;
  UnlockIndex* = OPIR.UnlockIndex; UnlockEntryNr* = OPIR.UnlockEntryNr;

  (* Software arithmetic sysfixes *)
  DivModLinkIndex* = OPIR.DivModLinkIndex; DivModEntryNr* = OPIR.DivModEntryNr;
  F64AddLinkIndex* = OPIR.F64AddLinkIndex; F64AddEntryNr* = OPIR.F64AddEntryNr;
  F64SubLinkIndex* = OPIR.F64SubLinkIndex; F64SubEntryNr* = OPIR.F64SubEntryNr;
  F64MulLinkIndex* = OPIR.F64MulLinkIndex; F64MulEntryNr* = OPIR.F64MulEntryNr;
  F64DivLinkIndex* = OPIR.F64DivLinkIndex; F64DivEntryNr* = OPIR.F64DivEntryNr;
  F64CmpLinkIndex* = OPIR.F64CmpLinkIndex; F64CmpEntryNr* = OPIR.F64CmpEntryNr;
  F64CvtIFLinkIndex* = OPIR.F64CvtIFLinkIndex; F64CvtIFEntryNr* = OPIR.F64CvtIFEntryNr;
  F64CvtFILinkIndex* = OPIR.F64CvtFILinkIndex; F64CvtFIEntryNr* = OPIR.F64CvtFIEntryNr;
  F64NegLinkIndex* = OPIR.F64NegLinkIndex; F64NegEntryNr* = OPIR.F64NegEntryNr;
  F64AbsLinkIndex* = OPIR.F64AbsLinkIndex; F64AbsEntryNr* = OPIR.F64AbsEntryNr;
  InitLinks = 19;

  MaxCommands = 128;
  MaxNewMethods = 16;
  MaxExtensions = 15;
  MaxEntry* = 128;
  LinkLength = 512;
  MaxSaveLevel = 32;
  MaxFwdFixups = 1024;

  (* FPU register allocation *)
  (* Single-precision: f0/fa0 reserved for return, allocate f1..f31 *)
  MaxFRegs = 32; (* f0..f31 *)
  FRegBase = 0;  (* f0 is index 0 *)

   (* Number of allocatable GPRs: a0-a7 (8), t1-t2 (2), t3-t4 (2), s1-s11 (11) = 23 registers *)
  (* We map them to indices 0-22 in regTab *)
  MaxGPRs = 23;

  PtrInit = 5;

 TYPE
  Instruction* = OPIR.Instruction;
  InstructionTable* = OPIR.InstructionTable;
  Map* = OPIR.Map;
  MapDesc* = OPIR.MapDesc;

  LinkRec = RECORD
   offset, mod, entry: INTEGER;
  END;

  VarConsRec = RECORD
   mod, entry, noflinks, index: INTEGER
  END;
  VarConsTable = POINTER TO ARRAY OF VarConsRec;

  VarConsLinkRec = RECORD
   offset, next: INTEGER
  END;
  VarConsLinkTable = POINTER TO ARRAY OF VarConsLinkRec;

  SavedRegRec = RECORD
   reg: ARRAY MaxGPRs OF INTEGER;  (* saved GPR allocation states *)
   freg: ARRAY MaxFRegs OF INTEGER; (* saved FPU allocation states *)
  END;

  PtrTable = POINTER TO ARRAY OF LONGINT;
  RecTable = POINTER TO ARRAY OF OPT.Struct;
  EntryTable = POINTER TO ARRAY OF INTEGER;
  ExpTable = POINTER TO ARRAY OF LONGINT;

 VAR
  ptrTab: PtrTable;
  recTab: RecTable;
  entry: EntryTable;

  varConsLink: VarConsTable;
  link: ARRAY LinkLength OF LinkRec;
  varConsTab: VarConsLinkTable;
  nofVarCons, noVarEntries, nofEntries, nofVarConsLinks, nofLinks, nofrecs: INTEGER;
  nofptrs: LONGINT;
  ConstErr, RegErr, VarEntryErr, LinkErr: BOOLEAN;

  (* RV32 register allocation *)
  (* regTab[i] = free (-1), Occupied (MIN(INTEGER)), or pReg index (>= 0) *)
   (* Indices 0-22 correspond to allocatable GPRs:
   *   0-7: a0-a7 (x10-x17)
   *   8-9: t1-t2 (x6-x7)
   *   10-11: t3-t4 (x28-x29)
   *   12: s1 (x9)
   *   13-22: s2-s11 (x18-x27)
   *)
  regTab: ARRAY MaxGPRs OF LONGINT;

  (* FPU register allocation: fregTab[i] for f0..f31 *)
  fregTab: ARRAY MaxFRegs OF LONGINT;

  savedRegs: ARRAY MaxSaveLevel OF SavedRegRec;
  nofSavedLevel: INTEGER;

  trapFixupTab: ARRAY nofTrapFixups OF LONGINT;

  (* Forward jump fixup table: records (machine code pos, target IR index) pairs *)
  fwdFixupPos: ARRAY MaxFwdFixups OF LONGINT;
  fwdFixupTarget: ARRAY MaxFwdFixups OF LONGINT;
  nofFwdFixups: LONGINT;

  nofStr: INTEGER;
  linkTable*: LONGINT;
  gVarLink*: LONGINT;

  explist: ExpTable; exppos: LONGINT;

  (* LONGREAL hi-word register tracking.
     On RV32 without D extension, LONGREAL (64-bit) values use two GPRs:
     the lo word in the assigned register, the hi word in lrealHi[loReg].
     lrealHi[r] = -1 means no hi-word companion for register r. *)
  lrealHi: ARRAY 32 OF SHORTINT;

 PROCEDURE ClearLRealHi;
  VAR i: SHORTINT;
 BEGIN
  FOR i := 0 TO 31 DO lrealHi[i] := -1 END
 END ClearLRealHi;

 PROCEDURE SetLRealHi(loReg, hiReg: SHORTINT);
 BEGIN
  IF (loReg >= 0) & (loReg < 32) THEN lrealHi[loReg] := hiReg END
 END SetLRealHi;

 PROCEDURE GetLRealHi(loReg: SHORTINT): SHORTINT;
 BEGIN
  IF (loReg >= 0) & (loReg < 32) THEN RETURN lrealHi[loReg] END;
  RETURN -1
 END GetLRealHi;

 PROCEDURE FreeLRealHi(loReg: SHORTINT);
  VAR hi: SHORTINT;
 BEGIN
  IF (loReg >= 0) & (loReg < 32) THEN
   hi := lrealHi[loReg];
   IF hi > -1 THEN
    FreeReg(hi);
    lrealHi[loReg] := -1
   END
  END
 END FreeLRealHi;


 PROCEDURE Init*;
 BEGIN
  OPO.CodeErr := FALSE; ConstErr := FALSE;
  VarEntryErr := FALSE; LinkErr := FALSE;
  OPO.dsize := 0; OPO.csize := 0; OPO.pc := 0;
  noVarEntries := 0; nofptrs := 0; nofVarConsLinks := 0;
  nofrecs := 0; nofEntries := 0; nofSavedLevel := 0;
  IF OPM.aosFlag THEN OPO.csize := 0 ELSE OPO.csize := 4 END; (* module.SELF: 4 bytes for System 3, 0 for AOS *)
  varConsLink[0].noflinks := 0; varConsLink[0].entry := -1;
  varConsLink[0].noflinks := 0; varConsLink[0].index := noEntry;
  nofVarCons := 1;
  link[0].mod := 0; link[0].entry := CaseTableEntryNr; link[0].offset := Nil;
  link[1].mod := 0; link[1].entry := LocProcAssEntryNr; link[1].offset := Nil;
  link[2].mod := 0; link[2].entry := NewEntryNr; link[2].offset := Nil;
  link[3].mod := 0; link[3].entry := NewSysEntryNr; link[3].offset := Nil;
  link[4].mod := 0; link[4].entry := NewArrayEntryNr; link[4].offset := Nil;
  link[5].mod := 0; link[5].entry := StartEntryNr; link[5].offset := Nil;
  link[6].mod := 0; link[6].entry := AwaitEntryNr; link[6].offset := Nil;
  link[7].mod := 0; link[7].entry := LockEntryNr; link[7].offset := Nil;
  link[8].mod := 0; link[8].entry := UnlockEntryNr; link[8].offset := Nil;
  (* Software arithmetic sysfixes *)
  link[9].mod := 0; link[9].entry := DivModEntryNr; link[9].offset := Nil;
  link[10].mod := 0; link[10].entry := F64AddEntryNr; link[10].offset := Nil;
  link[11].mod := 0; link[11].entry := F64SubEntryNr; link[11].offset := Nil;
  link[12].mod := 0; link[12].entry := F64MulEntryNr; link[12].offset := Nil;
  link[13].mod := 0; link[13].entry := F64DivEntryNr; link[13].offset := Nil;
  link[14].mod := 0; link[14].entry := F64CmpEntryNr; link[14].offset := Nil;
  link[15].mod := 0; link[15].entry := F64CvtIFEntryNr; link[15].offset := Nil;
  link[16].mod := 0; link[16].entry := F64CvtFIEntryNr; link[16].offset := Nil;
  link[17].mod := 0; link[17].entry := F64NegEntryNr; link[17].offset := Nil;
  link[18].mod := 0; link[18].entry := F64AbsEntryNr; link[18].offset := Nil;
  nofLinks := InitLinks;
  ClearLRealHi
 END Init;


 PROCEDURE RegToGPR(reg: SHORTINT): SHORTINT;
 (* Convert regTab index (0..22) to RV32 GPR number *)
 BEGIN
  IF reg <= 7 THEN RETURN SHORT(A0 + reg) (* a0-a7: x10-x17 *)
  ELSIF reg <= 9 THEN RETURN SHORT(T1 + (reg - 8)) (* t1-t2: x6-x7 *)
  ELSIF reg <= 11 THEN RETURN SHORT(T3 + (reg - 10)) (* t3-t4: x28-x29 *)
  ELSIF reg = 12 THEN RETURN S1 (* s1: x9 *)
  ELSE RETURN SHORT(S2 + (reg - 13)) (* s2-s11: x18-x27 *)
  END
 END RegToGPR;

 PROCEDURE GPRToReg(gpr: SHORTINT): SHORTINT;
 (* Convert RV32 GPR number to regTab index *)
 BEGIN
  IF (gpr >= A0) & (gpr <= A7) THEN RETURN SHORT(gpr - A0) (* a0-a7 -> 0-7 *)
  ELSIF (gpr >= T1) & (gpr <= T2) THEN RETURN SHORT(8 + (gpr - T1)) (* t1-t2 -> 8-9 *)
  ELSIF (gpr >= T3) & (gpr <= T4) THEN RETURN SHORT(10 + (gpr - T3)) (* t3-t4 -> 10-11 *)
  ELSIF gpr = S1 THEN RETURN 12 (* s1 -> 12 *)
  ELSIF (gpr >= S2) & (gpr <= S11) THEN RETURN SHORT(13 + (gpr - S2)) (* s2-s11 -> 13-22 *)
  ELSE RETURN none
  END
 END GPRToReg;

 PROCEDURE IsAllocatable(gpr: SHORTINT): BOOLEAN;
 (* Returns TRUE if the GPR can be allocated (a0-a7, t1-t2, t3-t4, s1-s11) *)
 BEGIN
  RETURN ((gpr >= A0) & (gpr <= A7)) OR ((gpr >= T1) & (gpr <= T2)) OR
         ((gpr >= T3) & (gpr <= T4)) OR ((gpr >= S1) & (gpr <= S11))
 END IsAllocatable;

 PROCEDURE loaded(pReg: LONGINT): BOOLEAN;
 BEGIN
  IF pReg > none THEN RETURN OPIR.Instr[pReg].reg > none
  ELSE RETURN (pReg = RiscSP) OR (pReg = RiscFP)
  END
 END loaded;

 PROCEDURE GetReg(VAR reg: SHORTINT);
 (* Returns any free allocatable GPR and marks it occupied *)
 (* Allocation order: a0-a7 (scratch) first, then t1-t2, t3-t4, s1-s11 *)
  VAR r: SHORTINT;
 BEGIN
  (* Try indices 0..MaxGPRs-1 in order *)
  r := 0;
  WHILE (r < MaxGPRs) & (regTab[r] # free) DO INC(r) END;
  IF r >= MaxGPRs THEN
   OPM.err(215); RegErr := TRUE; reg := 0; RETURN
  END;
  regTab[r] := Occupied;
  reg := RegToGPR(r)
 END GetReg;

 PROCEDURE GetThisReg(this: SHORTINT);
 (* Marks 'this' GPR as occupied. If occupied, moves its value to another register *)
  VAR r, idx: SHORTINT; pReg: LONGINT;
 BEGIN
  ASSERT(IsAllocatable(this));
  idx := GPRToReg(this);
  IF regTab[idx] # free THEN
   IF regTab[idx] = Occupied THEN
    (* Register is occupied but not tracking a pReg - just mark it *)
   ELSE
    (* Move the current occupant to another register *)
    pReg := regTab[idx];
    ASSERT(pReg >= 0);
    GetReg(r);
    regTab[GPRToReg(r)] := pReg;
    OPIR.Instr[pReg].reg := r;
    OPO.GenMOV(r, this)
   END
  END;
  regTab[idx] := Occupied
 END GetThisReg;

 PROCEDURE FreeReg(reg: SHORTINT);
 (* Releases a GPR *)
  VAR pReg: LONGINT; idx: SHORTINT;
 BEGIN
  IF (reg > none) & IsAllocatable(reg) THEN
   idx := GPRToReg(reg);
   pReg := regTab[idx];
   IF pReg > none THEN OPIR.Instr[pReg].reg := -2 - reg END;
   regTab[idx] := free
  END
 END FreeReg;

 PROCEDURE DecReg(reg: SHORTINT);
 (* Decrements use count of register; frees if count reaches 0 *)
  VAR pReg: LONGINT; idx: SHORTINT;
 BEGIN
  IF reg > none THEN
   IF IsAllocatable(reg) THEN
    idx := GPRToReg(reg);
    pReg := regTab[idx]
   ELSE pReg := none
   END;
   IF pReg > none THEN
    DEC(OPIR.Instr[pReg].used);
    IF (OPIR.Instr[pReg].used = 0) & (OPIR.Instr[pReg].reg > Nil) THEN
     FreeReg(OPIR.Instr[pReg].reg)
    END
   END
  END
 END DecReg;

 PROCEDURE LastUse(reg: SHORTINT): BOOLEAN;
  VAR pReg: LONGINT; idx: SHORTINT;
 BEGIN
  IF ~IsAllocatable(reg) THEN RETURN FALSE END;
  idx := GPRToReg(reg);
  pReg := regTab[idx];
  IF pReg > none THEN RETURN OPIR.Instr[pReg].used = 1
  ELSE RETURN TRUE
  END
 END LastUse;

 PROCEDURE AssignNewReg(pReg: LONGINT);
 (* Assigns pReg to any free register *)
  VAR reg: SHORTINT;
 BEGIN
  GetReg(reg);
  regTab[GPRToReg(reg)] := pReg;
  OPIR.Instr[pReg].reg := reg
 END AssignNewReg;

 PROCEDURE AssignThisReg(pReg: LONGINT; this: SHORTINT);
 (* Assigns pReg to register 'this'. Moves 'this' if occupied. *)
 BEGIN
  IF ~IsAllocatable(this) THEN
   (* Non-allocatable register (T0/SP/FP/RA): redirect to a free allocatable register.
      T0 is used as scratch by Load/Store/LoadImm32; assigning IR results to it
      causes silent clobbering because T0 is not tracked in regTab. *)
   AssignNewReg(pReg); RETURN
  END;
  GetThisReg(this);
  regTab[GPRToReg(this)] := pReg;
  OPIR.Instr[pReg].reg := this
 END AssignThisReg;

 PROCEDURE AssignReg(pReg: LONGINT; VAR reg, base, inx: SHORTINT);
 (* Assigns pReg to a register, considering hints and reuse.
    When a useReg hint forces AssignThisReg, the existing occupant of the
    target register may be moved to a different register.  We must fixup
    the VAR parameters reg/base/inx so callers (especially DecCheckReg)
    see the up-to-date register numbers ? otherwise they operate on stale
    values and can evict the instruction that was just assigned. *)
  VAR hint, pRegReg, pRegBase, pRegInx: LONGINT;
 BEGIN
  hint := OPIR.Instr[pReg].hint;
  IF hint >= tryR0 THEN
   IF regTab[hint - tryR0] = free THEN
    AssignThisReg(pReg, RegToGPR(SHORT(SHORT(hint - tryR0))));
    RETURN
   END;
   hint := noHint
  END;
  IF hint <= noHint THEN
   IF (reg = none) OR ~IsAllocatable(reg) OR ~LastUse(reg) THEN AssignNewReg(pReg)
   ELSE OPIR.Instr[pReg].reg := reg
   END
  ELSE
   (* Save pReg indices before AssignThisReg may move occupants *)
   pRegReg := none; pRegBase := none; pRegInx := none;
   IF (reg > none) & IsAllocatable(reg) THEN pRegReg := regTab[GPRToReg(reg)] END;
   IF (base > none) & IsAllocatable(base) THEN pRegBase := regTab[GPRToReg(base)] END;
   IF (inx > none) & IsAllocatable(inx) THEN pRegInx := regTab[GPRToReg(inx)] END;
   AssignThisReg(pReg, RegToGPR(SHORT(SHORT(hint))));
   (* Fixup: occupants may have been moved to new registers *)
   IF (reg > none) & (pRegReg > none) THEN reg := OPIR.Instr[pRegReg].reg END;
   IF (base > none) & (pRegBase > none) THEN base := OPIR.Instr[pRegBase].reg END;
   IF (inx > none) & (pRegInx > none) THEN inx := OPIR.Instr[pRegInx].reg END
  END
 END AssignReg;

 PROCEDURE DecCheckReg(pReg: LONGINT; src, base, inx: SHORTINT);
 (* Decrements use counts and updates register tracking *)
  VAR reg, idx: SHORTINT;

  PROCEDURE ReleaseReg(r: SHORTINT);
   VAR p: LONGINT;
  BEGIN
   IF r > none THEN
    IF IsAllocatable(r) THEN p := regTab[GPRToReg(r)]
    ELSE p := none
    END;
    IF p > none THEN OPIR.Instr[p].reg := -2 - r END
   END
  END ReleaseReg;

  PROCEDURE CheckRegister(r, s: SHORTINT);
  BEGIN
   IF r = s THEN ReleaseReg(s)
   ELSE DecReg(s)
   END
  END CheckRegister;

 BEGIN
  reg := OPIR.Instr[pReg].reg;
  CheckRegister(reg, src);
  CheckRegister(reg, base);
  CheckRegister(reg, inx);
  IF (reg > none) & IsAllocatable(reg) THEN
   idx := GPRToReg(reg);
   regTab[idx] := pReg
  END
 END DecCheckReg;

 PROCEDURE FindReg(pReg: LONGINT; VAR reg: SHORTINT);
 BEGIN
  ASSERT(loaded(pReg));
  IF pReg > none THEN reg := OPIR.Instr[pReg].reg
  ELSIF pReg = RiscSP THEN reg := SP
  ELSE reg := FP
  END
 END FindReg;

 PROCEDURE^ Load(VAR instr: Instruction);

 PROCEDURE FindLoadReg(pReg: LONGINT; VAR reg: SHORTINT);
 BEGIN
  IF pReg > none THEN
   IF ~loaded(pReg) THEN Load(OPIR.Instr[pReg]) END;
   reg := OPIR.Instr[pReg].reg
  ELSIF pReg = RiscSP THEN reg := SP
  ELSIF pReg = RiscFP THEN reg := FP
  ELSE reg := none
  END
 END FindLoadReg;

 PROCEDURE FindMemReg(VAR instr: Instruction; VAR mode, size, base, inx: SHORTINT; VAR disp: LONGINT);
 BEGIN
  size := SHORT(instr.op MOD 8) * 8;
  mode := SHORT((instr.op DIV 8) MOD 4);
  IF mode IN {MemReg, RegMem} THEN
   FindLoadReg(instr.src1, base); disp := instr.src2;
   FindLoadReg(instr.inx, inx)
  ELSIF mode = RegReg THEN
   FindLoadReg(instr.src1, base);
   disp := noDisp; inx := none
  ELSE (* ImmReg *)
   base := noBase; disp := noDisp; inx := none
  END
 END FindMemReg;


 PROCEDURE GetFreg(VAR freg: SHORTINT);
 (* Returns any free FPU register f0..f31 *)
  VAR i: SHORTINT;
 BEGIN
  (* Start from f1 to keep f0/fa0 for return values *)
  i := 1;
  WHILE (i < MaxFRegs) & (fregTab[i] # free) DO INC(i) END;
  IF i >= MaxFRegs THEN
   (* Try f0 as last resort *)
   IF fregTab[0] = free THEN i := 0
   ELSE OPM.err(216); RegErr := TRUE; freg := 0; RETURN
   END
  END;
  fregTab[i] := Occupied;
  freg := i
 END GetFreg;

 PROCEDURE FreeFreg(freg: SHORTINT);
 BEGIN
  IF freg > none THEN
   IF fregTab[freg] > free THEN OPIR.Instr[fregTab[freg]].reg := -2 - freg END;
   fregTab[freg] := free
  END
 END FreeFreg;

 PROCEDURE AssignFreg(pReg: LONGINT);
  VAR freg: SHORTINT;
 BEGIN
  GetFreg(freg);
  fregTab[freg] := pReg;
  OPIR.Instr[pReg].reg := freg
 END AssignFreg;

 PROCEDURE FindFreg(pReg: LONGINT; VAR freg: SHORTINT);
 BEGIN
  ASSERT((pReg >= 0) & (OPIR.Instr[pReg].reg >= 0));
  freg := OPIR.Instr[pReg].reg
 END FindFreg;

 PROCEDURE LastUseF(freg: SHORTINT): BOOLEAN;
 BEGIN
  ASSERT((freg >= 0) & (freg < MaxFRegs) & (fregTab[freg] >= 0));
  RETURN OPIR.Instr[fregTab[freg]].used = 1
 END LastUseF;

 PROCEDURE DecCheckFreg(freg: SHORTINT);
  VAR pReg: LONGINT;
 BEGIN
  IF freg > none THEN
   pReg := fregTab[freg];
   DEC(OPIR.Instr[pReg].used);
   IF OPIR.Instr[pReg].used = 0 THEN FreeFreg(freg) END
  END
 END DecCheckFreg;

 PROCEDURE IsSinglePrec(instr: Instruction): BOOLEAN;
 (* Returns TRUE if the FP instruction operates on single-precision (REAL) *)
 BEGIN
  RETURN (instr.op MOD 8) = 3 (* size=3 means float/single *)
 END IsSinglePrec;

 PROCEDURE NewVarCons*(mod, entry: INTEGER; VAR index: LONGINT);
  VAR i: LONGINT; var: VarConsTable;
 BEGIN
  IF nofVarCons >= LEN(varConsLink) THEN
   NEW(var, LEN(varConsLink) * 2);
   FOR i := 0 TO LEN(varConsLink) - 1 DO var[i] := varConsLink[i] END;
   varConsLink := var
  END;
  varConsLink[nofVarCons].mod := mod; varConsLink[nofVarCons].entry := entry;
  varConsLink[nofVarCons].noflinks := 0; varConsLink[nofVarCons].index := noEntry;
  index := nofVarCons;
  INC(nofVarCons)
 END NewVarCons;

 PROCEDURE VarConsLink(index, offset: LONGINT);
  VAR i: LONGINT; var: VarConsLinkTable;
 BEGIN
  IF nofVarConsLinks >= LEN(varConsTab) THEN
   NEW(var, LEN(varConsTab) * 2);
   FOR i := 0 TO LEN(varConsTab) - 1 DO var[i] := varConsTab[i] END;
   varConsTab := var
  END;
  INC(varConsLink[index].noflinks);
  IF varConsLink[index].noflinks = 1 THEN
   varConsLink[index].index := nofVarConsLinks
  ELSE
   index := varConsLink[index].index;
   WHILE varConsTab[index].next # noEntry DO index := varConsTab[index].next END;
   varConsTab[index].next := nofVarConsLinks
  END;
  varConsTab[nofVarConsLinks].offset := SHORT(offset);
  varConsTab[nofVarConsLinks].next := noEntry;
  INC(nofVarConsLinks)
 END VarConsLink;

 PROCEDURE AbsAccess(node: OPT.Node; offset: LONGINT);
 BEGIN
  IF OPM.noerr THEN
   IF (node # NIL) & (node.link = NIL) & (node.obj = NIL) &
      (node.left = NIL) & (node.right = NIL) THEN
    VarConsLink(0, offset)
   ELSE
    WHILE (node # NIL) & (node.left # NIL) DO node := node.left END;
    IF (node = NIL) OR (node.obj.mnolev = 0) THEN
     VarConsLink(0, offset)
    ELSE
     VarConsLink(node.obj.adr DIV 10000H, offset)
    END
   END
  END
 END AbsAccess;

 PROCEDURE NewEntry*(VAR entryNr: LONGINT);
  VAR table: EntryTable; i: LONGINT;
 BEGIN
  IF nofEntries >= LEN(entry) THEN
   NEW(table, LEN(entry) * 2);
   FOR i := 0 TO LEN(entry) - 1 DO table[i] := entry[i] END;
   entry := table
  END;
  entry[nofEntries] := Nil;
  entryNr := nofEntries;
  INC(nofEntries)
 END NewEntry;

 PROCEDURE NewLink*(mod, entry: LONGINT; VAR index: LONGINT);
 BEGIN
  IF nofLinks >= LinkLength THEN
   IF ~LinkErr THEN OPM.err(231); LinkErr := TRUE; index := 0 END
  ELSE
   link[nofLinks].mod := SHORT(mod); link[nofLinks].entry := SHORT(entry);
   link[nofLinks].offset := Nil;
   index := nofLinks;
   INC(nofLinks)
  END
 END NewLink;

 PROCEDURE AddLink(index, offset: LONGINT);
 (* RV32: JAL instruction is at 'offset'; store fixup chain in the JAL's imm20 field *)
 (* The chain is encoded as: imm20 = (nextoffset >> 2) & 0xFFFFF *)
  VAR old, oldImm20: LONGINT;
 BEGIN
  IF ~LinkErr THEN
   OPO.GetWord(offset, old);
   (* Extract current imm20 from JAL instruction (bits [31:12]) *)
   oldImm20 := (old DIV 1000H) MOD 100000H;
   IF link[index].offset = Nil THEN
    (* First entry: encode -1 as sentinel (0xFFFFF = -1 in 20-bit) *)
    OPO.PutWordAt(offset, (old MOD 1000H) + 0FFFFF000H)
   ELSE
    (* Chain: encode previous offset >> 2 *)
    IF link[index].offset >= 8000H THEN
     OPO.PutWordAt(offset, (old MOD 1000H) +
      (((link[index].offset - 10000H) DIV 4) MOD 100000H) * 1000H)
    ELSE
     OPO.PutWordAt(offset, (old MOD 1000H) +
      ((link[index].offset DIV 4) MOD 100000H) * 1000H)
    END
   END;
   link[index].offset := SHORT(offset)
  END
 END AddLink;

 PROCEDURE AllocConst*(VAR s: ARRAY OF SYSTEM.BYTE; len, align: LONGINT; VAR adr: LONGINT);
  VAR fill: LONGINT; table: OPO.ConstArray;
 BEGIN
  IF ~ConstErr THEN
   adr := OPO.csize;
   OPO.csize := OPO.csize + len;
   fill := (-len) MOD align;
   IF OPO.csize + fill > OPO.MaxConstLength THEN
    OPM.err(230); ConstErr := TRUE
   ELSE
    IF OPO.csize + fill >= LEN(OPO.constant) THEN
     NEW(table, LEN(OPO.constant) * 2);
     SYSTEM.MOVE(SYSTEM.ADR(OPO.constant[0]), SYSTEM.ADR(table[0]), adr);
     OPO.constant := table
    END;
    WHILE fill > 0 DO
     OPO.constant[OPO.csize] := 0X; INC(OPO.csize); DEC(fill)
    END;
    SYSTEM.MOVE(SYSTEM.ADR(s[0]), SYSTEM.ADR(OPO.constant[adr]), len)
   END
  ELSE adr := 0
  END
 END AllocConst;

 PROCEDURE AllocCaseTab*(low, high: LONGINT; VAR tab: LONGINT);
  VAR len, i: LONGINT; table: OPO.ConstArray;
 BEGIN
  IF ~ConstErr THEN
   len := 4 * (high - low + 1);
   tab := OPO.csize;
   OPO.csize := OPO.csize + len;
   IF OPO.csize > OPO.MaxConstLength THEN
    OPM.err(230); ConstErr := TRUE
   ELSE
    IF OPO.csize >= LEN(OPO.constant) THEN
     NEW(table, LEN(OPO.constant) * 2);
     SYSTEM.MOVE(SYSTEM.ADR(OPO.constant[0]), SYSTEM.ADR(table[0]), tab);
     OPO.constant := table
    END;
    i := tab;
    WHILE i < OPO.csize DO OPO.constant[i] := CHR(255); INC(i) END
   END
  ELSE tab := 0
  END
 END AllocCaseTab;

 PROCEDURE AllocTypDesc*(typ: OPT.Struct);
  VAR nil: LONGINT; table: RecTable; i: LONGINT;
 BEGIN
  IF typ.comp = Record THEN
   nil := 0; AllocConst(nil, 4, 4, typ.tdadr);
   IF typ.extlev > MaxExtensions THEN OPM.err(233)
   ELSIF typ.mno = 0 THEN
    IF nofrecs >= LEN(recTab) THEN
     NEW(table, LEN(recTab) * 2);
     FOR i := 0 TO LEN(recTab) - 1 DO table[i] := recTab[i] END;
     recTab := table
    END;
    recTab[nofrecs] := typ; INC(nofrecs)
   END
  END
 END AllocTypDesc;

 PROCEDURE CaseJump*(Label, tab, from, to: LONGINT);
 BEGIN
  IF ~ConstErr THEN
   from := tab + 4 * from; to := tab + 4 * to;
   WHILE from <= to DO
    OPO.PutConsDWord(from, Label);
    from := from + 4
   END
  END
 END CaseJump;


(* RV32 immediate helpers: handle arbitrary 32-bit immediates.
   RV32 I-type instructions use 12-bit signed immediates (-2048..2047).
   For values outside this range, we load into T0 (scratch register). *)

 PROCEDURE FitsImm12(imm: LONGINT): BOOLEAN;
 BEGIN RETURN (imm >= -2048) & (imm <= 2047)
 END FitsImm12;

 PROCEDURE EmitAddImm(Rd, Rn: LONGINT; imm: LONGINT);
 BEGIN
  IF FitsImm12(imm) THEN
   OPO.GenADDI(Rd, Rn, imm)
  ELSE
   OPO.LoadImm32(T0, imm);
   OPO.GenADD(Rd, Rn, T0)
  END
 END EmitAddImm;

 PROCEDURE EmitSubImm(Rd, Rn: LONGINT; imm: LONGINT);
 BEGIN
  IF FitsImm12(-imm) THEN
   OPO.GenADDI(Rd, Rn, -imm)
  ELSE
   OPO.LoadImm32(T0, imm);
   OPO.GenSUB(Rd, Rn, T0)
  END
 END EmitSubImm;

 PROCEDURE EmitAndImm(Rd, Rn: LONGINT; imm: LONGINT);
 BEGIN
  IF FitsImm12(imm) THEN
   OPO.GenANDI(Rd, Rn, imm)
  ELSE
   OPO.LoadImm32(T0, imm);
   OPO.GenAND(Rd, Rn, T0)
  END
 END EmitAndImm;

 PROCEDURE EmitOrImm(Rd, Rn: LONGINT; imm: LONGINT);
 BEGIN
  IF FitsImm12(imm) THEN
   OPO.GenORI(Rd, Rn, imm)
  ELSE
   OPO.LoadImm32(T0, imm);
   OPO.GenOR(Rd, Rn, T0)
  END
 END EmitOrImm;

 PROCEDURE EmitXorImm(Rd, Rn: LONGINT; imm: LONGINT);
 BEGIN
  IF FitsImm12(imm) THEN
   OPO.GenXORI(Rd, Rn, imm)
  ELSE
   OPO.LoadImm32(T0, imm);
   OPO.GenXOR(Rd, Rn, T0)
  END
 END EmitXorImm;

 PROCEDURE EmitLoad(rd, base: LONGINT; disp: LONGINT; size: SHORTINT);
 (* Load from memory, handling large displacements via T0 *)
 BEGIN
  IF FitsImm12(disp) THEN
   IF size = Bit8 THEN OPO.GenLBU(rd, base, disp)
   ELSIF size = Bit16 THEN OPO.GenLHU(rd, base, disp)
   ELSE OPO.GenLW(rd, base, disp)
   END
  ELSE
   OPO.LoadImm32(T0, disp);
   OPO.GenADD(T0, base, T0);
   IF size = Bit8 THEN OPO.GenLBU(rd, T0, 0)
   ELSIF size = Bit16 THEN OPO.GenLHU(rd, T0, 0)
   ELSE OPO.GenLW(rd, T0, 0)
   END
  END
 END EmitLoad;

 PROCEDURE EmitLoadSigned(rd, base: LONGINT; disp: LONGINT; size: SHORTINT);
 (* Load from memory with sign extension *)
 BEGIN
  IF FitsImm12(disp) THEN
   IF size = Bit8 THEN OPO.GenLB(rd, base, disp)
   ELSIF size = Bit16 THEN OPO.GenLH(rd, base, disp)
   ELSE OPO.GenLW(rd, base, disp)
   END
  ELSE
   OPO.LoadImm32(T0, disp);
   OPO.GenADD(T0, base, T0);
   IF size = Bit8 THEN OPO.GenLB(rd, T0, 0)
   ELSIF size = Bit16 THEN OPO.GenLH(rd, T0, 0)
   ELSE OPO.GenLW(rd, T0, 0)
   END
  END
 END EmitLoadSigned;

 PROCEDURE EmitStore(rs, base: LONGINT; disp: LONGINT; size: SHORTINT);
 (* Store to memory, handling large displacements via T0 *)
 BEGIN
  IF FitsImm12(disp) THEN
   IF size = Bit8 THEN OPO.GenSB(rs, base, disp)
   ELSIF size = Bit16 THEN OPO.GenSH(rs, base, disp)
   ELSE OPO.GenSW(rs, base, disp)
   END
  ELSE
   OPO.LoadImm32(T0, disp);
   OPO.GenADD(T0, base, T0);
   IF size = Bit8 THEN OPO.GenSB(rs, T0, 0)
   ELSIF size = Bit16 THEN OPO.GenSH(rs, T0, 0)
   ELSE OPO.GenSW(rs, T0, 0)
   END
  END
 END EmitStore;

 PROCEDURE EmitFLoad(frd, base: LONGINT; disp: LONGINT);
 (* FLW frd, disp(base) - handling large displacements *)
 BEGIN
  IF FitsImm12(disp) THEN
   OPO.GenFLW(frd, base, disp)
  ELSE
   OPO.LoadImm32(T0, disp);
   OPO.GenADD(T0, base, T0);
   OPO.GenFLW(frd, T0, 0)
  END
 END EmitFLoad;

 PROCEDURE EmitFStore(frs, base: LONGINT; disp: LONGINT);
 (* FSW frs, disp(base) - handling large displacements *)
 BEGIN
  IF FitsImm12(disp) THEN
   OPO.GenFSW(frs, base, disp)
  ELSE
   OPO.LoadImm32(T0, disp);
   OPO.GenADD(T0, base, T0);
   OPO.GenFSW(frs, T0, 0)
  END
 END EmitFStore;

 PROCEDURE Load(VAR instr: Instruction);
 (* ld, lea, ldbdw, ldbw, ldwdw, ldbdwu, ldwdwu, ldbwu, getReg, putReg *)
  VAR
   mode, size, base, inx, dummy, memBase: SHORTINT;
   disp, slotOff: LONGINT;
   op: LONGINT;
 BEGIN
  op := instr.op DIV 32;
  IF (op = Neg) OR (op = Not) THEN
   (* Neg/Not instruction whose register was evicted. Re-materialize. *)
   IF loaded(instr.src1) THEN
    base := OPIR.Instr[instr.src1].reg
   ELSE
    FindLoadReg(instr.src1, base)
   END;
   dummy := none;
   AssignReg(instr.dest, base, dummy, dummy);
   IF op = Neg THEN
    OPO.GenSUB(instr.reg, X0, base)
   ELSE
    OPO.GenXORI(instr.reg, base, -1)
   END;
   IF (instr.reg = base) & IsAllocatable(base) THEN
    IF regTab[GPRToReg(base)] > none THEN OPIR.Instr[regTab[GPRToReg(base)]].reg := -2 - base END
   END;
   IF (instr.reg > none) & IsAllocatable(instr.reg) THEN
    regTab[GPRToReg(instr.reg)] := instr.dest
   END;
   RETURN
  END;
  FindMemReg(instr, mode, size, base, inx, disp);
  IF op # PUTreg THEN AssignReg(instr.dest, base, base, inx) END;
  (* RV32: For absolute data references (base=noBase), load the absolute address
     via LoadImm32 into the destination register, then use it as base.
     The linker patches the constant pool / LUI+ADDI with the final address.
     NOTE: Must come before indexed-access code because base=noBase (-1). *)
  IF (mode IN {RegMem, MemReg}) & (base = noBase) & ~instr.abs THEN
   OPO.EmitAbsLoad(instr.reg, disp, slotOff);
   AbsAccess(instr.node, slotOff);
   IF inx > none THEN
    IF instr.scale > 0 THEN
     OPO.GenSLLI(T0, inx, instr.scale);
     OPO.GenADD(instr.reg, instr.reg, T0)
    ELSE
     OPO.GenADD(instr.reg, instr.reg, inx)
    END
   END;
   CASE op OF
    Ld:
     IF size = Bit8 THEN OPO.GenLBU(instr.reg, instr.reg, 0)
     ELSIF size = Bit16 THEN OPO.GenLHU(instr.reg, instr.reg, 0)
     ELSE OPO.GenLW(instr.reg, instr.reg, 0)
     END
    | Lea: (* Address already in instr.reg *)
    | Ldbdw, Ldbw: OPO.GenLB(instr.reg, instr.reg, 0)
    | Ldwdw: OPO.GenLH(instr.reg, instr.reg, 0)
    | Ldbdwu, Ldbwu: OPO.GenLBU(instr.reg, instr.reg, 0)
    | Ldwdwu: OPO.GenLHU(instr.reg, instr.reg, 0)
   ELSE HALT(BUG)
   END;
   dummy := none;
   DecCheckReg(instr.dest, dummy, base, inx);
   RETURN
  END;
  (* Indexed memory access: compute base+index*scale into T0 *)
  memBase := base;
  IF inx > none THEN
   IF instr.scale > 0 THEN
    OPO.GenSLLI(T0, inx, instr.scale);
    OPO.GenADD(T0, base, T0)
   ELSE
    OPO.GenADD(T0, base, inx)
   END;
   memBase := T0
  END;
  CASE op OF
   Ld:
    IF mode = ImmReg THEN
     OPO.LoadImm32(instr.reg, instr.src2)
    ELSIF mode = RegReg THEN
     IF instr.reg # memBase THEN OPO.GenMOV(instr.reg, memBase) END
    ELSE
     EmitLoad(instr.reg, memBase, disp, size)
    END
   | Lea:
    IF disp = 0 THEN
     IF instr.reg # memBase THEN OPO.GenMOV(instr.reg, memBase) END
    ELSE
     EmitAddImm(instr.reg, memBase, disp)
    END;
    (* On x86, useReg4 maps to ESP so the result naturally goes to the stack pointer.
       On RV32, useReg4 maps to a4, so we must explicitly update SP. *)
    IF instr.hint = OPIR.useReg4 THEN OPO.GenMOV(SP, instr.reg) END
   | Ldbdw, Ldbw:
    IF mode = RegReg THEN
     OPO.GenSLLI(instr.reg, memBase, 24);
     OPO.GenSRAI(instr.reg, instr.reg, 24)
    ELSE
     EmitLoadSigned(instr.reg, memBase, disp, Bit8)
    END
   | Ldwdw:
    IF mode = RegReg THEN
     OPO.GenSLLI(instr.reg, memBase, 16);
     OPO.GenSRAI(instr.reg, instr.reg, 16)
    ELSE
     EmitLoadSigned(instr.reg, memBase, disp, Bit16)
    END
   | Ldbdwu, Ldbwu:
    IF mode = RegReg THEN
     EmitAndImm(instr.reg, memBase, 0FFH)
    ELSE
     EmitLoad(instr.reg, memBase, disp, Bit8)
    END
   | Ldwdwu:
    IF mode = RegReg THEN
     OPO.GenSLLI(instr.reg, memBase, 16);
     OPO.GenSRLI(instr.reg, instr.reg, 16)
    ELSE
     EmitLoad(instr.reg, memBase, disp, Bit16)
    END
   | PUTreg:
    IF mode = ImmReg THEN
     OPO.LoadImm32(SHORT(SHORT(instr.hint)), instr.src2)
    ELSE
     IF SHORT(SHORT(instr.hint)) # base THEN
      OPO.GenMOV(SHORT(SHORT(instr.hint)), base)
     END
    END
  ELSE HALT(BUG)
  END;
  dummy := none;
  DecCheckReg(instr.dest, dummy, base, inx)
 END Load;

 PROCEDURE LoadProc(VAR instr: Instruction);
 (* ldProc, ldXProc: load procedure address *)
 (* Always emit LUI+ADDI pair (8 bytes) so AddLink offset pc-8 is correct.
    LoadImm32 may emit only ADDI for small values, breaking the chain. *)
  VAR dummy: SHORTINT; imm, lo12, hi20: LONGINT;
 BEGIN
  dummy := none;
  AssignReg(instr.dest, dummy, dummy, dummy);
  IF instr.op DIV 32 = LdProc THEN
   imm := SHORT(instr.src1 MOD 10000H)
  ELSE (* LdXProc *)
   imm := -1
  END;
  lo12 := imm MOD 1000H;
  IF lo12 >= 800H THEN lo12 := lo12 - 1000H END;
  hi20 := (imm - lo12) DIV 1000H;
  OPO.GenLUI(instr.reg, hi20 MOD 100000H);
  OPO.GenADDI(instr.reg, instr.reg, lo12);
  IF instr.op DIV 32 = LdProc THEN
   AddLink(LocProcAssIndex, OPO.pc - 8)
  ELSE
   AddLink(SHORT(instr.src1 MOD 10000H), OPO.pc - 8)
  END;
  DecCheckReg(instr.dest, dummy, dummy, dummy)
 END LoadProc;

 PROCEDURE Store(VAR instr: Instruction);
 (* store, getReg *)
  VAR
   mode, size, reg, base, inx, memBase: SHORTINT;
   disp, slotOff: LONGINT;
 BEGIN
  FindMemReg(instr, mode, size, base, inx, disp);
  (* RV32: For absolute data references (base=noBase), load address into T0 *)
  IF (mode IN {RegMem, MemReg}) & (base = noBase) & ~instr.abs THEN
   OPO.EmitAbsLoad(T0, disp, slotOff);
   AbsAccess(instr.node, slotOff);
   IF inx > none THEN
    IF instr.scale > 0 THEN
     (* Use T1 for shift since T0 holds the address *)
     OPO.GenSLLI(T1, inx, instr.scale);
     OPO.GenADD(T0, T0, T1)
    ELSE
     OPO.GenADD(T0, T0, inx)
    END
   END;
   IF instr.op DIV 32 = GETreg THEN
    OPO.GenMOV(SHORT(SHORT(instr.hint)), T0);
    reg := none
   ELSIF ~loaded(instr.dest) & ((OPIR.Instr[instr.dest].op DIV 8) MOD 4 = ImmReg) THEN
    OPO.LoadImm32(T1, OPIR.Instr[instr.dest].src2);
    IF size = Bit8 THEN OPO.GenSB(T1, T0, 0)
    ELSIF size = Bit16 THEN OPO.GenSH(T1, T0, 0)
    ELSE OPO.GenSW(T1, T0, 0)
    END;
    reg := none
   ELSE
    FindLoadReg(instr.dest, reg);
    IF size = Bit8 THEN OPO.GenSB(reg, T0, 0)
    ELSIF size = Bit16 THEN OPO.GenSH(reg, T0, 0)
    ELSE OPO.GenSW(reg, T0, 0)
    END
   END;
   DecReg(reg); DecReg(base); DecReg(inx);
   RETURN
  END;
  memBase := base;
  IF inx > none THEN
   IF instr.scale > 0 THEN
    OPO.GenSLLI(T0, inx, instr.scale);
    OPO.GenADD(T0, base, T0)
   ELSE
    OPO.GenADD(T0, base, inx)
   END;
   memBase := T0
  END;
  IF instr.op DIV 32 = GETreg THEN
   IF SHORT(SHORT(instr.hint)) # memBase THEN
    OPO.GenMOV(SHORT(SHORT(instr.hint)), memBase)
   END;
   reg := none
  ELSIF (memBase # T0) & ~loaded(instr.dest) & ((OPIR.Instr[instr.dest].op DIV 8) MOD 4 = ImmReg) THEN
   OPO.LoadImm32(T0, OPIR.Instr[instr.dest].src2);
   EmitStore(T0, memBase, disp, size);
   reg := none
  ELSE
   FindLoadReg(instr.dest, reg);
   EmitStore(reg, memBase, disp, size)
  END;
  DecReg(reg); DecReg(base); DecReg(inx)
 END Store;

 PROCEDURE GenPush(VAR instr: Instruction);
 (* push: push value onto stack *)
  VAR reg: SHORTINT;
 BEGIN
  IF (instr.op DIV 8) MOD 4 = ImmReg THEN
   OPO.LoadImm32(T0, instr.src2);
   OPO.GenADDI(SP, SP, -4);
   OPO.GenSW(T0, SP, 0)
  ELSE
   FindLoadReg(instr.src1, reg);
   OPO.GenADDI(SP, SP, -4);
   OPO.GenSW(reg, SP, 0);
   DecReg(reg)
  END
 END GenPush;

 PROCEDURE GenPop(VAR instr: Instruction);
 (* pop: pop value from stack into register *)
  VAR dummy: SHORTINT;
 BEGIN
  dummy := none;
  AssignReg(instr.dest, dummy, dummy, dummy);
  OPO.GenLW(instr.reg, SP, 0);
  OPO.GenADDI(SP, SP, 4)
 END GenPop;


 PROCEDURE Gen2(VAR instr: Instruction);
 (* neg, not *)
  VAR src, dummy: SHORTINT; op: LONGINT;
 BEGIN
  op := instr.op DIV 32;
  FindLoadReg(instr.src1, src);
  dummy := none;
  AssignReg(instr.dest, src, dummy, dummy);
  IF op = Neg THEN
   (* NEG: SUB Rd, x0, Rs *)
   OPO.GenSUB(instr.reg, X0, src)
  ELSE (* Not: XORI Rd, Rs, -1 *)
   OPO.GenXORI(instr.reg, src, -1)
  END;
  DecCheckReg(instr.dest, src, dummy, dummy)
 END Gen2;

 PROCEDURE Gen3(VAR instr: Instruction);
 (* add, sub, or, xor, and, sal, sar, shr, rol, bts, btr *)
  VAR
   mode, size, src, base, inx: SHORTINT;
   disp: LONGINT;
   op: LONGINT;
 BEGIN
  op := instr.op DIV 32;
  mode := SHORT((instr.op DIV 8) MOD 4);
  size := SHORT(instr.op MOD 8) * 8;
  IF mode = ImmReg THEN
   FindLoadReg(instr.src1, src);
   base := none; inx := none; disp := noDisp
  ELSIF ~loaded(instr.src1) THEN
   IF ~loaded(instr.src2) THEN
    FindLoadReg(instr.src1, src);
    FindLoadReg(instr.src2, base)
   ELSIF (op = Add) OR (op = oR) OR (op = Xor) OR (op = And) THEN
    FindReg(instr.src2, src);
    FindLoadReg(instr.src1, base)
   ELSE
    FindLoadReg(instr.src1, src);
    FindReg(instr.src2, base)
   END;
   inx := none; disp := noDisp
  ELSIF ~loaded(instr.src2) THEN
   FindReg(instr.src1, src);
   FindLoadReg(instr.src2, base);
   inx := none; disp := noDisp
  ELSE
   FindReg(instr.src1, src);
   FindReg(instr.src2, base);
   inx := none; disp := noDisp
  END;
  AssignReg(instr.dest, src, base, inx);
  IF instr.reg # src THEN OPO.GenMOV(instr.reg, src) END;
  CASE op OF
   Add:
    IF mode = ImmReg THEN EmitAddImm(instr.reg, instr.reg, instr.src2)
    ELSE OPO.GenADD(instr.reg, instr.reg, base)
    END
   | Sub:
    IF mode = ImmReg THEN EmitSubImm(instr.reg, instr.reg, instr.src2)
    ELSE OPO.GenSUB(instr.reg, instr.reg, base)
    END
   | oR:
    IF mode = ImmReg THEN EmitOrImm(instr.reg, instr.reg, instr.src2)
    ELSE OPO.GenOR(instr.reg, instr.reg, base)
    END
   | Xor:
    IF mode = ImmReg THEN EmitXorImm(instr.reg, instr.reg, instr.src2)
    ELSE OPO.GenXOR(instr.reg, instr.reg, base)
    END
   | And:
    IF mode = ImmReg THEN EmitAndImm(instr.reg, instr.reg, instr.src2)
    ELSE OPO.GenAND(instr.reg, instr.reg, base)
    END
   | Sal:
    IF mode = ImmReg THEN OPO.GenSLLI(instr.reg, src, SHORT(instr.src2))
    ELSE OPO.GenSLL(instr.reg, src, base)
    END
   | Sar:
    IF mode = ImmReg THEN OPO.GenSRAI(instr.reg, src, SHORT(instr.src2))
    ELSE OPO.GenSRA(instr.reg, src, base)
    END
   | Shr:
    IF mode = ImmReg THEN OPO.GenSRLI(instr.reg, src, SHORT(instr.src2))
    ELSE OPO.GenSRL(instr.reg, src, base)
    END
   | Rol:
    (* Rotate left: ROL n = (x << n) | (x >> (32-n)) *)
    IF mode = ImmReg THEN
     OPO.GenSLLI(T0, src, SHORT(instr.src2 MOD 32));
     OPO.GenSRLI(instr.reg, src, SHORT((32 - instr.src2) MOD 32));
     OPO.GenOR(instr.reg, instr.reg, T0)
    ELSE
     (* ROL by register: T0 = x << base; T1 = 32 - base; instr.reg = x >> T1; OR *)
     OPO.GenSLL(T0, src, base);
     OPO.LoadImm32(T1, 32);
     OPO.GenSUB(T1, T1, base);
     OPO.GenSRL(instr.reg, src, T1);
     OPO.GenOR(instr.reg, instr.reg, T0)
    END
   | Bts:
    (* Bit test and set: reg := reg OR (1 << bit) *)
    IF mode = ImmReg THEN
     OPO.LoadImm32(T0, 1);
     OPO.GenSLLI(T0, T0, SHORT(instr.src2));
     OPO.GenOR(instr.reg, instr.reg, T0)
    ELSE
     OPO.LoadImm32(T0, 1);
     OPO.GenSLL(T0, T0, base);
     OPO.GenOR(instr.reg, instr.reg, T0)
    END
   | Btr:
    (* Bit test and reset: reg := reg AND NOT(1 << bit) *)
    IF mode = ImmReg THEN
     OPO.LoadImm32(T0, 1);
     OPO.GenSLLI(T0, T0, SHORT(instr.src2));
     OPO.GenXORI(T0, T0, -1); (* NOT T0 *)
     OPO.GenAND(instr.reg, instr.reg, T0)
    ELSE
     OPO.LoadImm32(T0, 1);
     OPO.GenSLL(T0, T0, base);
     OPO.GenXORI(T0, T0, -1);
     OPO.GenAND(instr.reg, instr.reg, T0)
    END
  ELSE HALT(BUG)
  END;
  (* On x86, useReg4 maps to ESP so arithmetic results go directly to the stack pointer.
     On RV32, useReg4 maps to a4, so we must explicitly update SP after the computation. *)
  IF instr.hint = OPIR.useReg4 THEN OPO.GenMOV(SP, instr.reg) END;
  DecCheckReg(instr.dest, src, base, inx)
 END Gen3;

 PROCEDURE GenAbs(VAR instr: Instruction);
 (* abs: absolute value *)
 (* RV32: if x < 0, negate it. Use SRA to get sign, XOR+SUB to negate conditionally. *)
  VAR src, dummy: SHORTINT;
 BEGIN
  FindLoadReg(instr.src1, src);
  dummy := none;
  AssignReg(instr.dest, src, dummy, dummy);
  IF instr.reg # src THEN OPO.GenMOV(instr.reg, src) END;
  (* T0 = sign = x >> 31 (all 0s or all 1s) *)
  OPO.GenSRAI(T0, instr.reg, 31);
  (* x = (x XOR sign) - sign *)
  OPO.GenXOR(instr.reg, instr.reg, T0);
  OPO.GenSUB(instr.reg, instr.reg, T0);
  DecCheckReg(instr.dest, src, dummy, dummy)
 END GenAbs;

 PROCEDURE GenMul(VAR instr: Instruction);
 (* mul: integer multiply *)
  VAR src, base, dummy: SHORTINT; mode: LONGINT;
 BEGIN
  mode := (instr.op DIV 8) MOD 4;
  IF mode = ImmReg THEN
   FindLoadReg(instr.src1, src);
   OPO.LoadImm32(T0, instr.src2);
   base := T0
  ELSIF loaded(instr.src2) THEN
   FindReg(instr.src2, base);
   IF ~loaded(instr.src1) THEN FindLoadReg(instr.src1, src)
   ELSE FindReg(instr.src1, src)
   END
  ELSE
   IF ~loaded(instr.src1) THEN FindLoadReg(instr.src1, src)
   ELSE FindReg(instr.src1, src)
   END;
   FindLoadReg(instr.src2, base)
  END;
  dummy := none;
  AssignReg(instr.dest, src, base, dummy);
  OPO.GenMUL(instr.reg, src, base);
  DecCheckReg(instr.dest, src, base, dummy)
 END GenMul;

 PROCEDURE GenDivMod(VAR instr: Instruction);
 (* div, mod: Oberon floor division/modulo
  RV32 DIV truncates toward zero. Oberon requires floor division. *)
  VAR
   src, base, dummy: SHORTINT;
   mode: LONGINT;
   isDiv: BOOLEAN;
 BEGIN
  mode := (instr.op DIV 8) MOD 4;
  isDiv := instr.op DIV 32 = Div;
  IF mode = ImmReg THEN
   FindLoadReg(instr.src1, src);
   OPO.LoadImm32(T0, instr.src2);
   base := T0
  ELSIF loaded(instr.src2) THEN
   FindReg(instr.src2, base);
   IF ~loaded(instr.src1) THEN FindLoadReg(instr.src1, src)
   ELSE FindReg(instr.src1, src)
   END
  ELSE
   IF ~loaded(instr.src1) THEN FindLoadReg(instr.src1, src)
   ELSE FindReg(instr.src1, src)
   END;
   FindLoadReg(instr.src2, base)
  END;
  dummy := none;
  AssignReg(instr.dest, src, base, dummy);

  OPO.GenADDI(SP, SP, -4); OPO.GenSW(src, SP, 0);   (* push dividend *)
  OPO.GenADDI(SP, SP, -4); OPO.GenSW(base, SP, 0);   (* push divisor *)

  OPO.GenDIV(instr.reg, src, base);

  OPO.GenADDI(SP, SP, -4); OPO.GenSW(instr.reg, SP, 0);  (* push quotient *)
  (* Stack: [quotient(SP+0), divisor(SP+4), dividend(SP+8)] *)

  (* Compute remainder = dividend - quotient * divisor *)
  OPO.GenLW(instr.reg, SP, 0);   (* quotient *)
  OPO.GenLW(T0, SP, 4);          (* divisor *)
  OPO.GenMUL(T0, instr.reg, T0); (* quotient * divisor *)
  OPO.GenLW(instr.reg, SP, 8);   (* dividend *)
  OPO.GenSUB(T0, instr.reg, T0); (* T0 = remainder *)

  (* Floor correction: XOR remainder with divisor, check sign *)
  OPO.GenLW(instr.reg, SP, 4);        (* divisor *)
  OPO.GenXOR(T0, T0, instr.reg);      (* T0 = remainder XOR divisor *)
  OPO.GenSRAI(T0, T0, 31);            (* T0 = sign fill (0 or -1) *)
  EmitAndImm(T0, T0, 1);              (* T0 = correction (0 or 1) *)

  OPO.GenLW(instr.reg, SP, 0);        (* quotient *)
  OPO.GenSUB(instr.reg, instr.reg, T0); (* corrected quotient *)

  IF ~isDiv THEN
   (* MOD: result = dividend - corrected_quotient * divisor *)
   OPO.GenLW(T0, SP, 4);              (* divisor *)
   OPO.GenMUL(T0, instr.reg, T0);     (* corrected_quotient * divisor *)
   OPO.GenLW(instr.reg, SP, 8);       (* dividend *)
   OPO.GenSUB(instr.reg, instr.reg, T0) (* floor mod *)
  END;

  (* Clean up stack: 12 bytes *)
  OPO.GenADDI(SP, SP, 12);

  DecCheckReg(instr.dest, src, base, dummy)
 END GenDivMod;


(* RV32 comparison mechanism: Instead of ARM's condition codes (flags),
   we store comparison operands in T5 (x30) and T6 (x31), then use
   conditional branch instructions (BEQ/BNE/BLT/BGE/BLTU/BGEU) on T5,T6.
   OPO.EmitCondBranch handles the mapping from internal cc to branch instruction. *)

 PROCEDURE Flags(VAR instr: Instruction);
 (* cmp, bt, test: set comparison registers T5, T6 *)
  VAR
   mode, size, base, inx, reg: SHORTINT;
   disp: LONGINT;
   op: LONGINT;
 BEGIN
  op := instr.op DIV 32;
  mode := SHORT((instr.op DIV 8) MOD 4);
  size := SHORT(instr.op MOD 8) * 8;
  IF mode = ImmReg THEN
   FindLoadReg(instr.src1, reg);
   base := none; inx := none; disp := noDisp
  ELSIF ~loaded(instr.src1) THEN
   IF ~loaded(instr.src2) THEN
    FindLoadReg(instr.src1, reg);
    FindLoadReg(instr.src2, base)
   ELSE
    FindReg(instr.src2, base);
    FindLoadReg(instr.src1, reg)
   END;
   inx := none; disp := noDisp
  ELSIF ~loaded(instr.src2) THEN
   FindReg(instr.src1, reg);
   FindLoadReg(instr.src2, base);
   inx := none; disp := noDisp
  ELSE
   FindReg(instr.src1, reg);
   FindReg(instr.src2, base);
   inx := none; disp := noDisp
  END;
  IF op = Cmp THEN
   (* CMP: store operands in T5, T6 for subsequent conditional branch *)
   OPO.GenMOV(T5, reg);
   IF mode = ImmReg THEN
    OPO.LoadImm32(T6, instr.src2)
   ELSE
    OPO.GenMOV(T6, base)
   END
  ELSIF op = Test THEN
   (* TEST: T5 = reg AND imm/base, T6 = 0 *)
   IF mode = ImmReg THEN
    EmitAndImm(T5, reg, instr.src2)
   ELSE
    OPO.GenAND(T5, reg, base)
   END;
   OPO.GenMOV(T6, X0)
  ELSE (* Bt: bit test *)
   (* BT: test if bit is set. T5 = (reg >> bit) & 1, T6 = 0 *)
   IF mode = ImmReg THEN
    OPO.GenSRLI(T5, reg, SHORT(instr.src2));
    EmitAndImm(T5, T5, 1)
   ELSE
    OPO.GenSRL(T5, reg, base);
    EmitAndImm(T5, T5, 1)
   END;
   OPO.GenMOV(T6, X0)
  END;
  DecReg(reg); DecReg(base); DecReg(inx)
 END Flags;

 PROCEDURE Setcc(VAR instr: Instruction);
 (* sete..setnc: set register to 0 or 1 based on condition *)
  VAR dummy: SHORTINT; op: LONGINT;
 BEGIN
  dummy := none;
  AssignReg(instr.dest, dummy, dummy, dummy);
  op := instr.op DIV 32;
  CASE op OF
   Sete:
    OPO.GenSUB(instr.reg, T5, T6);
    OPO.GenSLTIU(instr.reg, instr.reg, 1)
   | Setne:
    OPO.GenSUB(instr.reg, T5, T6);
    OPO.GenSLTU(instr.reg, X0, instr.reg)
   | Setl:
    OPO.GenSLT(instr.reg, T5, T6)
   | Setle:
    OPO.GenSLT(instr.reg, T6, T5);
    OPO.GenXORI(instr.reg, instr.reg, 1)
   | Setg:
    OPO.GenSLT(instr.reg, T6, T5)
   | Setge:
    OPO.GenSLT(instr.reg, T5, T6);
    OPO.GenXORI(instr.reg, instr.reg, 1)
   | Seta:
    OPO.GenSLTU(instr.reg, T6, T5)
   | Setae:
    OPO.GenSLTU(instr.reg, T5, T6);
    OPO.GenXORI(instr.reg, instr.reg, 1)
   | Setb:
    OPO.GenSLTU(instr.reg, T5, T6)
   | Setbe:
    OPO.GenSLTU(instr.reg, T6, T5);
    OPO.GenXORI(instr.reg, instr.reg, 1)
   | Setc:
    OPO.GenSLTU(instr.reg, T5, T6)
   | Setnc:
    OPO.GenSLTU(instr.reg, T5, T6);
    OPO.GenXORI(instr.reg, instr.reg, 1)
  ELSE HALT(BUG)
  END
 END Setcc;

 PROCEDURE FixupFwdJumps(targetIR: LONGINT);
 (* Patch all forward jump placeholders targeting IR instruction targetIR.
    Scans the fixup table and patches each JAL x0 placeholder with the
    correct offset to the current OPO.pc. *)
  VAR j: LONGINT;
 BEGIN
  j := 0;
  WHILE j < nofFwdFixups DO
   IF fwdFixupTarget[j] = targetIR THEN
    OPO.EmitJALAt(fwdFixupPos[j], X0, OPO.pc - fwdFixupPos[j]);
    (* Mark as done by setting target to Nil *)
    fwdFixupTarget[j] := Nil
   END;
   INC(j)
  END
 END FixupFwdJumps;

 PROCEDURE Gen1(VAR instr: Instruction; instrNr: LONGINT);
  VAR op, target: LONGINT; cc: LONGINT; reg: SHORTINT;
 BEGIN
  op := instr.op DIV 32;
  IF op = JmpReg THEN
   (* Indirect jump via register *)
   FindLoadReg(instr.src2, reg);
   OPO.GenJALR(X0, reg, 0);
   DecReg(reg);
   RETURN
  END;
  target := instr.src2;
  IF op = Jmp THEN
   IF instrNr >= target THEN
    (* Backward unconditional jump: target PC is known *)
    OPO.GenJAL(X0, OPIR.Instr[target].pc - OPO.pc)
   ELSE
    (* Forward unconditional jump: emit placeholder, patch later *)
    IF nofFwdFixups < MaxFwdFixups THEN
     fwdFixupPos[nofFwdFixups] := OPO.pc;
     fwdFixupTarget[nofFwdFixups] := target;
     INC(nofFwdFixups)
    END;
    OPO.GenJAL(X0, 0)
   END
  ELSE
   (* Conditional branch: determine condition code *)
   CASE op OF
    Je:  cc := ccEQ
    | Jne: cc := ccNE
    | Jl:  cc := ccLT
    | Jle: cc := ccLE
    | Jg:  cc := ccGT
    | Jge: cc := ccGE
    | Ja:  cc := ccHI
    | Jae: cc := ccHS
    | Jb:  cc := ccLO
    | Jbe: cc := ccLS
    | Jc:  cc := ccCS
    | Jnc: cc := ccCC
   ELSE HALT(BUG); cc := ccEQ
   END;
   IF instrNr >= target THEN
    (* Backward conditional branch: target PC is known *)
    OPO.EmitCondBranch(cc, OPIR.Instr[target].pc - OPO.pc)
   ELSE
    (* Forward conditional branch: emit inverted branch + JAL placeholder *)
    OPO.EmitCondBranch(OPO.InvertCC(cc), 8);
    IF nofFwdFixups < MaxFwdFixups THEN
     fwdFixupPos[nofFwdFixups] := OPO.pc;
     fwdFixupTarget[nofFwdFixups] := target;
     INC(nofFwdFixups)
    END;
    OPO.GenJAL(X0, 0)
   END
  END
 END Gen1;

 PROCEDURE GenRepMovs(VAR instr: Instruction);
 (* repMovs: block memory copy *)
  VAR dest, src, nofElem: SHORTINT; Lloop: LONGINT;
    step: LONGINT; reverse, stackPush: BOOLEAN;
 BEGIN
  IF loaded(instr.dest) THEN FindReg(instr.dest, dest) ELSE FindLoadReg(instr.dest, dest) END;
  IF loaded(instr.src1) THEN FindReg(instr.src1, src) ELSE FindLoadReg(instr.src1, src) END;
  IF loaded(instr.src2) THEN FindReg(instr.src2, nofElem) ELSE FindLoadReg(instr.src2, nofElem) END;
  reverse := instr.hint = 1;
  IF instr.inx = Bit32 THEN step := 4
  ELSIF instr.inx = Bit16 THEN step := 2
  ELSE step := 1
  END;
  IF reverse THEN step := -step END;
  stackPush := ~reverse & (dest = SP);
  IF stackPush THEN
   IF step = 4 THEN
    OPO.GenSLLI(T0, nofElem, 2);
    OPO.GenADD(src, src, T0)
   ELSIF step = 2 THEN
    OPO.GenSLLI(T0, nofElem, 1);
    OPO.GenADD(src, src, T0)
   ELSE
    OPO.GenADD(src, src, nofElem)
   END
  END;
  OPO.GenBEQ(nofElem, X0, 6*4);
  Lloop := OPO.pc;
  IF stackPush THEN
   OPO.GenADDI(src, src, -step);
   OPO.GenADDI(dest, dest, -step);
   IF (step = 4) OR (step = -4) THEN
    OPO.GenLW(T0, src, 0); OPO.GenSW(T0, dest, 0)
   ELSE
    OPO.GenLBU(T0, src, 0); OPO.GenSB(T0, dest, 0)
   END
  ELSIF (ABS(step) = 4) THEN
   OPO.GenLW(T0, src, 0); OPO.GenSW(T0, dest, 0);
   OPO.GenADDI(src, src, step); OPO.GenADDI(dest, dest, step)
  ELSIF (ABS(step) = 2) THEN
   OPO.GenLHU(T0, src, 0); OPO.GenSH(T0, dest, 0);
   OPO.GenADDI(src, src, step); OPO.GenADDI(dest, dest, step)
  ELSE
   OPO.GenLBU(T0, src, 0); OPO.GenSB(T0, dest, 0);
   OPO.GenADDI(src, src, step); OPO.GenADDI(dest, dest, step)
  END;
  OPO.GenADDI(nofElem, nofElem, -1);
  OPO.GenBNE(nofElem, X0, Lloop - OPO.pc);
  DecReg(dest); DecReg(src); DecReg(nofElem)
 END GenRepMovs;

 PROCEDURE GenCmpString(VAR instr: Instruction);
 (* cmpString: compare two null-terminated strings *)
  VAR srcAdr, src2Adr, ch1, ch2: SHORTINT; Lloop: LONGINT;
 BEGIN
  IF loaded(instr.src2) THEN
   FindReg(instr.src2, src2Adr);
   IF ~loaded(instr.src1) THEN FindLoadReg(instr.src1, srcAdr)
   ELSE FindReg(instr.src1, srcAdr)
   END
  ELSE
   IF ~loaded(instr.src1) THEN FindLoadReg(instr.src1, srcAdr)
   ELSE FindReg(instr.src1, srcAdr)
   END;
   FindLoadReg(instr.src2, src2Adr)
  END;
  GetReg(ch1); GetReg(ch2);
  Lloop := OPO.pc;
  OPO.GenLBU(ch1, srcAdr, 0);
  OPO.GenADDI(srcAdr, srcAdr, 1);
  OPO.GenLBU(ch2, src2Adr, 0);
  OPO.GenADDI(src2Adr, src2Adr, 1);
  OPO.GenBNE(ch1, ch2, 2*4);
  OPO.GenBNE(ch1, X0, Lloop - OPO.pc);
  OPO.GenMOV(T5, ch1);
  OPO.GenMOV(T6, ch2);
  FreeReg(ch1); FreeReg(ch2);
  DecReg(srcAdr); DecReg(src2Adr)
 END GenCmpString;

 PROCEDURE GenShort(VAR instr: Instruction);
 (* short: truncate to shorter type *)
  VAR src: SHORTINT; size: LONGINT;
 BEGIN
  FindReg(instr.src1, src);
  size := (instr.op MOD 8) * 8;
  ASSERT(LastUse(src));
  IF size = Bit16 THEN
   EmitAndImm(src, src, 0FFFFH)
  ELSE
   EmitAndImm(src, src, 0FFH)
  END;
  FreeReg(src);
  AssignThisReg(instr.dest, src)
 END GenShort;

 PROCEDURE GenPhi(VAR instr: Instruction);
 (* phi: SSA phi node *)
  VAR src1, src2: SHORTINT;
 BEGIN
  ASSERT((OPIR.Instr[instr.src2].reg >= 0) & (OPIR.Instr[instr.src1].reg # none));
  IF OPIR.Instr[instr.src1].reg < 0 THEN src1 := SHORT(-2 - OPIR.Instr[instr.src1].reg)
  ELSE
   src1 := OPIR.Instr[instr.src1].reg;
   FreeReg(src1)
  END;
  src2 := OPIR.Instr[instr.src2].reg;
  IF src1 # src2 THEN
   AssignThisReg(instr.src2, src1);
   OPO.GenMOV(src1, src2);
   IF IsAllocatable(src2) THEN regTab[GPRToReg(src2)] := free END
  END
 END GenPhi;

 PROCEDURE GenTrap(trapNr: LONGINT);
 (* Emit a trap: LUI x0,trapNr (NOP encoding trap number) + EBREAK *)
 BEGIN
  OPO.GenLUI(X0, trapNr MOD 100000H);
  OPO.GenEBREAK
 END GenTrap;

 PROCEDURE GenTrapCC(VAR instr: Instruction);
 (* te, tne, tle, ta, tae, to: conditional trap *)
  VAR cc: LONGINT; op: LONGINT;
 BEGIN
  op := instr.op DIV 32;
  IF op = To THEN
   GenTrap(instr.src2)
  ELSE
   CASE op OF
    Te:  cc := ccNE
    | Tne: cc := ccEQ
    | Tle: cc := ccGT
    | Ta:  cc := ccLS
    | Tae: cc := ccLO
   ELSE HALT(BUG); cc := ccAL
   END;
   OPO.EmitCondBranch(cc, 12);
   GenTrap(instr.src2)
  END
 END GenTrapCC;

 PROCEDURE FixupAndGenTrap;
 (* Generate trap code for all pending trap fixups *)
  VAR i: LONGINT;
 BEGIN
  i := 0;
  WHILE i < nofTrapFixups DO
   IF trapFixupTab[i] # Nil THEN
    GenTrap(i)
   END;
   INC(i)
  END
 END FixupAndGenTrap;


(* RV32F: Single-precision (REAL) uses hardware FPU via F extension.
   Double-precision (LONGREAL) uses SysFix soft-float calls.
   The SysFix entries are established in multibootlinker.c. *)

 PROCEDURE Fload(VAR instr: Instruction);
 (* fload, fild: load floating-point value *)
  VAR
   mode, size, base, inx, dummy: SHORTINT;
   disp, slotOff: LONGINT;
   op: LONGINT;
   hiReg: SHORTINT;
 BEGIN
  op := instr.op DIV 32;
  FindMemReg(instr, mode, size, base, inx, disp);
  IF IsSinglePrec(instr) & (op = Fild) THEN
   (* Single-precision integer-to-float: FCVT.S.W *)
   AssignFreg(instr.dest);
   FindLoadReg(instr.src1, base);
   OPO.GenFCVTSW(instr.reg, base, 0); (* rm=0: RNE = round nearest even *)
   DecReg(base)
  ELSIF IsSinglePrec(instr) THEN
   (* Single precision: use hardware FPU register *)
   AssignFreg(instr.dest);
   IF (mode IN {RegMem, MemReg}) & (base = noBase) & ~instr.abs THEN
    (* Global variable: load address, then FLW *)
    OPO.EmitAbsLoad(T0, disp, slotOff);
    AbsAccess(instr.node, slotOff);
    IF inx > none THEN
     IF instr.scale > 0 THEN
      OPO.GenSLLI(T1, inx, instr.scale);
      OPO.GenADD(T0, T0, T1)
     ELSE
      OPO.GenADD(T0, T0, inx)
     END
    END;
    OPO.GenFLW(instr.reg, T0, 0)
   ELSIF inx > none THEN
    IF instr.scale > 0 THEN
     OPO.GenSLLI(T0, inx, instr.scale);
     OPO.GenADD(T0, base, T0)
    ELSE
     OPO.GenADD(T0, base, inx)
    END;
    EmitFLoad(instr.reg, T0, disp)
   ELSIF mode = ImmReg THEN
    (* Load immediate float: put bits in T0, then FMV.W.X *)
    OPO.LoadImm32(T0, instr.src2);
    OPO.GenFMVWX(instr.reg, T0)
   ELSE
    EmitFLoad(instr.reg, base, disp)
   END
  ELSE
   (* LONGREAL (double-precision) path: values are 8 bytes (lo + hi word) *)
   dummy := none;
   AssignReg(instr.dest, base, dummy, dummy);
   IF op = Fild THEN
    (* fild double-prec: load integer from memory, call Float64.CvtIF with resAddr *)
    IF (mode IN {RegMem, MemReg}) & (base = noBase) & ~instr.abs THEN
     OPO.EmitAbsLoad(T0, disp, slotOff);
     AbsAccess(instr.node, slotOff);
     OPO.GenLW(T0, T0, 0)
    ELSE
     EmitLoad(T0, base, disp, Bit32)
    END;
    (* Allocate 16 bytes: 8 params (ival, resAddr) + 8 result area.
       Oberon convention: last param at lowest address (sp+0). *)
    OPO.GenADDI(SP, SP, -16);
    OPO.GenADDI(T1, SP, 8);       (* compute resAddr = sp+8 *)
    OPO.GenSW(T1, SP, 0);         (* sp+0 = resAddr (2nd/last param) *)
    OPO.GenSW(T0, SP, 4);         (* sp+4 = ival (1st/first param) *)
    OPO.GenJAL(RA, 0);
    AddLink(F64CvtIFLinkIndex, OPO.pc - 4);
    (* Callee cleans 8 bytes of params; sp now points to result area *)
    OPO.GenLW(instr.reg, SP, 0);  (* resultLo *)
    GetReg(hiReg);
    OPO.GenLW(hiReg, SP, 4);      (* resultHi *)
    SetLRealHi(instr.reg, hiReg);
    OPO.GenADDI(SP, SP, 8)        (* clean up result area *)
   ELSE
    (* fload double-prec: load both lo and hi words (8 bytes) *)
    GetReg(hiReg);
    IF (mode IN {RegMem, MemReg}) & (base = noBase) & ~instr.abs THEN
     OPO.EmitAbsLoad(T0, disp, slotOff);
     AbsAccess(instr.node, slotOff);
     OPO.GenLW(instr.reg, T0, 0);  (* lo word *)
     OPO.GenLW(hiReg, T0, 4)       (* hi word *)
    ELSE
     EmitLoad(instr.reg, base, disp, Bit32);       (* lo word *)
     EmitLoad(hiReg, base, disp + 4, Bit32)         (* hi word *)
    END;
    SetLRealHi(instr.reg, hiReg)
   END
  END;
  dummy := none;
  DecReg(base); DecReg(inx)
 END Fload;

 PROCEDURE Fstore(VAR instr: Instruction);
 (* fstore, fist: store floating-point value *)
  VAR
   mode, size, base, inx, freg: SHORTINT;
   disp, slotOff: LONGINT;
   op: LONGINT;
   hiReg: SHORTINT;
 BEGIN
  op := instr.op DIV 32;
  FindMemReg(instr, mode, size, base, inx, disp);
  IF IsSinglePrec(instr) & (op = Fist) THEN
   (* Single-precision REAL to integer: FCVT.W.S *)
   FindFreg(instr.src1, freg);
   OPO.GenFCVTWS(T0, freg, 1); (* rm=1: RTZ = truncate toward zero *)
   DecCheckFreg(freg);
   IF (mode IN {RegMem, MemReg}) & (base = noBase) & ~instr.abs THEN
    OPO.EmitAbsLoad(T1, disp, slotOff);
    AbsAccess(instr.node, slotOff);
    OPO.GenSW(T0, T1, 0)
   ELSE
    EmitStore(T0, base, disp, Bit32)
   END
  ELSIF IsSinglePrec(instr) THEN
   FindFreg(instr.src1, freg);
   IF (mode IN {RegMem, MemReg}) & (base = noBase) & ~instr.abs THEN
    OPO.EmitAbsLoad(T0, disp, slotOff);
    AbsAccess(instr.node, slotOff);
    IF inx > none THEN
     IF instr.scale > 0 THEN
      OPO.GenSLLI(T1, inx, instr.scale);
      OPO.GenADD(T0, T0, T1)
     ELSE
      OPO.GenADD(T0, T0, inx)
     END
    END;
    OPO.GenFSW(freg, T0, 0)
   ELSIF inx > none THEN
    IF instr.scale > 0 THEN
     OPO.GenSLLI(T0, inx, instr.scale);
     OPO.GenADD(T0, base, T0)
    ELSE
     OPO.GenADD(T0, base, inx)
    END;
    EmitFStore(freg, T0, disp)
   ELSE
    EmitFStore(freg, base, disp)
   END;
   DecCheckFreg(freg)
  ELSE
   (* LONGREAL (double-precision) path: store both lo and hi words (8 bytes) *)
   IF op = Fist THEN
    (* fist double-prec: LONGREAL to integer via Float64.CvtFI *)
    FindLoadReg(instr.dest, freg);
    hiReg := GetLRealHi(freg);
    (* Oberon convention: last param at lowest address (sp+0). *)
    OPO.GenADDI(SP, SP, -8);
    IF hiReg > -1 THEN
     OPO.GenSW(hiReg, SP, 0);  (* sp+0 = hiA (2nd/last param) *)
     FreeReg(hiReg); SetLRealHi(freg, -1)
    ELSE OPO.GenSW(X0, SP, 0)  (* sp+0 = hiA = 0 *)
    END;
    OPO.GenSW(freg, SP, 4);    (* sp+4 = loA (1st/first param) *)
    DecReg(freg);
    OPO.GenJAL(RA, 0);
    AddLink(F64CvtFILinkIndex, OPO.pc - 4);
    (* Callee cleans 8 bytes of params. Result in a0 *)
    IF (mode IN {RegMem, MemReg}) & (base = noBase) & ~instr.abs THEN
     OPO.EmitAbsLoad(T0, disp, slotOff);
     AbsAccess(instr.node, slotOff);
     OPO.GenSW(A0, T0, 0)
    ELSE
     EmitStore(A0, base, disp, Bit32)
    END
   ELSE
    (* fstore double-prec: store both lo and hi words *)
    FindLoadReg(instr.dest, freg);
    hiReg := GetLRealHi(freg);
    IF (mode IN {RegMem, MemReg}) & (base = noBase) & ~instr.abs THEN
     OPO.EmitAbsLoad(T0, disp, slotOff);
     AbsAccess(instr.node, slotOff);
     OPO.GenSW(freg, T0, 0);       (* lo word *)
     IF hiReg > -1 THEN
      OPO.GenSW(hiReg, T0, 4)      (* hi word *)
     END
    ELSE
     EmitStore(freg, base, disp, Bit32);         (* lo word *)
     IF hiReg > -1 THEN
      EmitStore(hiReg, base, disp + 4, Bit32)    (* hi word *)
     END
    END;
    IF hiReg > -1 THEN
     FreeReg(hiReg); SetLRealHi(freg, -1)
    END;
    DecReg(freg)
   END
  END;
  DecReg(base); DecReg(inx)
 END Fstore;

 PROCEDURE FloatGen3(VAR instr: Instruction);
 (* fadd, fsub, fmul, fdiv *)
  VAR op: LONGINT; src, src2: SHORTINT;
    srcHi, src2Hi: SHORTINT;
 BEGIN
  op := instr.op DIV 32;
  IF IsSinglePrec(instr) THEN
   (* Single precision: use hardware F extension *)
   FindFreg(instr.src1, src);
   FindFreg(instr.src2, src2);
   AssignFreg(instr.dest);
   CASE op OF
    Fadd: OPO.GenFADDS(instr.reg, src, src2)
    | Fsub: OPO.GenFSUBS(instr.reg, src, src2)
    | Fmul: OPO.GenFMULS(instr.reg, src, src2)
    | Fdiv: OPO.GenFDIVS(instr.reg, src, src2)
   ELSE HALT(BUG)
   END;
   DecCheckFreg(src); DecCheckFreg(src2)
  ELSE
   (* LONGREAL binary ops: push 5 words (loA, hiA, loB, hiB, resAddr) for Float64 *)
   FindLoadReg(instr.src1, src);
   srcHi := GetLRealHi(src);
   FindLoadReg(instr.src2, src2);
   src2Hi := GetLRealHi(src2);
   (* Allocate 28 bytes: 20 params + 8 result area.
      Oberon convention: last param at lowest address (sp+0). *)
   OPO.GenADDI(SP, SP, -28);
   (* resAddr = sp + 20 (address of result area) *)
   OPO.GenADDI(T0, SP, 20);
   OPO.GenSW(T0, SP, 0);           (* sp+0 = resAddr (5th/last param) *)
   IF src2Hi > -1 THEN
    OPO.GenSW(src2Hi, SP, 4);      (* sp+4 = hiB (4th param) *)
    FreeReg(src2Hi); SetLRealHi(src2, -1)
   ELSE OPO.GenSW(X0, SP, 4)       (* sp+4 = hiB = 0 *)
   END;
   OPO.GenSW(src2, SP, 8);         (* sp+8 = loB (3rd param) *)
   IF srcHi > -1 THEN
    OPO.GenSW(srcHi, SP, 12);      (* sp+12 = hiA (2nd param) *)
    FreeReg(srcHi); SetLRealHi(src, -1)
   ELSE OPO.GenSW(X0, SP, 12)      (* sp+12 = hiA = 0 *)
   END;
   OPO.GenSW(src, SP, 16);         (* sp+16 = loA (1st/first param) *)
   DecReg(src); DecReg(src2);
   OPO.GenJAL(RA, 0);
   CASE op OF
    Fadd: AddLink(F64AddLinkIndex, OPO.pc - 4)
    | Fsub: AddLink(F64SubLinkIndex, OPO.pc - 4)
    | Fmul: AddLink(F64MulLinkIndex, OPO.pc - 4)
    | Fdiv: AddLink(F64DivLinkIndex, OPO.pc - 4)
   ELSE HALT(BUG)
   END;
   (* Callee cleans 20 bytes of params; sp now points to result area *)
   AssignThisReg(instr.dest, A0);
   instr.reg := A0;
   OPO.GenLW(A0, SP, 0);           (* resultLo *)
   GetThisReg(A1);
   OPO.GenLW(A1, SP, 4);           (* resultHi *)
   SetLRealHi(A0, A1);
   OPO.GenADDI(SP, SP, 8)          (* clean up result area *)
  END
 END FloatGen3;

 PROCEDURE FloatGen2(VAR instr: Instruction);
 (* fabs, fchs (negate) *)
  VAR op: LONGINT; src: SHORTINT;
      srcHi: SHORTINT;
 BEGIN
  op := instr.op DIV 32;
  IF IsSinglePrec(instr) THEN
   FindFreg(instr.src1, src);
   AssignFreg(instr.dest);
   IF op = Fabs THEN
    OPO.GenFSGNJXS(instr.reg, src, src) (* FABS = FSGNJX with same src *)
   ELSE (* Fchs: negate *)
    OPO.GenFSGNJNS(instr.reg, src, src) (* FNEG = FSGNJN with same src *)
   END;
   DecCheckFreg(src)
  ELSE
   (* LONGREAL unary ops: push 3 words (lo, hi, resAddr) for Float64.Neg/Abs *)
   FindLoadReg(instr.src1, src);
   srcHi := GetLRealHi(src);
   (* Allocate 20 bytes: 12 params + 8 result area.
      Oberon convention: last param at lowest address (sp+0). *)
   OPO.GenADDI(SP, SP, -20);
   (* resAddr = sp + 12 (address of result area) *)
   OPO.GenADDI(T0, SP, 12);
   OPO.GenSW(T0, SP, 0);           (* sp+0 = resAddr (3rd/last param) *)
   IF srcHi > -1 THEN
    OPO.GenSW(srcHi, SP, 4);       (* sp+4 = hi word (2nd param) *)
    FreeReg(srcHi); SetLRealHi(src, -1)
   ELSE OPO.GenSW(X0, SP, 4)       (* sp+4 = hi = 0 *)
   END;
   OPO.GenSW(src, SP, 8);          (* sp+8 = lo word (1st/first param) *)
   DecReg(src);
   IF op = Fabs THEN
    OPO.GenJAL(RA, 0);
    AddLink(F64AbsLinkIndex, OPO.pc - 4)
   ELSE
    OPO.GenJAL(RA, 0);
    AddLink(F64NegLinkIndex, OPO.pc - 4)
   END;
   (* Callee cleans 12 bytes of params; sp now points to result area *)
   AssignThisReg(instr.dest, A0);
   instr.reg := A0;
   OPO.GenLW(A0, SP, 0);           (* resultLo *)
   GetThisReg(A1);
   OPO.GenLW(A1, SP, 4);           (* resultHi *)
   SetLRealHi(A0, A1);
   OPO.GenADDI(SP, SP, 8)          (* clean up result area *)
  END
 END FloatGen2;

 PROCEDURE FloatCmp(VAR instr: Instruction);
 (* fcmp: compare floating-point values, result in T5/T6 *)
  VAR src, src2: SHORTINT;
      srcHi, src2Hi: SHORTINT;
 BEGIN
  IF IsSinglePrec(instr) THEN
   FindFreg(instr.src1, src);
   FindFreg(instr.src2, src2);
   (* Use FLT.S and FEQ.S to build comparison result in T5, T6 *)

   OPO.GenFLTS(T5, src, src2);    (* T5 = 1 if src < src2 *)
   OPO.GenFLTS(T6, src2, src);    (* T6 = 1 if src2 < src *)
   OPO.GenFLTS(T5, src2, src);    (* T5 = 1 if src > src2, 0 otherwise *)
   OPO.GenFLTS(T6, src, src2);    (* T6 = 1 if src < src2, 0 otherwise *)
   DecCheckFreg(src); DecCheckFreg(src2)
  ELSE
   (* LONGREAL comparison via Float64.Cmp(loA, hiA, loB, hiB): INTEGER *)
   FindLoadReg(instr.src1, src);
   srcHi := GetLRealHi(src);
   FindLoadReg(instr.src2, src2);
   src2Hi := GetLRealHi(src2);
   (* Oberon convention: last param at lowest address (sp+0). Callee cleans. *)
   OPO.GenADDI(SP, SP, -16);
   IF src2Hi > -1 THEN
    OPO.GenSW(src2Hi, SP, 0);  (* sp+0 = hiB (4th/last param) *)
    FreeReg(src2Hi); SetLRealHi(src2, -1)
   ELSE OPO.GenSW(X0, SP, 0)
   END;
   OPO.GenSW(src2, SP, 4);     (* sp+4 = loB (3rd param) *)
   IF srcHi > -1 THEN
    OPO.GenSW(srcHi, SP, 8);   (* sp+8 = hiA (2nd param) *)
    FreeReg(srcHi); SetLRealHi(src, -1)
   ELSE OPO.GenSW(X0, SP, 8)
   END;
   OPO.GenSW(src, SP, 12);     (* sp+12 = loA (1st/first param) *)
   DecReg(src); DecReg(src2);
   OPO.GenJAL(RA, 0);
   AddLink(F64CmpLinkIndex, OPO.pc - 4);
   OPO.GenSLT(T5, X0, A0);    (* T5 = (0 < a0) = 1 if A > B *)
   OPO.GenSLTI(T6, A0, 0)     (* T6 = (a0 < 0) = 1 if A < B *)
  END
 END FloatCmp;

 PROCEDURE GenEntier(VAR instr: Instruction);
  VAR src, dummy: SHORTINT; srcIsSingle: BOOLEAN;
    srcHi: SHORTINT;
 BEGIN
  srcIsSingle := FALSE;
  IF instr.src1 >= 0 THEN
   srcIsSingle := (OPIR.Instr[instr.src1].op MOD 8) = 3
  END;
  IF srcIsSingle THEN
   (* Single-precision REAL to integer: FCVT.W.S *)
   FindFreg(instr.src1, src);
   dummy := none;
   AssignReg(instr.dest, dummy, dummy, dummy);
   OPO.GenFCVTWS(instr.reg, src, 1); (* rm=1: RTZ = truncate toward zero *)
   DecCheckFreg(src)
  ELSE
   (* Double-precision LONGREAL to integer: call Float64.CvtFI *)
   FindLoadReg(instr.src1, src);
   srcHi := GetLRealHi(src);
   (* Oberon convention: last param at lowest address (sp+0). *)
   OPO.GenADDI(SP, SP, -8);
   IF srcHi > -1 THEN
    OPO.GenSW(srcHi, SP, 0);    (* sp+0 = hiA (2nd/last param) *)
    FreeReg(srcHi); SetLRealHi(src, -1)
   ELSE OPO.GenSW(X0, SP, 0)    (* sp+0 = hiA = 0 *)
   END;
   OPO.GenSW(src, SP, 4);       (* sp+4 = loA (1st/first param) *)
   DecReg(src);
   OPO.GenJAL(RA, 0);
   AddLink(F64CvtFILinkIndex, OPO.pc - 4);
   (* Callee cleans 8 bytes of params. Result in a0 *)
   dummy := none;
   AssignReg(instr.dest, dummy, dummy, dummy);
   OPO.GenMOV(instr.reg, A0)
  END
 END GenEntier;
 

 PROCEDURE GenEnter(locSize: LONGINT; scope: OPT.Object; sysflag: SHORTINT);
 BEGIN
  OPO.GenADDI(SP, SP, -8);
  OPO.GenSW(RA, SP, 4);
  OPO.GenSW(FP, SP, 0);
  OPO.GenMOV(FP, SP);
  IF locSize > 0 THEN
   EmitSubImm(SP, SP, locSize)
  END
 END GenEnter;

 PROCEDURE PushRegs;
 (* Save all allocated registers before a nested call *)
  VAR i: SHORTINT;
 BEGIN
  ASSERT(nofSavedLevel < MaxSaveLevel);
  i := 0;
  WHILE i < MaxGPRs DO
   savedRegs[nofSavedLevel].reg[i] := regTab[i];
   IF regTab[i] # free THEN
    (* Push register to stack *)
    OPO.GenADDI(SP, SP, -4);
    OPO.GenSW(RegToGPR(i), SP, 0);
    regTab[i] := free
   END;
   INC(i)
  END;
  i := 0;
  WHILE i < MaxFRegs DO
   savedRegs[nofSavedLevel].freg[i] := fregTab[i];
   IF fregTab[i] # free THEN
    (* Push FPU register to stack *)
    OPO.GenADDI(SP, SP, -4);
    OPO.GenFSW(i, SP, 0);
    fregTab[i] := free
   END;
   INC(i)
  END;
  INC(nofSavedLevel)
 END PushRegs;

 PROCEDURE PopRegs(VAR instr: Instruction);
 (* Restore registers after a nested call *)
  VAR i: SHORTINT; size: LONGINT; hasResult: BOOLEAN;
 BEGIN
  DEC(nofSavedLevel);
  IF instr.hint # noHint THEN size := (instr.op MOD 8) * 8
  ELSE size := -1
  END;
  hasResult := size >= 0;
  (* Restore FPU registers in reverse order *)
  i := MaxFRegs - 1;
  WHILE i >= 0 DO
   IF savedRegs[nofSavedLevel].freg[i] # free THEN
    OPO.GenFLW(i, SP, 0);
    OPO.GenADDI(SP, SP, 4)
   END;
   fregTab[i] := savedRegs[nofSavedLevel].freg[i];
   DEC(i)
  END;
  (* Restore GPRs in reverse order *)
  (* If a0 needs to be restored AND call has a result in a0, we must save the result first *)
  IF hasResult & (savedRegs[nofSavedLevel].reg[GPRToReg(A0)] # free) THEN
   OPO.GenMOV(T0, A0); (* save return value *)
   i := MaxGPRs - 1;
   WHILE i >= 0 DO
    IF savedRegs[nofSavedLevel].reg[i] # free THEN
     OPO.GenLW(RegToGPR(i), SP, 0);
     OPO.GenADDI(SP, SP, 4)
    END;
    DEC(i)
   END;
   (* Move old a0 to a free register *)
   i := 1;
   WHILE (i < MaxGPRs) & ~((savedRegs[nofSavedLevel].reg[i] = free) & ~(savedRegs[nofSavedLevel].reg[i] # free)) DO INC(i) END;
   IF i < MaxGPRs THEN
    OPO.GenMOV(RegToGPR(i), A0);
    savedRegs[nofSavedLevel].reg[i] := savedRegs[nofSavedLevel].reg[GPRToReg(A0)]
   END;
   OPO.GenMOV(A0, T0); (* restore return value *)
   savedRegs[nofSavedLevel].reg[GPRToReg(A0)] := free
  ELSE
   i := MaxGPRs - 1;
   WHILE i >= 0 DO
    IF savedRegs[nofSavedLevel].reg[i] # free THEN
     OPO.GenLW(RegToGPR(i), SP, 0);
     OPO.GenADDI(SP, SP, 4)
    END;
    DEC(i)
   END
  END;
  i := 0;
  WHILE i < MaxGPRs DO
   IF savedRegs[nofSavedLevel].reg[i] = free THEN
    (* nothing *)
   ELSIF regTab[i] = free THEN
    regTab[i] := savedRegs[nofSavedLevel].reg[i];
    IF regTab[i] >= 0 THEN OPIR.Instr[regTab[i]].reg := RegToGPR(i) END
   END;
   INC(i)
  END;
  (* Set result register *)
  IF size = Bit8 THEN
   regTab[GPRToReg(A0)] := instr.dest; instr.reg := A0
  ELSIF (size = Bit16) OR (size = Bit32) THEN
   regTab[GPRToReg(A0)] := instr.dest; instr.reg := A0
  ELSIF size = Bit64 THEN
   regTab[GPRToReg(A0)] := instr.dest; instr.reg := A0
  END
 END PopRegs;

 PROCEDURE FixupCaseTab(VAR instr: Instruction);
 (* Patch case table entries with actual PC values *)
  VAR elseLabel, from, to, val, caseFixup: LONGINT;
 BEGIN
  caseFixup := link[0].offset;
  elseLabel := OPIR.Instr[instr.src2].pc;
  from := instr.src1; to := instr.src1 + instr.inx - 4;
  WHILE from <= to DO
   OPO.GetConsDWord(from, val);
   IF val = Nil THEN val := elseLabel
   ELSE val := OPIR.Instr[val].pc
   END;
   IF from = to THEN
    IF caseFixup >= 32768 THEN val := (caseFixup - 10000H) * 10000H + val
    ELSE val := caseFixup * 10000H + val
    END
   ELSE
    IF from + 4 >= 32768 THEN val := (from + 4 - 10000H) * 10000H + val
    ELSE val := (from + 4) * 10000H + val
    END
   END;
   OPO.PutConsDWord(from, val);
   from := from + 4
  END;
  link[0].offset := SHORT(instr.src1)
 END FixupCaseTab;

  PROCEDURE EncodeFixup(i: LONGINT);
  VAR L, L1, chainVal: LONGINT; node: OPT.Node;
 BEGIN
  node := OPIR.Instr[i].node;
  node.left.obj.linkadr := -2 - OPIR.Instr[i].pc - 10000H;
  L := i;
  WHILE L > Nil DO
   OPO.ExtractChainVal(OPIR.Instr[L].pc, chainVal);
   IF (chainVal > -10000H) & (-2 - chainVal > Nil) THEN
    L1 := -2 - chainVal;
    OPO.EmitChainJALAt(OPIR.Instr[L].pc, RA, (-2 - OPIR.Instr[L1].pc - 10000H))
   ELSE
    L1 := chainVal
   END;
   L := L1
  END
 END EncodeFixup;

 PROCEDURE GenAsm(instr: Instruction);
  VAR n, code, fix: OPT.Node; pc: LONGINT;
 BEGIN
  pc := OPO.pc; n := instr.node;
  code := n.left;
  WHILE code # NIL DO
   OPO.InlineCode(code.conval.ext^, 0); code := code.link
  END;
  fix := n.right;
  WHILE fix # NIL DO
   IF (fix.obj.mode = Var) & (fix.obj.mnolev <= 0) THEN
    OPO.PutWordAt(pc + fix.conval.intval, fix.obj.linkadr);
    AbsAccess(fix, pc + fix.conval.intval)
   ELSIF (fix.obj.linkadr <= MAX(SHORTINT)) & (fix.obj.linkadr >= MIN(SHORTINT)) THEN
    OPO.PutByteAt(pc + fix.conval.intval, SHORT(SHORT(fix.obj.linkadr)))
   ELSE
    OPM.Mark(600, SHORT(fix.conval.intval2))
   END;
   fix := fix.link
  END
 END GenAsm;

  PROCEDURE FixupLocalProcCall*(proc: OPT.Object);
 (* Patch all forward calls to a local procedure now that its address is known *)
 (* RV32: Forward calls use JAL with chain link in raw bits[31:12].
    We walk the chain and patch each JAL with the correct real offset. *)
  VAR L, chainLink, entryNr: LONGINT;
 BEGIN
  IF (proc.linkadr < 0) & ~(proc.mode IN {TProc, Typ}) THEN
   L := -2 - proc.linkadr - 10000H;
   WHILE L > Nil DO
    OPO.ExtractChainVal(L, chainLink);
    (* Patch JAL with correct offset to procedure entry (real J-type encoding) *)
    OPO.EmitJALAt(L, RA, OPO.pc - L);
    L := -2 - chainLink - 10000H
   END
  END;
  proc.linkadr := OPO.pc;
  IF proc.mode IN {XProc, TProc, Typ} THEN
   IF proc.mode IN {TProc, Typ} THEN entryNr := proc.adr MOD 10000H
   ELSE entryNr := proc.adr
   END;
   IF OPO.pc > 32767 THEN entry[entryNr] := SHORT(OPO.pc - 65536)
   ELSE entry[entryNr] := SHORT(OPO.pc)
   END
  END
 END FixupLocalProcCall;


 PROCEDURE GenCode*(pSize: INTEGER);
  VAR
   obj: OPT.Object;
   list: OPT.Object;
   i, k: LONGINT;
   op: LONGINT;
   reg: SHORTINT;
   sysflag: SHORTINT;
   node: OPT.Node;

  PROCEDURE MarkPos;
   VAR j: LONGINT;
  BEGIN
   IF OPIR.mapSize < LEN(OPIR.map^) THEN
    OPIR.map[OPIR.mapSize].pos := OPIR.Instr[i].src1;
    OPIR.map[OPIR.mapSize].pc := OPO.pc;
    j := OPIR.mapSize - 1;
    WHILE (j >= 0) & (OPIR.map[j].pos < 0) DO
     OPIR.map[j].pos := OPIR.map[OPIR.mapSize].pos; DEC(j)
    END;
    INC(OPIR.mapSize)
   ELSE
    OPIR.map[OPIR.mapSize - 1].pos := -1;
    OPIR.map[OPIR.mapSize - 1].pc := -1
   END
  END MarkPos;

 BEGIN
  i := 0;
  WHILE i < nofTrapFixups DO
   trapFixupTab[i] := Nil; INC(i)
  END;
  i := 0;
  WHILE i < MaxGPRs DO
   regTab[i] := free; INC(i)
  END;
  i := 0;
  WHILE i < MaxFRegs DO
   fregTab[i] := free; INC(i)
  END;
  RegErr := FALSE;
  nofFwdFixups := 0;
  i := 0;
  WHILE ~OPO.CodeErr & ~RegErr & (i < pSize) DO
   node := OPIR.Instr[i].node;
   FixupFwdJumps(i);
   OPIR.Instr[i].pc := OPO.pc;
   op := OPIR.Instr[i].op DIV 32;
   IF op > 0 THEN
    CASE op OF
     NewStat:
      OPM.errpos := OPIR.Instr[i].src1;
      IF OPIR.map # NIL THEN MarkPos END
     | Ld, Lea, Ldbdw, Ldwdw, Ldbw, Ldbdwu, Ldwdwu, Ldbwu, PUTreg:
      Load(OPIR.Instr[i])
     | LdProc, LdXProc:
      LoadProc(OPIR.Instr[i])
     | Sto, GETreg:
      Store(OPIR.Instr[i])
     | Push:
      GenPush(OPIR.Instr[i])
     | Pop:
      GenPop(OPIR.Instr[i])
     | Add, Sub, oR, Xor, And, Sal, Sar, Shr, Rol, Bts, Btr:
      Gen3(OPIR.Instr[i])
     | Div, Mod:
      GenDivMod(OPIR.Instr[i])
     | Mul:
      GenMul(OPIR.Instr[i])
     | Neg, Not:
      Gen2(OPIR.Instr[i])
     | Abso:
      GenAbs(OPIR.Instr[i])
     | Cmp, Bt, Test:
      Flags(OPIR.Instr[i])
     | Sete, Setne, Setl, Setle, Setg, Setge, Seta, Setae, Setb, Setbe, Setc, Setnc:
      Setcc(OPIR.Instr[i])
     | Je, Jne, Jl, Jle, Jg, Jge, Ja, Jae, Jb, Jbe, Jc, Jnc, Jmp, JmpReg:
      Gen1(OPIR.Instr[i], i)
     | Te, Tne, Tle, Ta, Tae, To:
      GenTrapCC(OPIR.Instr[i])
     | Trap:
      GenTrap(OPIR.Instr[i].src2)
     | Call:
      node := OPIR.Instr[i].node;
      obj := node.left.obj;
      IF obj.mode = CProc THEN
       HALT(99)
      ELSIF OPIR.Instr[i].src2 >= 0 THEN
       (* Backward call: JAL ra, offset *)
       OPO.GenJAL(RA, OPIR.Instr[i].src2 - OPO.pc)
      ELSE
       (* Forward call: JAL with chain link in raw bits, no J-type scrambling *)
       OPO.EmitChainJAL(RA, OPIR.Instr[i].src2);
       IF -2 - node.left.obj.linkadr = i THEN
        EncodeFixup(i)
       END
      END
     | Xcall:
      (* External call: JAL with fixup for linker *)
      OPO.GenJAL(RA, 0);
      AddLink(OPIR.Instr[i].src2 DIV 10000H, OPIR.Instr[i].pc)
     | CallReg:
      FindReg(OPIR.Instr[i].src2, reg);
      OPO.GenJALR(RA, reg, 0);
      DecReg(reg)
     | PushReg:
      PushRegs
     | PopReg:
      PopRegs(OPIR.Instr[i])
     | Ret:
      (* ret parSize: callee cleans parameters and returns.
         The Leave instruction already restored FP and RA.
         Ret adds parSize to SP and returns via JALR x0, ra, 0. *)
      IF OPIR.Instr[i].src2 > 0 THEN
       EmitAddImm(SP, SP, OPIR.Instr[i].src2)
      END;
      OPO.GenJALR(X0, RA, 0)
     | Enter:
      IF OPIR.map # NIL THEN MarkPos END;
      IF node # NIL THEN
       list := node.obj.scope.scope;
       sysflag := node.obj.sysflag
      ELSE
       list := NIL;
       sysflag := 0
      END;
      GenEnter(OPIR.Instr[i].src2, list, sysflag)
     | Leave:
      (* leave: procedure epilogue (without ret)
         RV32: MV sp, s0; LW s0, 0(sp); LW ra, 4(sp); ADDI sp, sp, 8 *)
      OPO.GenMOV(SP, FP);
      OPO.GenLW(FP, SP, 0);
      OPO.GenLW(RA, SP, 4);
      OPO.GenADDI(SP, SP, 8)
     | RepMovs:
      GenRepMovs(OPIR.Instr[i])
     | CmpString:
      GenCmpString(OPIR.Instr[i])
     | Short:
      GenShort(OPIR.Instr[i])
     | Phi:
      GenPhi(OPIR.Instr[i])
     | Label:
      (* label: no code, just a fixup point *)
     | Entier:
      GenEntier(OPIR.Instr[i])
     | Cli:
      (* cli: disable interrupts - not applicable on bare-metal RV32 without specific CSR *)
      OPO.GenNOP
     | Sti:
      (* sti: enable interrupts *)
      OPO.GenNOP
     | In, Out:
      OPM.err(200)
     | Assembler:
      GenAsm(OPIR.Instr[i])
     | Clear:
      (* clear: handled by repMovs with zero source *)
     | Std:
      (* std: set direction flag - no equivalent *)
     | Dmb:
      (* dmb: memory barrier - FENCE *)
      OPO.GenFENCE
     | FLoad, Fild:
      Fload(OPIR.Instr[i])
     | FStore, Fist:
      Fstore(OPIR.Instr[i])
     | Fadd, Fsub, Fmul, Fdiv:
      FloatGen3(OPIR.Instr[i])
     | Fabs, Fchs:
      FloatGen2(OPIR.Instr[i])
     | Fcmp:
      FloatCmp(OPIR.Instr[i])
     | Case:
      FixupCaseTab(OPIR.Instr[i])
     | Cld:
      (* cld: clear direction flag - no equivalent *)
    ELSE
     (* Unknown opcode *)
    END
   END;
   INC(i)
  END;
  FixupAndGenTrap
 END GenCode;


 PROCEDURE OutRefPoint*(proc: OPT.Object);
 VAR obj: OPT.Object; n: LONGINT;
 BEGIN
  IF proc = NIL THEN
   OPM.RefW(RefTag);
   OPM.RefW(0F8X);
   OPM.RefWNum(0)
  ELSE
   IF NewRef THEN
    OPM.RefW(0F9X);
    OPM.RefWNum(proc.linkadr);
    obj := proc.link; n := 0;
    WHILE obj # NIL DO INC(n); obj := obj.link END;
    OPM.RefWNum(n);
    n := proc.typ.form;
    IF n IN {Undef, NilTyp, NoTyp} THEN n := 0
    ELSIF n = Comp THEN n := 10H + proc.typ.comp
    END;
    OPM.RefW(CHR(n));
    OPM.RefW(CHR(proc.mnolev));
    IF slNeeded IN proc.conval.setval THEN OPM.RefW(1X)
    ELSE OPM.RefW(0X)
    END
   ELSE
    OPM.RefW(0F8X);
    OPM.RefWNum(proc.linkadr)
   END
  END
 END OutRefPoint;

 PROCEDURE OutRefName*(name: ARRAY OF CHAR);
  VAR ch: CHAR; i: INTEGER;
 BEGIN
  i := 0;
  REPEAT ch := name[i]; OPM.RefW(ch); INC(i) UNTIL ch = 0X
 END OutRefName;

 PROCEDURE OutRefs*(obj: OPT.Object);
  VAR f: INTEGER;
 BEGIN
  IF obj # NIL THEN
   OutRefs(obj.left);
   IF obj.mode IN {Var, VarPar} THEN
    f := obj.typ.form;
    IF NewRef THEN
     IF (f IN {Byte..Set, Pointer, ProcTyp, HInt}) OR (obj.typ.comp = Record) OR
        (obj.typ.comp IN {StaticArr, OpenArr}) & (obj.typ.BaseTyp.form IN {Byte..Set, Pointer, ProcTyp}) THEN
      IF (obj.mode = Var) & (obj.typ.comp # OpenArr) THEN OPM.RefW(1X)
      ELSE OPM.RefW(3X)
      END;
      IF obj.typ.comp = StaticArr THEN
       OPM.RefW(CHR(80H + obj.typ.BaseTyp.form));
       OPM.RefWNum(obj.typ.n)
      ELSIF obj.typ.comp = OpenArr THEN
       OPM.RefW(CHR(80H + obj.typ.BaseTyp.form));
       OPM.RefWNum(0)
      ELSIF obj.typ.comp = Record THEN
       OPM.RefW(CHR(10H + Record));
       OPM.RefWNum(obj.typ.tdadr)
      ELSIF (f = Pointer) & (obj.typ.BaseTyp # NIL) & (obj.typ.BaseTyp.comp = Record) THEN
       OPM.RefW(CHR(10H + Pointer));
       OPM.RefWNum(obj.typ.BaseTyp.tdadr)
      ELSE
       OPM.RefW(CHR(f))
      END;
      OPM.RefWNum(obj.linkadr);
      OutRefName(obj.name)
     END
    ELSE
     IF (f IN {Byte..Set, Pointer, ProcTyp}) OR
        (obj.typ.comp IN {StaticArr, OpenArr}) & (obj.typ.BaseTyp.form IN {Byte..Set, Pointer, ProcTyp}) THEN
      IF (obj.mode = Var) & (obj.typ.comp # OpenArr) THEN OPM.RefW(1X)
      ELSE OPM.RefW(3X)
      END;
      IF obj.typ.comp = StaticArr THEN
       OPM.RefW(CHR(80H + obj.typ.BaseTyp.form));
       OPM.RefWNum(obj.typ.n)
      ELSIF obj.typ.comp = OpenArr THEN
       OPM.RefW(CHR(80H + obj.typ.BaseTyp.form));
       OPM.RefWNum(0)
      ELSE
       OPM.RefW(CHR(f))
      END;
      OPM.RefWNum(obj.linkadr);
      OutRefName(obj.name)
     END
    END
   END;
   OutRefs(obj.right)
  END
 END OutRefs;

 PROCEDURE LSW(x: LONGINT): LONGINT;
 BEGIN
  RETURN SYSTEM.VAL(LONGINT, SYSTEM.VAL(SET, x) * SYSTEM.VAL(SET, 0FFFFH))
 END LSW;

 PROCEDURE Export(obj: OPT.Object; VAR nofExp: INTEGER);
  VAR typ: OPT.Struct; i: LONGINT; tmp: ExpTable;

  PROCEDURE ExportMeth(fld: OPT.Object; basetyp: OPT.Struct; VAR noFld: INTEGER);
  BEGIN
   IF fld # NIL THEN
    ExportMeth(fld.left, basetyp, noFld);
    IF (fld.mode = TProc) & (fld.vis # internal) THEN
     INC(noFld); OPM.ObjWNum(fld.fp)
    END;
    ExportMeth(fld.right, basetyp, noFld)
   END
  END ExportMeth;

  PROCEDURE ExportRecord(typ: OPT.Struct);
   VAR fld: OPT.Object; pos: LONGINT; nofld: INTEGER;
  BEGIN
   IF typ.mno = 0 THEN
    OPM.ObjW(EURecord);
    IF typ.oref # 0 THEN OPM.ObjWNum(-typ.oref)
    ELSE
     INC(nofStr); typ.oref := nofStr;
     OPM.ObjWNum(typ.tdadr);
     OPT.FPrintTyp(typ);
     pos := OPM.ObjAllocInt();
     nofld := 2;
     IF (typ.BaseTyp # NIL) & (typ.mno = OPT.modNo) THEN ExportRecord(typ.BaseTyp) END;
     OPM.ObjWNum(typ.pbfp); OPM.ObjWNum(typ.pvfp);
     ExportMeth(typ.link, typ.BaseTyp, nofld);
     fld := typ.link;
     WHILE (fld # NIL) & (fld.mode # TProc) DO
      IF fld.vis # internal THEN
       INC(nofld);
       OPM.ObjWNum(fld.fp);
       typ := fld.typ;
       WHILE (typ # NIL) & ((typ.form = Comp) & (typ.comp # Record) OR (typ.form = Pointer)) DO
        typ := typ.BaseTyp
       END;
       IF (typ # NIL) & (typ.form = Comp) & (typ.comp = Record) THEN ExportRecord(typ) END
      END;
      fld := fld.link
     END;
     OPM.ObjW(EUEnd); OPM.ObjFillInt(pos, nofld)
    END
   END
  END ExportRecord;

 BEGIN
  IF obj # NIL THEN
   IF obj.prio = 127 THEN
    Export(obj.link2, nofExp); Export(obj.left, nofExp); Export(obj.right, nofExp)
   ELSE
    Export(obj.left, nofExp);
    IF obj.vis # internal THEN
     OPT.FPrintObj(obj);
     OPM.ObjWNum(obj.fp);
     i := 0;
     WHILE i < exppos DO
      IF obj.fp = explist[i] THEN OPM.Mark(280, obj.txtpos) END;
      INC(i)
     END;
     IF exppos = LEN(explist) THEN
      NEW(tmp, 32 + LEN(explist));
      SYSTEM.MOVE(SYSTEM.ADR(explist[0]), SYSTEM.ADR(tmp[0]), 4 * LEN(explist));
      explist := tmp
     END;
     explist[exppos] := obj.fp; INC(exppos);
     IF obj.mode = Var THEN OPM.ObjWNum(obj.linkadr)
     ELSIF obj.mode = XProc THEN OPM.ObjWNum(LSW(entry[obj.adr]))
     ELSE OPM.ObjW(0X)
     END;
     INC(nofExp);
     IF (obj.mode = Typ) OR (obj.mode = Var) THEN
      typ := obj.typ;
      WHILE (typ # NIL) & ((typ.form = Comp) & (typ.comp # Record) OR (typ.form = Pointer)) DO
       typ := typ.BaseTyp
      END;
      IF (typ # NIL) & (typ.form = Comp) & (typ.comp = Record) THEN ExportRecord(typ) END
     END
    END;
    Export(obj.right, nofExp)
   END
  END
 END Export;

 PROCEDURE Use(obj: OPT.Object);
  VAR typ: OPT.Struct; alias: BOOLEAN;

  PROCEDURE UseRecord(typ: OPT.Struct);
  VAR name: ARRAY 32 OF CHAR;
  BEGIN
   IF (typ.oref = 0) & (typ.mno = OPT.modNo) THEN
    OPM.ObjW(EURecord);
    IF (typ.tdadr = OPM.TDAdrUndef) OR (typ.tdadr = -2) THEN OPM.ObjWNum(0)
    ELSE OPM.ObjWNum(-typ.tdadr)
    END;
    OPT.FPrintTyp(typ); typ.oref := -1;
    IF typ.pvused THEN
     name := "@"; OPM.ObjWNum(typ.pvfp); OPM.ObjWString(name)
    ELSIF typ.pbused THEN
     name := "@"; OPM.ObjWNum(typ.pbfp); OPM.ObjWString(name)
    END;
    OPM.ObjW(EUEnd)
   END
  END UseRecord;

 BEGIN
  IF obj # NIL THEN
   IF obj.prio = 127 THEN Use(obj.link2); Use(obj.left); Use(obj.right)
   ELSE
    Use(obj.left);
    alias := FALSE;
    IF ~obj.used & (obj.mode = Typ) & (obj.vis # internal) & (obj.typ.strobj # obj) &
       (obj.typ.strobj.vis = internal) & obj.typ.strobj.used THEN
     alias := TRUE
    END;
    IF alias OR obj.used & (obj.vis # internal)
    & ((obj.mode # XProc) OR (obj.adr DIV 10000H # 0) & (link[obj.adr DIV 10000H].offset # Nil))
    & ((obj.mode # Var) OR (obj.adr # 0)) THEN
     OPT.FPrintObj(obj);
     OPM.ObjWNum(obj.fp); OPM.ObjWString(obj.name);
     IF obj.mode = Var THEN OPM.ObjWNum(obj.adr DIV 10000H)
     ELSIF obj.mode = XProc THEN OPM.ObjWNum(LSW(link[obj.adr DIV 10000H].offset) + EUProcFlag)
     ELSE OPM.ObjW(0X)
     END;
     IF (obj.mode = Typ) OR (obj.mode = Var) THEN
      typ := obj.typ;
      WHILE (typ # NIL) & ((typ.form = Comp) & (typ.comp # Record) OR (typ.form = Pointer)) DO
       typ := typ.BaseTyp
      END;
      IF (typ # NIL) & (typ.form = Comp) & (typ.comp = Record) THEN
       UseRecord(typ);
       IF typ.strobj.fp = 0 THEN typ.strobj.fp := obj.fp END
      END
     END
    END;
    Use(obj.right)
   END
  END
 END Use;

 PROCEDURE OutCode*(VAR modName: ARRAY OF CHAR);
  VAR
   i, k, pos: LONGINT;
   nofcmds, nofnewmth, nofinhmth, linkCorrection, nofExp, nofImp: INTEGER;
   obj: OPT.Object;
   typ, btyp: OPT.Struct;
   commandTab: ARRAY MaxCommands OF OPT.Object;
   newMthTab: ARRAY MaxEntry OF OPT.Object;
   modMap: ARRAY 128 OF SHORTINT;

  PROCEDURE WriteName(VAR name: ARRAY OF CHAR);
   VAR i: INTEGER; ch: CHAR;
  BEGIN
   i := 0;
   REPEAT ch := name[i]; OPM.ObjW(ch); INC(i) UNTIL ch = 0X
  END WriteName;

  PROCEDURE FindPtrs(typ: OPT.Struct; adr: LONGINT);
   VAR fld: OPT.Object; i, n, s: LONGINT; btyp: OPT.Struct;

   PROCEDURE Add(adr: LONGINT);
    VAR table: PtrTable;
   BEGIN
    IF nofptrs >= LEN(ptrTab) THEN
     NEW(table, LEN(ptrTab) * 2);
     FOR i := 0 TO LEN(ptrTab) - 1 DO table[i] := ptrTab[i] END;
     ptrTab := table
    END;
    ptrTab[nofptrs] := adr; INC(nofptrs)
   END Add;

  BEGIN
   IF typ.form = Pointer THEN
    IF typ.sysflag = 0 THEN Add(adr) END
   ELSIF (typ.form = ProcTyp) & (typ.sysflag = delegate) THEN Add(adr + 4)
   ELSIF typ.comp = Record THEN
    btyp := typ.BaseTyp;
    IF btyp # NIL THEN FindPtrs(btyp, adr) END;
    fld := typ.link;
    WHILE (fld # NIL) & (fld.mode = Fld) DO
     IF fld.name = OPT.HdPtrName THEN Add(adr)
     ELSIF fld.sysflag # untraced THEN FindPtrs(fld.typ, fld.adr + adr)
     END;
     fld := fld.link
    END
   ELSIF typ.comp = StaticArr THEN
    btyp := typ.BaseTyp; n := typ.n;
    WHILE btyp.comp = StaticArr DO n := btyp.n * n; btyp := btyp.BaseTyp END;
    IF (btyp.form = Pointer) OR (btyp.comp IN {Record, DynArr}) OR
       ((btyp.form = ProcTyp) & (btyp.sysflag = delegate)) THEN
     i := 0; s := btyp.size;
     WHILE i < n DO FindPtrs(btyp, i * s + adr); INC(i) END
    END
   ELSIF typ.comp = DynArr THEN
    Add(adr)
   END
  END FindPtrs;

  PROCEDURE traverse(obj: OPT.Object);
  BEGIN
   IF obj # NIL THEN
    IF obj.mode = XProc THEN
     IF obj.vis # internal THEN
      IF (obj.link = NIL) & (obj.typ = OPT.notyp) THEN
       IF nofcmds <= MaxCommands THEN commandTab[nofcmds] := obj; INC(nofcmds)
       ELSE OPM.err(232)
       END
      ELSIF (obj.typ = OPT.ptrtyp) & (obj.link # NIL) & (obj.link.typ = OPT.ptrtyp) &
            (obj.link.link = NIL) THEN
       IF nofcmds <= MaxCommands THEN commandTab[nofcmds] := obj; INC(nofcmds)
       ELSE OPM.err(232)
       END
      END
     END
    ELSIF (obj.mode = Var) & (obj.sysflag # untraced) THEN FindPtrs(obj.typ, obj.linkadr)
    ELSIF obj.mode = Module THEN OPT.modules[-obj.mnolev].used := TRUE
    END;
    traverse(obj.left); traverse(obj.right)
   END
  END traverse;

  PROCEDURE FindNewMths(obj: OPT.Object);
  BEGIN
   IF obj # NIL THEN
    IF (obj.mode = TProc) OR ((obj.mode = Typ) & (obj.conval # NIL) & (hasBody IN obj.conval.setval)) THEN
     newMthTab[nofnewmth] := obj; INC(nofnewmth)
    END;
    IF obj.mode = Typ THEN FindNewMths(obj.typ.link)
    ELSE FindNewMths(obj.left); FindNewMths(obj.right)
    END
   END
  END FindNewMths;

 BEGIN (* OutCode *)
  modMap[0] := 0;
  linkCorrection := 0; i := 0;
  WHILE i < nofLinks DO
   IF (link[i].offset = Nil) OR (link[i].mod > 0) THEN INC(linkCorrection) END;
   INC(i)
  END;
  i := (-OPO.csize) MOD 4;
  WHILE i > 0 DO OPO.constant[OPO.csize] := 0X; INC(OPO.csize); DEC(i) END;
  nofcmds := 0;
  traverse(OPT.topScope.right);
  nofImp := 0; i := 1;
  WHILE i < OPT.nofmod DO
   IF OPT.modules[i].used THEN INC(nofImp); modMap[i] := SHORT(nofImp) END;
   INC(i)
  END;
  i := 0;
  OPM.ObjWInt(nofEntries); OPM.ObjWInt(nofcmds);
  IF nofptrs > MAX(INTEGER) THEN OPM.err(222) END;
  OPM.ObjWInt(SHORT(nofptrs)); OPM.ObjWInt(nofrecs);
  OPM.ObjWInt(nofImp);
  OPM.ObjWInt(nofVarCons); OPM.ObjWInt(nofLinks - linkCorrection);
  OPM.ObjWBytes(OPO.dsize, 4); OPM.ObjWInt(SHORT(OPO.csize)); OPM.ObjWInt(SHORT(OPO.pc));
  WriteName(modName);
  OPM.ObjW(EntryTag);
  i := 0; WHILE i < nofEntries DO OPM.ObjWInt(entry[i]); INC(i) END;
  OPM.ObjW(commandTag);
  i := 0;
  WHILE i < nofcmds DO
   obj := commandTab[i];
   IF obj.link # NIL THEN OPM.ObjW("$") END;
   WriteName(obj.name); OPM.ObjWInt(entry[obj.adr MOD 10000H]);
   INC(i)
  END;
  OPM.ObjW(pointerTag);
  i := 0;
  WHILE i < nofptrs DO OPM.ObjWBytes(ptrTab[i], 4); INC(i) END;
  OPM.ObjW(importTag);
  i := 1;
  WHILE i < OPT.nofmod DO
   obj := OPT.modules[i];
   IF obj.used THEN WriteName(obj.name) END;
   INC(i)
  END;
  OPM.ObjW(VarConsLinkTag);
  i := 0;
  WHILE i < nofVarCons DO
   OPM.ObjW(CHR(modMap[varConsLink[i].mod]));
   OPM.ObjWInt(varConsLink[i].entry); OPM.ObjWInt(varConsLink[i].noflinks);
   k := varConsLink[i].index;
   WHILE k # noEntry DO OPM.ObjWInt(varConsTab[k].offset); k := varConsTab[k].next END;
   INC(i)
  END;
  OPM.ObjW(LinkTag);
  i := 0;
  WHILE i < nofLinks DO
   IF (link[i].offset # Nil) & (link[i].mod <= 0) THEN
    OPM.ObjW(CHR(modMap[link[i].mod])); OPM.ObjW(CHR(link[i].entry));
    OPM.ObjWInt(link[i].offset)
   END;
   INC(i)
  END;
  OPM.ObjW(DataTag);
  i := 0; WHILE i < OPO.csize DO OPM.ObjW(OPO.constant[i]); INC(i) END;
  OPM.ObjW(ExportTag);
  pos := OPM.ObjAllocInt();
  nofExp := 0; nofStr := 0; OPT.modNo := 0;
  exppos := 0;
  Export(OPT.topScope.right, nofExp);
  OPM.ObjW(EUEnd); OPM.ObjFillInt(pos, nofExp);
  OPM.ObjW(CodeTag);
  i := 0; WHILE i < OPO.pc DO OPM.ObjW(OPO.code[i]); INC(i) END;
  OPM.ObjW(UseTag);
  i := 1;
  WHILE i < OPT.nofmod DO
   IF OPT.modules[i].used THEN
    OPM.ObjWString(OPT.modules[i].name);
    OPT.modNo := SHORT(i);
    Use(OPT.modules[i].right);
    OPM.ObjW(EUEnd)
   END;
   INC(i)
  END;
  OPM.ObjW(EUEnd);
  OPM.ObjW(TypeTag);
  i := 0;
  WHILE i < nofrecs DO
   typ := recTab[i];
   nofptrs := 0;
   FindPtrs(typ, 0);
   OPM.ObjWBytes(typ.size, 4);
   OPM.ObjWInt(SHORT(typ.tdadr));
   btyp := typ.BaseTyp;
   IF btyp = NIL THEN
    nofinhmth := 0;
    OPM.ObjWInt(-1); OPM.ObjWLInt(-1)
   ELSE
    nofinhmth := SHORT(btyp.n);
    OPM.ObjWInt(modMap[btyp.mno]);
    IF btyp.mno = 0 THEN OPM.ObjWBytes(btyp.tdadr, 4)
    ELSE OPM.ObjWLInt(btyp.strobj.fp)
    END
   END;
   OPM.ObjWInt(SHORT(typ.n));
   OPM.ObjWInt(nofinhmth);
   nofnewmth := 0;
   FindNewMths(typ.strobj);
   OPM.ObjWInt(nofnewmth);
   IF nofptrs > MAX(INTEGER) THEN OPM.err(221) END;
   OPM.ObjWInt(SHORT(nofptrs));
   IF (typ.strobj # NIL) & (typ.strobj.mnolev = 0) THEN
    IF typ.ptr # NIL THEN
     IF typ.ptr.strobj = NIL THEN WriteName(typ.strobj.name)
     ELSE WriteName(typ.ptr.strobj.name)
     END
    ELSE WriteName(typ.strobj.name)
    END
   ELSE OPM.ObjW(0X)
   END;
   WHILE nofnewmth > 0 DO
    DEC(nofnewmth);
    OPM.ObjWInt(SHORT(newMthTab[nofnewmth].adr DIV 10000H));
    OPM.ObjWInt(SHORT(newMthTab[nofnewmth].adr MOD 10000H))
   END;
   k := 0;
   WHILE k < nofptrs DO OPM.ObjWBytes(ptrTab[k], 4); INC(k) END;
   INC(i)
  END;
  OPM.CloseObj
 END OutCode;

 PROCEDURE Close*;
  VAR i: LONGINT;
 BEGIN
  FOR i := 0 TO LEN(OPIR.Instr) - 1 DO OPIR.Instr[i].node := NIL END;
  i := 0; WHILE i < LEN(recTab) DO recTab[i] := NIL; INC(i) END
 END Close;

BEGIN
 NEW(ptrTab, 512); NEW(recTab, 64); NEW(entry, 128);
 NEW(varConsLink, 100); NEW(varConsTab, 500);
 NEW(explist, 32)
END OPL.
