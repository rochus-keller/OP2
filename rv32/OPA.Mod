(* OPA - RV32 Assembler module for the OP2 compiler 
   Inline assembler for RV32 (RISC-V 32-bit, RV32IMAF encoding)
    
  Supported instruction categories:
    - Integer R-type: ADD, SUB, AND, OR, XOR, SLL, SRL, SRA, SLT, SLTU
    - Integer I-type: ADDI, ANDI, ORI, XORI, SLTI, SLTIU, SLLI, SRLI, SRAI
    - Upper immediate: LUI, AUIPC
    - Jump: JAL, JALR
    - Branch: BEQ, BNE, BLT, BGE, BLTU, BGEU
    - Load: LB, LH, LW, LBU, LHU
    - Store: SB, SH, SW
    - M extension: MUL, MULH, MULHSU, MULHU, DIV, DIVU, REM, REMU
    - F extension: FLW, FSW, FADD.S, FSUB.S, FMUL.S, FDIV.S, FSGNJ.S, FSGNJN.S, FSGNJX.S
    - F compare: FEQ.S, FLT.S, FLE.S
    - F convert: FCVT.W.S, FCVT.S.W, FMV.X.W, FMV.W.X
    - System: ECALL, EBREAK, FENCE, WFI, NOP
    - Data: DCD, DCW, DCB
    - Pseudo: MV, LI, RET, NEG, NOT, SEQZ, SNEZ, J, CALL
    - All instruction tables are embedded directly in the module

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

MODULE OPA; (** non-portable *)
 IMPORT SYSTEM, OPM, OPS, OPT, OPB;

 CONST
  none = -1;

  (* Processor target *)
  RV32IMAF = 0;

  (* Node classes for inline instructions *)
  Nassembler = 29;
  Ncode = 30;
  Nfixup = 31;

  (* Own Symbol Table types *)
  StLabel = 0; StFwdLabel = 1;
  StConst = 3; StType = 4; StVar = 5; StVarPar = 6; StGlobal = 7;
  StMod = 11;

  (* Addressing modes for RV32 *)
  RegMode = 08H;     (* GPR x0-x31 *)
  FRegMode = 10H;    (* FPR f0-f31 *)
  ImmMode = 20H;     (* Immediate value *)
  MemMode = 28H;     (* Memory: offset(rs1) *)
  LabelMode = 30H;   (* Label reference *)
  FwdLabelMode = 31H; (* Forward label reference *)

  (* Scanner: ASCII codes *)
  TAB = 09X;
  CR = 0DX;
  LF = 0AX;
  SPACE = 20X;

  (* Scanner: Sym values *)
  ScUndef = 0;
  ScIdent = 1;
  ScSemicolon = 2;
  ScAt = 3;
  ScNumber = 4;
  ScComma = 5;
  ScLBrak = 6;
  ScRBrak = 7;
  ScCR = 8;
  ScMult = 9;
  ScEnd = 10;
  ScLabel = 11;
  ScColon = 12;
  ScPlus = 13;
  ScMinus = 14;
  ScDiv = 15;
  ScLPar = 16;
  ScRPar = 17;
  ScString = 18;
  ScPoint = 19;
  ScLBrace = 20;
  ScRBrace = 21;
  ScHash = 22;
  ScExcl = 23;

  (* Structure sizes *)
  NameLen = 32;
  MaxStrLen = 256;
  MnemoLen = 12;

  (* Instruction table sizes *)
  MaxInstr = 256;
  InstrHashSize = 512;

  (* Instruction categories *)
  CatRType = 0;    (* R-type: op rd, rs1, rs2 *)
  CatIType = 1;    (* I-type: op rd, rs1, imm *)
  CatSType = 2;    (* S-type: op rs2, offset(rs1) *)
  CatBType = 3;    (* B-type: op rs1, rs2, label *)
  CatUType = 4;    (* U-type: op rd, imm20 *)
  CatJType = 5;     (* J-type: JAL rd, label *)
  CatJALR = 6;     (* JALR rd, rs1, imm *)
  CatLoad = 7;     (* Load: op rd, offset(rs1) *)
  CatStore = 8;    (* Store: op rs2, offset(rs1) *)
  CatFLoad = 9;    (* FLW: op frd, offset(rs1) *)
  CatFStore = 10;  (* FSW: op frs2, offset(rs1) *)
  CatFR3 = 11;     (* Float R-type 3-operand: op frd, frs1, frs2 *)
  CatFR2 = 12;     (* Float R-type 2-operand: op frd, frs1 *)
  CatFCmp = 13;    (* Float compare: op xrd, frs1, frs2 *)
  CatFCvtF2I = 14;  (* FCVT.W.S: op xrd, frs1 *)
  CatFCvtI2F = 15;  (* FCVT.S.W: op frd, xrs1 *)
  CatFMvF2X = 16;  (* FMV.X.W: op xrd, frs1 *)
  CatFMvX2F = 17;  (* FMV.W.X: op frd, xrs1 *)
  CatSys = 18;     (* System: ECALL, EBREAK, WFI, FENCE *)
  CatData = 19;    (* Data directives: DCD, DCW, DCB *)
  CatPseudo = 20;  (* Pseudo-instructions: NOP, MV, LI, RET, etc. *)
  CatShiftI = 21;  (* Shift immediate: SLLI, SRLI, SRAI *)

  (* RV32 opcodes, bits [6:0] *)
  opLUI    = 037H;
  opAUIPC  = 017H;
  opJAL    = 06FH;
  opJALR   = 067H;
  opBRANCH = 063H;
  opLOAD   = 003H;
  opSTORE  = 023H;
  opOPIMM  = 013H;
  opOP     = 033H;
  opFLOAT  = 007H;
  opFSTORE = 027H;
  opFOP    = 053H;
  opSYSTEM = 073H;
  opFENCE  = 00FH;

  (* Pseudo-instruction sub-ops *)
  psNOP = 0; psMV = 1; psLI = 2; psRET = 3; psNEG = 4; psNOT = 5;
  psSEQZ = 6; psSNEZ = 7; psJ = 8; psCALL = 9;

 TYPE
  Name = OPS.Name;
  Mnemo = ARRAY MnemoLen OF CHAR;

  Object = POINTER TO ObjDesc;
  FixPnt = POINTER TO FixPntDesc;

  InstrDesc = RECORD
   name: Mnemo;
   cat: SHORTINT;       (* instruction category *)
   op: LONGINT;         (* primary opcode / sub-operation *)
   flags: SET;          (* instruction flags *)
  END;

  Operand = RECORD
   mode: LONGINT;
   reg: INTEGER;       (* register number *)
   imm: LONGINT;       (* immediate value *)
   disp: LONGINT;      (* displacement for memory *)
   base: INTEGER;      (* base register for memory *)
   obj: Object;        (* for fixups *)
  END;

  ObjDesc = RECORD
   typ: LONGINT;
   val, size: LONGINT;
   name: Name;
   left, right, next: Object;
   fix: FixPnt;
   obj: OPT.Object
  END;

  FixPntDesc = RECORD
   pc: LONGINT;
   node: OPT.Node;
   pos: LONGINT;
   next: FixPnt;
  END;

 VAR
  root: Object;
  InstrTab: ARRAY MaxInstr OF InstrDesc;
  InstrHash: ARRAY InstrHashSize OF INTEGER;
  nofInstr: INTEGER;
  SizeTab: ARRAY 17 OF SHORTINT;

  export, inline: BOOLEAN;
  FirstTime: BOOLEAN;
  Target: SET;
  pc: LONGINT;

  sym: LONGINT;
  ident: Name;
  val: LONGINT;
  str: ARRAY MaxStrLen OF CHAR;
  errpos: LONGINT;

  first, last: OPT.Node;
  fixlist: OPT.Node;


 PROCEDURE AND(a, b: LONGINT): LONGINT;
 BEGIN RETURN SYSTEM.VAL(LONGINT, SYSTEM.VAL(SET, a) * SYSTEM.VAL(SET, b))
 END AND;

 PROCEDURE ORL(a, b: LONGINT): LONGINT;
 BEGIN RETURN SYSTEM.VAL(LONGINT, SYSTEM.VAL(SET, a) + SYSTEM.VAL(SET, b))
 END ORL;

 PROCEDURE insert(VAR name: ARRAY OF CHAR; VAR obj: Object);
  VAR ob0, ob1: Object; d: LONGINT;
 BEGIN
  ob0 := root; ob1 := ob0.right; d := 1;
  LOOP
   IF ob1 = NIL THEN
    NEW(ob1); COPY(name, ob1.name); ob1.typ := StFwdLabel;
    ob1.left := NIL; ob1.right := NIL; ob1.fix := NIL; ob1.obj := NIL;
    ob1.next := root.next; root.next := ob1;
    ob1.val := OPM.errpos;
    IF d < 0 THEN ob0.left := ob1 ELSE ob0.right := ob1 END;
    EXIT
   ELSIF name < ob1.name THEN d := -1; ob0 := ob1; ob1 := ob1.left
   ELSIF name > ob1.name THEN d := 1; ob0 := ob1; ob1 := ob1.right
   ELSE EXIT
   END
  END;
  obj := ob1
 END insert;

 PROCEDURE ConvertObj(ob: OPT.Object): Object;
  VAR obj: Object;
 BEGIN
  IF ob # NIL THEN
   NEW(obj);
   CASE ob.mode OF
     | 1: (* Var *)
     obj.val := 1; obj.size := SizeTab[ob.typ.form];
     IF ob.mnolev <= 0 THEN obj.typ := StGlobal
     ELSE obj.typ := StVar
     END
    | 2: (* VarPar *)
     obj.typ := StVarPar; obj.val := 1; obj.size := 4
    | 3: (* Con *)
     obj.typ := StConst; obj.val := ob.conval.intval;
     IF (ob.typ.form > 6) OR (ob.typ.form = 2) THEN OPM.err(51) END
    | 5: (* Type *)
     obj.typ := StType; obj.size := SizeTab[ob.typ.form]; OPM.err(514)
    | 11: (* Mod *)
     obj.typ := StMod
   ELSE
    obj.typ := StConst; obj.val := 0; OPM.err(514)
   END;
   obj.obj := ob
  END;
  RETURN obj
 END ConvertObj;

 PROCEDURE find(VAR name: Name; VAR obj: Object);
  VAR ob0: Object; ob: OPT.Object;
 BEGIN
  ob0 := root.right;
  WHILE (ob0 # NIL) & (ob0.name # name) DO
   IF name < ob0.name THEN ob0 := ob0.left ELSE ob0 := ob0.right END
  END;
  obj := ob0;
  IF obj = NIL THEN
   COPY(name, OPS.name); OPT.Find(ob);
   IF ob # NIL THEN obj := ConvertObj(ob)
   ELSE insert(name, obj)
   END
  END
 END find;

 (* Instruction Table - Embedded directly *)
 PROCEDURE HashInstr(VAR name: ARRAY OF CHAR): LONGINT;
  VAR i, k: LONGINT;
 BEGIN
  i := 0; k := 0;
  WHILE name[i] # 0X DO
   k := (k * 31 + ORD(name[i])) MOD InstrHashSize;
   INC(i)
  END;
  RETURN k
 END HashInstr;

 PROCEDURE AddInstr(name: ARRAY OF CHAR; cat: SHORTINT; op: LONGINT; flags: SET);
  VAR h: LONGINT;
 BEGIN
  ASSERT(nofInstr < MaxInstr);
  COPY(name, InstrTab[nofInstr].name);
  InstrTab[nofInstr].cat := cat;
  InstrTab[nofInstr].op := op;
  InstrTab[nofInstr].flags := flags;
  h := HashInstr(name);
  WHILE InstrHash[h] >= 0 DO h := (h + 1) MOD InstrHashSize END;
  InstrHash[h] := nofInstr;
  INC(nofInstr)
 END AddInstr;

 PROCEDURE FindInstruction(VAR name: ARRAY OF CHAR; VAR inx: LONGINT);
  VAR h, n: LONGINT;
 BEGIN
  h := HashInstr(name);
  n := 0;
  WHILE (n < InstrHashSize) & (InstrHash[h] >= 0) DO
   IF InstrTab[InstrHash[h]].name = name THEN
    inx := InstrHash[h]; RETURN
   END;
   h := (h + 1) MOD InstrHashSize;
   INC(n)
  END;
  inx := -1
 END FindInstruction;

 PROCEDURE BuildInstrTable;
 (* Build the complete RV32IMAF instruction table *)
 BEGIN
  nofInstr := 0;

  (* Integer R-type: op = funct7*256 + funct3 *)
  AddInstr("ADD", CatRType, 000H * 100H + 0, {});
  AddInstr("SUB", CatRType, 020H * 100H + 0, {});
  AddInstr("AND", CatRType, 000H * 100H + 7, {});
  AddInstr("OR", CatRType, 000H * 100H + 6, {});
  AddInstr("XOR", CatRType, 000H * 100H + 4, {});
  AddInstr("SLL", CatRType, 000H * 100H + 1, {});
  AddInstr("SRL", CatRType, 000H * 100H + 5, {});
  AddInstr("SRA", CatRType, 020H * 100H + 5, {});
  AddInstr("SLT", CatRType, 000H * 100H + 2, {});
  AddInstr("SLTU", CatRType, 000H * 100H + 3, {});

  (* M extension: MUL, DIV, REM ? funct7=0x01 *)
  AddInstr("MUL", CatRType, 001H * 100H + 0, {});
  AddInstr("MULH", CatRType, 001H * 100H + 1, {});
  AddInstr("MULHSU", CatRType, 001H * 100H + 2, {});
  AddInstr("MULHU", CatRType, 001H * 100H + 3, {});
  AddInstr("DIV", CatRType, 001H * 100H + 4, {});
  AddInstr("DIVU", CatRType, 001H * 100H + 5, {});
  AddInstr("REM", CatRType, 001H * 100H + 6, {});
  AddInstr("REMU", CatRType, 001H * 100H + 7, {});

  (* Integer I-type: op = funct3 *)
  AddInstr("ADDI", CatIType, 0, {});
  AddInstr("ANDI", CatIType, 7, {});
  AddInstr("ORI", CatIType, 6, {});
  AddInstr("XORI", CatIType, 4, {});
  AddInstr("SLTI", CatIType, 2, {});
  AddInstr("SLTIU", CatIType, 3, {});

  (* Shift immediate: op = funct3*256 + funct7_bit *)
  AddInstr("SLLI", CatShiftI, 1 * 100H + 0, {});
  AddInstr("SRLI", CatShiftI, 5 * 100H + 0, {});
  AddInstr("SRAI", CatShiftI, 5 * 100H + 1, {}); (* funct7 bit 5 = 1 *)

  (* Upper immediate *)
  AddInstr("LUI", CatUType, opLUI, {});
  AddInstr("AUIPC", CatUType, opAUIPC, {});

  (* Jump *)
  AddInstr("JAL", CatJType, 0, {});
  AddInstr("JALR", CatJALR, 0, {});

  (* Branch: op = funct3 *)
  AddInstr("BEQ", CatBType, 0, {});
  AddInstr("BNE", CatBType, 1, {});
  AddInstr("BLT", CatBType, 4, {});
  AddInstr("BGE", CatBType, 5, {});
  AddInstr("BLTU", CatBType, 6, {});
  AddInstr("BGEU", CatBType, 7, {});

  (* Load: op = funct3 *)
  AddInstr("LB", CatLoad, 0, {});
  AddInstr("LH", CatLoad, 1, {});
  AddInstr("LW", CatLoad, 2, {});
  AddInstr("LBU", CatLoad, 4, {});
  AddInstr("LHU", CatLoad, 5, {});

  (* Store: op = funct3 *)
  AddInstr("SB", CatStore, 0, {});
  AddInstr("SH", CatStore, 1, {});
  AddInstr("SW", CatStore, 2, {});

  (* Float load/store *)
  AddInstr("FLW", CatFLoad, 2, {});
  AddInstr("FSW", CatFStore, 2, {});

  (* Float 3-operand: op = funct7 *)
  AddInstr("FADD.S", CatFR3, 000H, {});
  AddInstr("FSUB.S", CatFR3, 004H, {});
  AddInstr("FMUL.S", CatFR3, 008H, {});
  AddInstr("FDIV.S", CatFR3, 00CH, {});

  (* Float sign injection (2-operand using 3-operand format) *)
  AddInstr("FSGNJ.S", CatFR3, 010H, {});
  AddInstr("FSGNJN.S", CatFR3, 010H, {1}); (* funct3=1 flag *)
  AddInstr("FSGNJX.S", CatFR3, 010H, {2}); (* funct3=2 flag *)

  (* Float compare: op = funct3 *)
  AddInstr("FEQ.S", CatFCmp, 2, {});
  AddInstr("FLT.S", CatFCmp, 1, {});
  AddInstr("FLE.S", CatFCmp, 0, {});

  (* Float conversions *)
  AddInstr("FCVT.W.S", CatFCvtF2I, 0, {});   (* rs2=0 for W *)
  AddInstr("FCVT.WU.S", CatFCvtF2I, 1, {});  (* rs2=1 for WU *)
  AddInstr("FCVT.S.W", CatFCvtI2F, 0, {});   (* rs2=0 for W *)
  AddInstr("FCVT.S.WU", CatFCvtI2F, 1, {});  (* rs2=1 for WU *)

  (* Float move *)
  AddInstr("FMV.X.W", CatFMvF2X, 0, {});
  AddInstr("FMV.W.X", CatFMvX2F, 0, {});

  (* System instructions *)
  AddInstr("ECALL", CatSys, 0, {});
  AddInstr("EBREAK", CatSys, 1, {});
  AddInstr("FENCE", CatSys, 2, {});
  AddInstr("WFI", CatSys, 3, {});

  (* Data directives *)
  AddInstr("DCD", CatData, 4, {});
  AddInstr("DCW", CatData, 2, {});
  AddInstr("DCB", CatData, 1, {});

  (* Pseudo-instructions *)
  AddInstr("NOP", CatPseudo, psNOP, {});
  AddInstr("MV", CatPseudo, psMV, {});
  AddInstr("LI", CatPseudo, psLI, {});
  AddInstr("RET", CatPseudo, psRET, {});
  AddInstr("NEG", CatPseudo, psNEG, {});
  AddInstr("NOT", CatPseudo, psNOT, {});
  AddInstr("SEQZ", CatPseudo, psSEQZ, {});
  AddInstr("SNEZ", CatPseudo, psSNEZ, {});
  AddInstr("J", CatPseudo, psJ, {});
  AddInstr("CALL", CatPseudo, psCALL, {})
 END BuildInstrTable;


 PROCEDURE skipBlanks;
 BEGIN
  WHILE (OPS.ch = SPACE) OR (OPS.ch = TAB) DO OPM.Get(OPS.ch) END;
  IF OPS.ch = ";" THEN
   WHILE (OPS.ch # CR) & (OPS.ch # LF) DO OPM.Get(OPS.ch) END
  END
 END skipBlanks;

 PROCEDURE GetIdent(VAR name: Name);
  VAR i: LONGINT;
 BEGIN
  i := 0; OPM.errpos := OPM.curpos - 1;
  REPEAT
   IF i < NameLen - 1 THEN name[i] := OPS.ch; INC(i) END;
   OPM.Get(OPS.ch)
  UNTIL ~(("A" <= CAP(OPS.ch)) & (CAP(OPS.ch) <= "Z") OR ("0" <= OPS.ch) & (OPS.ch <= "9")
     OR (OPS.ch = ".") OR (OPS.ch = "_"));
  name[i] := 0X
 END GetIdent;

 PROCEDURE Get(VAR sym: LONGINT);

  PROCEDURE Comment;
  BEGIN
   OPM.Get(OPS.ch);
   LOOP
    LOOP
     WHILE OPS.ch = "(" DO OPM.Get(OPS.ch);
      IF OPS.ch = "*" THEN Comment END
     END;
     IF OPS.ch = "*" THEN OPM.Get(OPS.ch); EXIT END;
     IF OPS.ch = OPM.Eot THEN EXIT END;
     OPM.Get(OPS.ch)
    END;
    IF OPS.ch = ")" THEN OPM.Get(OPS.ch); EXIT END;
    IF OPS.ch = OPM.Eot THEN OPM.Mark(5, OPM.errpos); EXIT END
   END
  END Comment;

  PROCEDURE Str;
   VAR och: CHAR; i: LONGINT;
  BEGIN
   och := OPS.ch; i := 0;
   LOOP
    OPM.Get(OPS.ch);
    IF OPS.ch = och THEN EXIT
    ELSIF OPS.ch < " " THEN OPM.err(3); EXIT
    ELSIF i = MaxStrLen - 1 THEN OPM.err(241); EXIT
    END;
    str[i] := OPS.ch; INC(i)
   END;
   OPM.Get(OPS.ch);
   str[i] := 0X; val := i
  END Str;

 BEGIN
  skipBlanks;
  OPM.errpos := OPM.curpos;
  CASE OPS.ch OF
   "A".."Z", "a".."z":
    GetIdent(ident);
    IF OPS.ch = ":" THEN
     OPM.Get(OPS.ch); sym := ScLabel
    ELSIF ident = "END" THEN
     sym := ScEnd
    ELSE
     sym := ScIdent
    END
   | "0".."9":
    val := 0; sym := ScNumber;
    OPS.Number;
    ASSERT(OPS.numtyp <= 2);
    val := OPS.intval
   | ";": OPM.Get(OPS.ch); sym := ScSemicolon
   | "@": OPM.Get(OPS.ch); sym := ScAt
   | ",": OPM.Get(OPS.ch); sym := ScComma
   | "[": OPM.Get(OPS.ch); sym := ScLBrak
   | "]": OPM.Get(OPS.ch); sym := ScRBrak
   | "{": OPM.Get(OPS.ch); sym := ScLBrace
   | "}": OPM.Get(OPS.ch); sym := ScRBrace
   | CR: OPM.Get(OPS.ch); sym := ScCR
   | LF: OPM.Get(OPS.ch); sym := ScCR
   | "*": OPM.Get(OPS.ch); sym := ScMult
   | "/": OPM.Get(OPS.ch); sym := ScDiv
   | "+": OPM.Get(OPS.ch); sym := ScPlus
   | "-": OPM.Get(OPS.ch); sym := ScMinus
   | "(": OPM.Get(OPS.ch);
    IF OPS.ch = "*" THEN Comment; Get(sym)
    ELSE sym := ScLPar
    END
   | ")": OPM.Get(OPS.ch); sym := ScRPar
   | ":": OPM.Get(OPS.ch); sym := ScColon
   | ".": OPM.Get(OPS.ch); sym := ScPoint
   | "#": OPM.Get(OPS.ch); sym := ScHash
   | "!": OPM.Get(OPS.ch); sym := ScExcl
   | 22X, 27X: Str; sym := ScString
  ELSE
   sym := ScUndef; OPM.Get(OPS.ch)
  END
 END Get;

 PROCEDURE Check(s: LONGINT);
 BEGIN
  IF sym # s THEN OPM.err(SHORT(s)) END;
  Get(sym)
 END Check;

 PROCEDURE Expression(VAR x: LONGINT);
  VAR y, op: LONGINT;

  PROCEDURE Factor(VAR x: LONGINT);
  BEGIN
   IF sym = ScNumber THEN x := val; Get(sym)
   ELSIF sym = ScLPar THEN
    Get(sym); Expression(x);
    Check(ScRPar)
   ELSE OPM.err(601); x := 0
   END
  END Factor;

  PROCEDURE Term(VAR x: LONGINT);
   VAR y, op: LONGINT;
  BEGIN
   Factor(x);
   WHILE (sym = ScMult) OR (sym = ScDiv) DO
    op := sym; Get(sym);
    Factor(y);
    IF op = ScMult THEN x := x * y ELSE x := x DIV y END
   END
  END Term;

 BEGIN
  IF sym = ScMinus THEN Get(sym); Term(x); x := -x
  ELSE Term(x)
  END;
  WHILE (sym = ScPlus) OR (sym = ScMinus) DO
   op := sym; Get(sym);
   Term(y);
   IF op = ScPlus THEN x := x + y ELSE x := x - y END
  END
 END Expression;


 PROCEDURE ParseRegister(VAR name: Name; VAR reg: INTEGER; VAR mode: LONGINT): BOOLEAN;
 (* Parse a register name and return its number and mode *)
 BEGIN
  mode := RegMode;
  (* ABI names *)
  IF name = "zero" THEN reg := 0; RETURN TRUE
  ELSIF name = "ra" THEN reg := 1; RETURN TRUE
  ELSIF name = "sp" THEN reg := 2; RETURN TRUE
  ELSIF name = "gp" THEN reg := 3; RETURN TRUE
  ELSIF name = "tp" THEN reg := 4; RETURN TRUE
  ELSIF name = "t0" THEN reg := 5; RETURN TRUE
  ELSIF name = "t1" THEN reg := 6; RETURN TRUE
  ELSIF name = "t2" THEN reg := 7; RETURN TRUE
  ELSIF name = "s0" THEN reg := 8; RETURN TRUE
   ELSIF name = "fp" THEN reg := 8; RETURN TRUE
  ELSIF name = "s1" THEN reg := 9; RETURN TRUE
  ELSIF name = "a0" THEN reg := 10; RETURN TRUE
  ELSIF name = "a1" THEN reg := 11; RETURN TRUE
  ELSIF name = "a2" THEN reg := 12; RETURN TRUE
  ELSIF name = "a3" THEN reg := 13; RETURN TRUE
  ELSIF name = "a4" THEN reg := 14; RETURN TRUE
  ELSIF name = "a5" THEN reg := 15; RETURN TRUE
  ELSIF name = "a6" THEN reg := 16; RETURN TRUE
  ELSIF name = "a7" THEN reg := 17; RETURN TRUE
  ELSIF name = "s2" THEN reg := 18; RETURN TRUE
  ELSIF name = "s3" THEN reg := 19; RETURN TRUE
  ELSIF name = "s4" THEN reg := 20; RETURN TRUE
  ELSIF name = "s5" THEN reg := 21; RETURN TRUE
  ELSIF name = "s6" THEN reg := 22; RETURN TRUE
  ELSIF name = "s7" THEN reg := 23; RETURN TRUE
  ELSIF name = "s8" THEN reg := 24; RETURN TRUE
  ELSIF name = "s9" THEN reg := 25; RETURN TRUE
  ELSIF name = "s10" THEN reg := 26; RETURN TRUE
  ELSIF name = "s11" THEN reg := 27; RETURN TRUE
   ELSIF name = "t3" THEN reg := 28; RETURN TRUE
   ELSIF name = "t4" THEN reg := 29; RETURN TRUE
   ELSIF name = "t5" THEN reg := 30; RETURN TRUE
   ELSIF name = "t6" THEN reg := 31; RETURN TRUE
  (* Numeric names x0-x31 *)
  ELSIF name = "x0" THEN reg := 0; RETURN TRUE
  ELSIF name = "x1" THEN reg := 1; RETURN TRUE
  ELSIF name = "x2" THEN reg := 2; RETURN TRUE
  ELSIF name = "x3" THEN reg := 3; RETURN TRUE
  ELSIF name = "x4" THEN reg := 4; RETURN TRUE
  ELSIF name = "x5" THEN reg := 5; RETURN TRUE
  ELSIF name = "x6" THEN reg := 6; RETURN TRUE
  ELSIF name = "x7" THEN reg := 7; RETURN TRUE
  ELSIF name = "x8" THEN reg := 8; RETURN TRUE
  ELSIF name = "x9" THEN reg := 9; RETURN TRUE
  ELSIF name = "x10" THEN reg := 10; RETURN TRUE
  ELSIF name = "x11" THEN reg := 11; RETURN TRUE
  ELSIF name = "x12" THEN reg := 12; RETURN TRUE
  ELSIF name = "x13" THEN reg := 13; RETURN TRUE
  ELSIF name = "x14" THEN reg := 14; RETURN TRUE
  ELSIF name = "x15" THEN reg := 15; RETURN TRUE
  ELSIF name = "x16" THEN reg := 16; RETURN TRUE
  ELSIF name = "x17" THEN reg := 17; RETURN TRUE
  ELSIF name = "x18" THEN reg := 18; RETURN TRUE
  ELSIF name = "x19" THEN reg := 19; RETURN TRUE
  ELSIF name = "x20" THEN reg := 20; RETURN TRUE
  ELSIF name = "x21" THEN reg := 21; RETURN TRUE
  ELSIF name = "x22" THEN reg := 22; RETURN TRUE
  ELSIF name = "x23" THEN reg := 23; RETURN TRUE
  ELSIF name = "x24" THEN reg := 24; RETURN TRUE
  ELSIF name = "x25" THEN reg := 25; RETURN TRUE
  ELSIF name = "x26" THEN reg := 26; RETURN TRUE
  ELSIF name = "x27" THEN reg := 27; RETURN TRUE
  ELSIF name = "x28" THEN reg := 28; RETURN TRUE
  ELSIF name = "x29" THEN reg := 29; RETURN TRUE
  ELSIF name = "x30" THEN reg := 30; RETURN TRUE
  ELSIF name = "x31" THEN reg := 31; RETURN TRUE
  (* FP registers f0-f31 *)
  ELSIF name[0] = "f" THEN
   mode := FRegMode;
   IF name = "f0" THEN reg := 0; RETURN TRUE
   ELSIF name = "f1" THEN reg := 1; RETURN TRUE
   ELSIF name = "f2" THEN reg := 2; RETURN TRUE
   ELSIF name = "f3" THEN reg := 3; RETURN TRUE
   ELSIF name = "f4" THEN reg := 4; RETURN TRUE
   ELSIF name = "f5" THEN reg := 5; RETURN TRUE
   ELSIF name = "f6" THEN reg := 6; RETURN TRUE
   ELSIF name = "f7" THEN reg := 7; RETURN TRUE
   ELSIF name = "f8" THEN reg := 8; RETURN TRUE
   ELSIF name = "f9" THEN reg := 9; RETURN TRUE
   ELSIF name = "f10" THEN reg := 10; RETURN TRUE
   ELSIF name = "f11" THEN reg := 11; RETURN TRUE
   ELSIF name = "f12" THEN reg := 12; RETURN TRUE
   ELSIF name = "f13" THEN reg := 13; RETURN TRUE
   ELSIF name = "f14" THEN reg := 14; RETURN TRUE
   ELSIF name = "f15" THEN reg := 15; RETURN TRUE
   ELSIF name = "f16" THEN reg := 16; RETURN TRUE
   ELSIF name = "f17" THEN reg := 17; RETURN TRUE
   ELSIF name = "f18" THEN reg := 18; RETURN TRUE
   ELSIF name = "f19" THEN reg := 19; RETURN TRUE
   ELSIF name = "f20" THEN reg := 20; RETURN TRUE
   ELSIF name = "f21" THEN reg := 21; RETURN TRUE
   ELSIF name = "f22" THEN reg := 22; RETURN TRUE
   ELSIF name = "f23" THEN reg := 23; RETURN TRUE
   ELSIF name = "f24" THEN reg := 24; RETURN TRUE
   ELSIF name = "f25" THEN reg := 25; RETURN TRUE
   ELSIF name = "f26" THEN reg := 26; RETURN TRUE
   ELSIF name = "f27" THEN reg := 27; RETURN TRUE
   ELSIF name = "f28" THEN reg := 28; RETURN TRUE
   ELSIF name = "f29" THEN reg := 29; RETURN TRUE
   ELSIF name = "f30" THEN reg := 30; RETURN TRUE
   ELSIF name = "f31" THEN reg := 31; RETURN TRUE
   ELSE mode := RegMode; RETURN FALSE (* fp handled above *)
   END
  ELSE RETURN FALSE
  END
 END ParseRegister;

 PROCEDURE GetOperand(VAR o: Operand);
 (* Parse one RV32 operand *)
  VAR obj: Object; name: Name; reg: INTEGER; mode: LONGINT;
 BEGIN
  o.mode := none; o.reg := none; o.imm := 0; o.disp := 0;
  o.base := none; o.obj := NIL;
  IF sym = ScIdent THEN
   COPY(ident, name);
   IF ParseRegister(name, reg, mode) THEN
    o.mode := mode; o.reg := reg;
    Get(sym)
   ELSE
    find(name, obj);
    IF (obj # NIL) & (obj.typ = StLabel) THEN
     o.mode := LabelMode; o.imm := obj.val;
     Get(sym)
    ELSIF (obj # NIL) & (obj.typ = StFwdLabel) THEN
     o.mode := FwdLabelMode; o.obj := obj;
     Get(sym)
    ELSIF (obj # NIL) & (obj.typ = StConst) THEN
     o.mode := ImmMode; o.imm := obj.val;
     Get(sym)
    ELSE
     o.mode := ImmMode; o.imm := 0;
     OPM.err(500)
    END
   END
  ELSIF sym = ScNumber THEN
   o.mode := ImmMode;
   Expression(o.imm)
  ELSIF sym = ScMinus THEN
   o.mode := ImmMode;
   Expression(o.imm)
  ELSE
   o.mode := none
  END
 END GetOperand;

 PROCEDURE GetMemOperand(VAR o: Operand);
 (* Parse a RV32 memory operand: imm(rs1) *)
 (* Expects the immediate to already be in o.imm if parsed *)
  VAR name: Name; reg: INTEGER; mode: LONGINT;
 BEGIN
  o.mode := MemMode;
  (* Parse offset *)
  IF sym = ScNumber THEN
   Expression(o.disp)
  ELSIF sym = ScMinus THEN
   Expression(o.disp)
  ELSIF sym = ScIdent THEN
   (* Check if identifier is actually a register (zero offset) *)
   COPY(ident, name);
   IF ~ParseRegister(name, reg, mode) THEN
    (* Could be a constant expression *)
    Expression(o.disp)
   ELSE
    o.disp := 0
   END
  ELSE
   o.disp := 0
  END;
  (* Expect ( rs1 ) *)
  IF sym = ScLPar THEN
   Get(sym);
   IF sym = ScIdent THEN
    COPY(ident, name);
    IF ParseRegister(name, reg, mode) & (mode = RegMode) THEN
     o.base := reg; Get(sym)
    ELSE OPM.err(506)
    END
   ELSE OPM.err(506)
   END;
   IF sym = ScRPar THEN Get(sym) ELSE OPM.err(507) END
  ELSE
   OPM.err(507)
  END
 END GetMemOperand;


 PROCEDURE CheckLabels;
  VAR obj, obj1, obj2: Object;
 BEGIN
  obj1 := root.next; obj := NIL;
  WHILE obj1 # NIL DO
   obj2 := obj1.next; obj1.next := obj; obj := obj1; obj1 := obj2
  END;
  WHILE obj # NIL DO
   IF obj.typ = StFwdLabel THEN
    OPM.Mark(128, obj.val)
   END;
   obj := obj.next
  END
 END CheckLabels;

 PROCEDURE InsertFix(VAR obj: Object; pc: LONGINT);
  VAR fix: FixPnt; x: OPT.Node;
 BEGIN
  CASE obj.typ OF
   StFwdLabel:
    NEW(fix); fix.pc := pc;
    fix.node := last;
    fix.pos := ORD(last.conval.ext[0]) - 3;
    fix.next := obj.fix; obj.fix := fix
   | StVar, StVarPar, StGlobal:
    IF export & inline THEN OPM.err(517) END;
    x := OPT.NewNode(Nfixup);
    x.obj := obj.obj; x.conval := OPT.NewConst();
    x.conval.intval := pc; x.conval.intval2 := OPM.errpos;
    x.link := fixlist; fixlist := x
  ELSE
   OPM.err(607)
  END
 END InsertFix;

 PROCEDURE FixDisp(VAR fix: FixPnt);
  VAR pos: LONGINT; disp, i: LONGINT;
 BEGIN
  disp := pc - fix.pc;
  FOR i := 0 TO 3 DO
   fix.node.conval.ext[fix.pos + i] := CHR(disp MOD 256);
   disp := disp DIV 256
  END
 END FixDisp;


 PROCEDURE NewNode;
  VAR x: OPT.Node;
 BEGIN
  x := OPT.NewNode(Ncode); x.conval := OPT.NewConst();
  x.conval.ext := OPT.NewExt(); x.conval.ext[0] := 0X;
  x.conval.intval := OPM.errpos;
  OPB.Link(first, last, x)
 END NewNode;

 PROCEDURE PutByte(b: LONGINT);
  VAR pos: LONGINT;
 BEGIN
  pos := ORD(last.conval.ext[0]) + 1;
  IF pos > 255 THEN NewNode; pos := 1 END;
  last.conval.ext[pos] := CHR(b);
  last.conval.ext[0] := CHR(pos);
  INC(pc)
 END PutByte;

 PROCEDURE PutWord(w: LONGINT);
 (* Emit a 32-bit instruction word (little-endian) *)
 BEGIN
  PutByte(AND(w, 0FFH));
  PutByte(AND(w DIV 100H, 0FFH));
  PutByte(AND(w DIV 10000H, 0FFH));
  PutByte(AND(w DIV 1000000H, 0FFH))
 END PutWord;


 PROCEDURE EncRType(funct7, rs2, rs1, funct3, rd, opcode: LONGINT);
 BEGIN
  PutWord(
   (funct7 MOD 80H) * 2000000H +
   (rs2 MOD 20H) * 100000H +
   (rs1 MOD 20H) * 8000H +
   (funct3 MOD 8) * 1000H +
   (rd MOD 20H) * 80H +
   (opcode MOD 80H))
 END EncRType;

 PROCEDURE EncIType(imm12, rs1, funct3, rd, opcode: LONGINT);
 BEGIN
  PutWord(
   (imm12 MOD 1000H) * 100000H +
   (rs1 MOD 20H) * 8000H +
   (funct3 MOD 8) * 1000H +
   (rd MOD 20H) * 80H +
   (opcode MOD 80H))
 END EncIType;

 PROCEDURE EncSType(imm12, rs2, rs1, funct3, opcode: LONGINT);
  VAR lo, hi: LONGINT;
 BEGIN
  lo := imm12 MOD 20H;
  hi := (imm12 DIV 20H) MOD 80H;
  PutWord(
   hi * 2000000H +
   (rs2 MOD 20H) * 100000H +
   (rs1 MOD 20H) * 8000H +
   (funct3 MOD 8) * 1000H +
   lo * 80H +
   (opcode MOD 80H))
 END EncSType;

 PROCEDURE EncBType(imm13, rs2, rs1, funct3, opcode: LONGINT);
  VAR b12, b11, bA, bB: LONGINT;
 BEGIN
  b12 := (imm13 DIV 1000H) MOD 2;
  b11 := (imm13 DIV 800H) MOD 2;
  bA  := (imm13 DIV 20H) MOD 40H;
  bB  := (imm13 DIV 2) MOD 10H;
  PutWord(
   b12 * 80000000H +
   bA * 2000000H +
   (rs2 MOD 20H) * 100000H +
   (rs1 MOD 20H) * 8000H +
   (funct3 MOD 8) * 1000H +
   bB * 100H +
   b11 * 80H +
   (opcode MOD 80H))
 END EncBType;

 PROCEDURE EncUType(imm20, rd, opcode: LONGINT);
 BEGIN
  PutWord(
   (imm20 MOD 100000H) * 1000H +
   (rd MOD 20H) * 80H +
   (opcode MOD 80H))
 END EncUType;

 PROCEDURE EncJType(imm21, rd, opcode: LONGINT);
  VAR b20, bC, b11, bD: LONGINT;
 BEGIN
  b20 := (imm21 DIV 100000H) MOD 2;
  bC  := (imm21 DIV 1000H) MOD 100H;
  b11 := (imm21 DIV 800H) MOD 2;
  bD  := (imm21 DIV 2) MOD 400H;
  PutWord(
   b20 * 80000000H +
   bD * 200000H +
   b11 * 100000H +
   bC * 1000H +
   (rd MOD 20H) * 80H +
   (opcode MOD 80H))
 END EncJType;

 PROCEDURE LoadImm32(rd, imm: LONGINT);
 (* Load 32-bit immediate using LUI + ADDI *)
  VAR lo12, hi20: LONGINT;
 BEGIN
  IF (imm >= -2048) & (imm <= 2047) THEN
   EncIType(imm, 0, 0, rd, opOPIMM) (* ADDI rd, x0, imm *)
  ELSE
   lo12 := imm MOD 1000H;
   IF lo12 >= 800H THEN lo12 := lo12 - 1000H END;
   hi20 := (imm - lo12) DIV 1000H;
   EncUType(hi20 MOD 100000H, rd, opLUI);
   IF lo12 # 0 THEN
    EncIType(lo12, rd, 0, rd, opOPIMM) (* ADDI rd, rd, lo12 *)
   END
  END
 END LoadImm32;


 PROCEDURE ParseInstruction;
  VAR inx, opcode, cat: LONGINT;
   op: ARRAY 4 OF Operand;
   nop: INTEGER;
   name: Name;
   funct7, funct3: LONGINT;
   i: INTEGER;
 BEGIN
  COPY(ident, name);
  FindInstruction(name, inx);
  IF inx < 0 THEN OPM.err(502); Get(sym); RETURN END;

  cat := InstrTab[inx].cat;
  opcode := InstrTab[inx].op;

  (* Parse operands *)
  Get(sym); nop := 0;
  FOR i := 0 TO 3 DO
   op[i].mode := none; op[i].reg := none; op[i].imm := 0;
   op[i].disp := 0; op[i].base := none; op[i].obj := NIL
  END;

  CASE cat OF
   | CatRType:
    (* op rd, rs1, rs2 *)
    GetOperand(op[0]); Check(ScComma);
    GetOperand(op[1]); Check(ScComma);
    GetOperand(op[2]);
    IF (op[0].mode = RegMode) & (op[1].mode = RegMode) & (op[2].mode = RegMode) THEN
     funct7 := opcode DIV 100H;
     funct3 := opcode MOD 100H;
     EncRType(funct7, op[2].reg, op[1].reg, funct3, op[0].reg, opOP)
    ELSE OPM.err(501)
    END

  | CatIType:
    (* op rd, rs1, imm *)
    GetOperand(op[0]); Check(ScComma);
    GetOperand(op[1]); Check(ScComma);
    GetOperand(op[2]);
    IF (op[0].mode = RegMode) & (op[1].mode = RegMode) & (op[2].mode = ImmMode) THEN
     funct3 := opcode;
     EncIType(op[2].imm, op[1].reg, funct3, op[0].reg, opOPIMM)
    ELSE OPM.err(501)
    END

  | CatShiftI:
    (* op rd, rs1, shamt *)
    GetOperand(op[0]); Check(ScComma);
    GetOperand(op[1]); Check(ScComma);
    GetOperand(op[2]);
    IF (op[0].mode = RegMode) & (op[1].mode = RegMode) & (op[2].mode = ImmMode) THEN
     funct3 := opcode DIV 100H;
     (* For SRAI, set bit 30 (funct7 bit 5) *)
     IF opcode MOD 100H = 1 THEN (* SRAI *)
      EncIType(400H + op[2].imm MOD 20H, op[1].reg, funct3, op[0].reg, opOPIMM)
     ELSE
      EncIType(op[2].imm MOD 20H, op[1].reg, funct3, op[0].reg, opOPIMM)
     END
    ELSE OPM.err(501)
    END

  | CatUType:
    (* op rd, imm20 *)
    GetOperand(op[0]); Check(ScComma);
    GetOperand(op[1]);
    IF (op[0].mode = RegMode) & (op[1].mode = ImmMode) THEN
     EncUType(op[1].imm, op[0].reg, opcode)
    ELSE OPM.err(501)
    END

  | CatJType:
    GetOperand(op[0]);
    IF op[0].mode = RegMode THEN
     Check(ScComma);
     GetOperand(op[1]);
     IF op[1].mode = ImmMode THEN
      EncJType(op[1].imm, op[0].reg, opJAL)
     ELSIF op[1].mode = LabelMode THEN
      EncJType(op[1].imm - pc, op[0].reg, opJAL)
     ELSIF op[1].mode = FwdLabelMode THEN
      PutWord(opJAL + (op[0].reg MOD 20H) * 80H);
      IF op[1].obj # NIL THEN InsertFix(op[1].obj, pc - 4) END
     ELSE OPM.err(501)
     END
    ELSIF (op[0].mode = LabelMode) OR (op[0].mode = ImmMode) THEN
     (* JAL offset (implicit rd=ra) *)
     IF op[0].mode = LabelMode THEN
      EncJType(op[0].imm - pc, 1, opJAL) (* rd=ra=x1 *)
     ELSE
      EncJType(op[0].imm, 1, opJAL)
     END
    ELSIF op[0].mode = FwdLabelMode THEN
     PutWord(opJAL + 1 * 80H); (* rd=ra *)
     IF op[0].obj # NIL THEN InsertFix(op[0].obj, pc - 4) END
    ELSE OPM.err(501)
    END

  | CatJALR:
    GetOperand(op[0]); Check(ScComma);
    GetOperand(op[1]);
    IF (op[0].mode = RegMode) & (op[1].mode = RegMode) THEN
     Check(ScComma);
     GetOperand(op[2]);
     IF op[2].mode = ImmMode THEN
      EncIType(op[2].imm, op[1].reg, 0, op[0].reg, opJALR)
     ELSE OPM.err(501)
     END
    ELSE OPM.err(501)
    END

  | CatBType:
    GetOperand(op[0]); Check(ScComma);
    GetOperand(op[1]); Check(ScComma);
    GetOperand(op[2]);
    IF (op[0].mode = RegMode) & (op[1].mode = RegMode) THEN
     IF op[2].mode = ImmMode THEN
      EncBType(op[2].imm, op[1].reg, op[0].reg, opcode, opBRANCH)
     ELSIF op[2].mode = LabelMode THEN
      EncBType(op[2].imm - pc, op[1].reg, op[0].reg, opcode, opBRANCH)
     ELSIF op[2].mode = FwdLabelMode THEN
      PutWord(opBRANCH + (opcode MOD 8) * 1000H +
        (op[0].reg MOD 20H) * 8000H + (op[1].reg MOD 20H) * 100000H);
      IF op[2].obj # NIL THEN InsertFix(op[2].obj, pc - 4) END
     ELSE OPM.err(501)
     END
    ELSE OPM.err(501)
    END

  | CatLoad:
    GetOperand(op[0]); Check(ScComma);
    IF op[0].mode = RegMode THEN
     GetMemOperand(op[1]);
     IF op[1].mode = MemMode THEN
      EncIType(op[1].disp, op[1].base, opcode, op[0].reg, opLOAD)
     ELSE OPM.err(501)
     END
    ELSE OPM.err(501)
    END

  | CatStore:
    GetOperand(op[0]); Check(ScComma);
    IF op[0].mode = RegMode THEN
     GetMemOperand(op[1]);
     IF op[1].mode = MemMode THEN
      EncSType(op[1].disp, op[0].reg, op[1].base, opcode, opSTORE)
     ELSE OPM.err(501)
     END
    ELSE OPM.err(501)
    END

  | CatFLoad:
    GetOperand(op[0]); Check(ScComma);
    IF op[0].mode = FRegMode THEN
     GetMemOperand(op[1]);
     IF op[1].mode = MemMode THEN
      EncIType(op[1].disp, op[1].base, opcode, op[0].reg, opFLOAT)
     ELSE OPM.err(501)
     END
    ELSE OPM.err(501)
    END

  | CatFStore:
    GetOperand(op[0]); Check(ScComma);
    IF op[0].mode = FRegMode THEN
     GetMemOperand(op[1]);
     IF op[1].mode = MemMode THEN
      EncSType(op[1].disp, op[0].reg, op[1].base, opcode, opFSTORE)
     ELSE OPM.err(501)
     END
    ELSE OPM.err(501)
    END

  | CatFR3:
    GetOperand(op[0]); Check(ScComma);
    GetOperand(op[1]); Check(ScComma);
    GetOperand(op[2]);
    IF (op[0].mode = FRegMode) & (op[1].mode = FRegMode) & (op[2].mode = FRegMode) THEN
     funct3 := 7; (* rmDYN by default *)
     IF 1 IN InstrTab[inx].flags THEN funct3 := 1
     ELSIF 2 IN InstrTab[inx].flags THEN funct3 := 2
     END;
     EncRType(opcode, op[2].reg, op[1].reg, funct3, op[0].reg, opFOP)
    ELSE OPM.err(501)
    END

  | CatFCmp:
    GetOperand(op[0]); Check(ScComma);
    GetOperand(op[1]); Check(ScComma);
    GetOperand(op[2]);
    IF (op[0].mode = RegMode) & (op[1].mode = FRegMode) & (op[2].mode = FRegMode) THEN
     EncRType(050H, op[2].reg, op[1].reg, opcode, op[0].reg, opFOP)
    ELSE OPM.err(501)
    END

  | CatFCvtF2I:
    GetOperand(op[0]); Check(ScComma);
    GetOperand(op[1]);
    IF (op[0].mode = RegMode) & (op[1].mode = FRegMode) THEN
     EncRType(060H, opcode, op[1].reg, 7, op[0].reg, opFOP) (* rmDYN *)
    ELSE OPM.err(501)
    END

  | CatFCvtI2F:
    GetOperand(op[0]); Check(ScComma);
    GetOperand(op[1]);
    IF (op[0].mode = FRegMode) & (op[1].mode = RegMode) THEN
     EncRType(068H, opcode, op[1].reg, 7, op[0].reg, opFOP)
    ELSE OPM.err(501)
    END

  | CatFMvF2X:
    GetOperand(op[0]); Check(ScComma);
    GetOperand(op[1]);
    IF (op[0].mode = RegMode) & (op[1].mode = FRegMode) THEN
     EncRType(070H, 0, op[1].reg, 0, op[0].reg, opFOP)
    ELSE OPM.err(501)
    END

  | CatFMvX2F:
    GetOperand(op[0]); Check(ScComma);
    GetOperand(op[1]);
    IF (op[0].mode = FRegMode) & (op[1].mode = RegMode) THEN
     EncRType(078H, 0, op[1].reg, 0, op[0].reg, opFOP)
    ELSE OPM.err(501)
    END

  | CatSys:
    CASE opcode OF
     0: PutWord(073H)           (* ECALL *)
    | 1: PutWord(00100073H)     (* EBREAK *)
    | 2: PutWord(00FF000FH)     (* FENCE iorw, iorw *)
    | 3: PutWord(010500073H)    (* WFI *)
    END

  | CatData:
    GetOperand(op[0]);
    IF op[0].mode = ImmMode THEN
     IF opcode = 4 THEN PutWord(op[0].imm)
     ELSIF opcode = 2 THEN
      PutByte(AND(op[0].imm, 0FFH));
      PutByte(AND(op[0].imm DIV 100H, 0FFH))
     ELSIF opcode = 1 THEN
      PutByte(AND(op[0].imm, 0FFH))
     END
    ELSIF op[0].mode = FwdLabelMode THEN
     IF opcode = 4 THEN
      PutWord(0);
      IF op[0].obj # NIL THEN InsertFix(op[0].obj, pc - 4) END
     ELSE OPM.err(501)
     END
    ELSE OPM.err(501)
    END

  | CatPseudo:
    CASE opcode OF
     psNOP: 
      PutWord(013H)
    | psMV: 
      GetOperand(op[0]); Check(ScComma);
      GetOperand(op[1]);
      IF (op[0].mode = RegMode) & (op[1].mode = RegMode) THEN
       EncIType(0, op[1].reg, 0, op[0].reg, opOPIMM)
      ELSE OPM.err(501)
      END
    | psLI: 
      GetOperand(op[0]); Check(ScComma);
      GetOperand(op[1]);
      IF (op[0].mode = RegMode) & (op[1].mode = ImmMode) THEN
       LoadImm32(op[0].reg, op[1].imm)
      ELSE OPM.err(501)
      END
    | psRET: 
      EncIType(0, 1, 0, 0, opJALR)
    | psNEG: 
      GetOperand(op[0]); Check(ScComma);
      GetOperand(op[1]);
      IF (op[0].mode = RegMode) & (op[1].mode = RegMode) THEN
       EncRType(020H, op[1].reg, 0, 0, op[0].reg, opOP)
      ELSE OPM.err(501)
      END
    | psNOT: 
      GetOperand(op[0]); Check(ScComma);
      GetOperand(op[1]);
      IF (op[0].mode = RegMode) & (op[1].mode = RegMode) THEN
       EncIType(0FFFH, op[1].reg, 4, op[0].reg, opOPIMM)
      ELSE OPM.err(501)
      END
    | psSEQZ: 
      GetOperand(op[0]); Check(ScComma);
      GetOperand(op[1]);
      IF (op[0].mode = RegMode) & (op[1].mode = RegMode) THEN
       EncIType(1, op[1].reg, 3, op[0].reg, opOPIMM)
      ELSE OPM.err(501)
      END
    | psSNEZ: 
      GetOperand(op[0]); Check(ScComma);
      GetOperand(op[1]);
      IF (op[0].mode = RegMode) & (op[1].mode = RegMode) THEN
       EncRType(0, op[1].reg, 0, 3, op[0].reg, opOP)
      ELSE OPM.err(501)
      END
    | psJ: 
      GetOperand(op[0]);
      IF op[0].mode = ImmMode THEN
       EncJType(op[0].imm, 0, opJAL)
      ELSIF op[0].mode = LabelMode THEN
       EncJType(op[0].imm - pc, 0, opJAL)
      ELSIF op[0].mode = FwdLabelMode THEN
       PutWord(opJAL);
       IF op[0].obj # NIL THEN InsertFix(op[0].obj, pc - 4) END
      ELSE OPM.err(501)
      END
    | psCALL: 
      GetOperand(op[0]);
      IF op[0].mode = ImmMode THEN
       EncJType(op[0].imm, 1, opJAL)
      ELSIF op[0].mode = LabelMode THEN
       EncJType(op[0].imm - pc, 1, opJAL)
      ELSIF op[0].mode = FwdLabelMode THEN
       PutWord(opJAL + 1 * 80H);
       IF op[0].obj # NIL THEN InsertFix(op[0].obj, pc - 4) END
      ELSE OPM.err(501)
      END
    END

  ELSE
   OPM.err(502)
  END
 END ParseInstruction;

 PROCEDURE ParseLabel;
  VAR obj: Object; fix: FixPnt;
 BEGIN
  ASSERT(sym = ScLabel);
  insert(ident, obj);
  IF obj.typ = StFwdLabel THEN
   fix := obj.fix;
   WHILE fix # NIL DO FixDisp(fix); fix := fix.next END;
   obj.typ := StLabel; obj.val := pc
  ELSE OPM.err(512)
  END;
  Get(sym)
 END ParseLabel;


 PROCEDURE Init;
 BEGIN
  root.next := NIL; root.left := NIL; root.right := NIL;
  pc := 0; Target := {RV32IMAF}
 END Init;

 PROCEDURE Close;
 BEGIN
  root.right := NIL
 END Close;

 PROCEDURE BodyInit;
  VAR i: LONGINT;
 BEGIN
  OPM.LogWLn; OPM.LogWStr("  using OP2-ASM RV32 add-on");
  NEW(root); root.left := NIL; root.right := NIL; root.next := NIL;

  (* Initialize hash table *)
  FOR i := 0 TO InstrHashSize - 1 DO InstrHash[i] := -1 END;

  (* Build embedded instruction tables *)
  BuildInstrTable;

  (* Initialize size table for Oberon types *)
  SizeTab[0] := 0; SizeTab[1] := 1; SizeTab[2] := 1; SizeTab[3] := 1;
  SizeTab[4] := 1; SizeTab[5] := 2; SizeTab[6] := 4; SizeTab[7] := 4;
  SizeTab[8] := 8; SizeTab[9] := 4; SizeTab[10] := 4; SizeTab[11] := 4;
  SizeTab[12] := 0; SizeTab[13] := 4; SizeTab[14] := 4; SizeTab[15] := 0;
  SizeTab[16] := 8
 END BodyInit;

 (* Entry point *)
 PROCEDURE Assemble*(VAR x: OPT.Node; exported, inlined: BOOLEAN);
 BEGIN
  export := exported; inline := inlined;
  IF FirstTime THEN BodyInit; FirstTime := FALSE END;
  Init;
  first := NIL; last := NIL; NewNode;
  fixlist := NIL;
  Get(sym);
  IF sym = ScLBrace THEN
   (* Skip target specification *)
   WHILE (sym # ScRBrace) & (sym # ScCR) & (sym # ScEnd) DO Get(sym) END;
   IF sym = ScRBrace THEN Get(sym) END
  ELSE
   Get(sym)
  END;
  WHILE (sym # ScEnd) & (sym # ScUndef) DO
   IF sym = ScLabel THEN ParseLabel END;
   IF sym = ScIdent THEN ParseInstruction END;
   WHILE (sym # ScEnd) & (sym # ScCR) DO
    Get(sym); OPM.err(510)
   END;
   Get(sym)
  END;
  IF OPM.noerr THEN CheckLabels END;
  Close;
  OPB.Construct(Nassembler, first, fixlist); x := first; x.conval := NIL
 END Assemble;

BEGIN
 FirstTime := TRUE
END OPA.
