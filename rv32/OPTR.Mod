(* OPTR - Target module for the OP2 compiler 
  Abstracts target-specific properties for the front end 
  RV32 (RISC-V 32-bit, RV32IMAF) implementation (for the Olimex ESP32-P4-PC board)

 Register numbering scheme for RV32:
    0..31  = x0..x31 (32-bit GPRs)
    x0  = zero (hardwired zero, not usable)
    x1  = ra  (return address / link register)
    x2  = sp  (stack pointer)
    x3  = gp  (global pointer, reserved)
    x4  = tp  (thread pointer, reserved)
    x5  = t0  (scratch, used internally by backend like ARM's IP)
    x8  = s0  (frame pointer / FP)
    x30 = t5  (comparison scratch register 1)
    x31 = t6  (comparison scratch register 2)
 
   Allocatable GPRs used by OPL:
      x10-x17 (a0-a7), x6-x7 (t1-t2), x28-x29 (t3-t4), x9 (s1)
   ValidRegType: All GPRs 1..31 can hold any 32-bit-or-smaller type.
     x0 is excluded because it is hardwired to zero.
   RegIndex: Identity (RISC-V register number = index).

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

MODULE OPTR; (** non-portable *)
 IMPORT OPM;
 
 CONST
  (* Structure forms - needed for ValidRegType *)
  Undef = 0; Byte = 1; Bool = 2; Char = 3; SInt = 4; Int = 5; LInt = 6;
  Real = 7; Set = 9; NilTyp = 11;
  Pointer = 13; ProcTyp = 14;

 TYPE
  EnterConstProc* = PROCEDURE(name: ARRAY OF CHAR; value: LONGINT);

 VAR
  Target* : SHORTINT;
  MinRegNr*: LONGINT;
  MaxRegNr*: LONGINT;

 PROCEDURE ValidRegType*(regNr: LONGINT; typeForm: SHORTINT): BOOLEAN;
 BEGIN
  IF (1 <= regNr) & (regNr <= 31) THEN
   RETURN typeForm IN {Undef..Real, Set, NilTyp, Pointer, ProcTyp}
  ELSE
   RETURN FALSE
  END
 END ValidRegType;

 PROCEDURE RegIndex*(regNr: LONGINT): LONGINT;
 BEGIN
  RETURN regNr
 END RegIndex;

 PROCEDURE IsLegacyReg*(regNr: LONGINT): BOOLEAN;
 BEGIN
  RETURN (1 <= regNr) & (regNr <= 31)
 END IsLegacyReg;

 PROCEDURE EnterRegisters*(enter: EnterConstProc);
 BEGIN
  (* ABI names *)
  enter("zero", 0);
  enter("ra", 1); enter("sp", 2); enter("gp", 3); enter("tp", 4);
  enter("t0", 5); enter("t1", 6); enter("t2", 7);
  enter("s0", 8); enter("FP", 8); enter("s1", 9);
  enter("a0", 10); enter("a1", 11); enter("a2", 12); enter("a3", 13);
  enter("a4", 14); enter("a5", 15); enter("a6", 16); enter("a7", 17);
  enter("s2", 18); enter("s3", 19); enter("s4", 20); enter("s5", 21);
  enter("s6", 22); enter("s7", 23); enter("s8", 24); enter("s9", 25);
  enter("s10", 26); enter("s11", 27);
  enter("t3", 28); enter("t4", 29); enter("t5", 30); enter("t6", 31);
  (* Numeric names *)
  enter("x0", 0); enter("x1", 1); enter("x2", 2); enter("x3", 3);
  enter("x4", 4); enter("x5", 5); enter("x6", 6); enter("x7", 7);
  enter("x8", 8); enter("x9", 9); enter("x10", 10); enter("x11", 11);
  enter("x12", 12); enter("x13", 13); enter("x14", 14); enter("x15", 15);
  enter("x16", 16); enter("x17", 17); enter("x18", 18); enter("x19", 19);
  enter("x20", 20); enter("x21", 21); enter("x22", 22); enter("x23", 23);
  enter("x24", 24); enter("x25", 25); enter("x26", 26); enter("x27", 27);
  enter("x28", 28); enter("x29", 29); enter("x30", 30); enter("x31", 31);
  (* Aliases *)
  enter("SP", 2); enter("RA", 1)
 END EnterRegisters;

BEGIN
 Target := OPM.rv32;
 MinRegNr := 0;
 MaxRegNr := 31
END OPTR.
