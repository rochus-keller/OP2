(*
   Low-level Out module for RV32 using RISC-V semihosting.
   Uses the standard RISC-V semihosting trap sequence:
     SLLI x0, x0, 0x1F
     EBREAK
     SRAI x0, x0, 7
   with SYS_WRITEC (op=3) to write a single character.
   Requires QEMU 10.x or later with -semihosting flag.
   The OP2 compiler generates a prologue for all procedures including CODE blocks.
   Parameters are on the stack frame at FP+8, FP+12, etc (pushed by caller).
   
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

MODULE RawOut;

  IMPORT SYSTEM;

  (* Write a single character via semihosting SYS_WRITEC (op=3).
     a0 = operation number (3 = SYS_WRITEC)
     a1 = pointer to character byte on stack (FP+8) *)
  PROCEDURE Char*(ch: CHAR);
  CODE {SYSTEM.riscv}
    ADDI  a1, s0, 8
    ADDI  a0, x0, 3
    SLLI  x0, x0, 31
    EBREAK
    SRAI  x0, x0, 7
  END Char;

  (* Write a null-terminated string by iterating and calling Char. *)
  PROCEDURE String*(str: ARRAY OF CHAR);
    VAR i: INTEGER;
  BEGIN i := 0;
    WHILE str[i] # 0X DO Char(str[i]); INC(i) END
  END String;

  PROCEDURE Int*(i: LONGINT; n: INTEGER);
  VAR
    j, k: LONGINT;
    buf: ARRAY 12 OF CHAR;
    isNeg: BOOLEAN;
  BEGIN
    IF i = 0 THEN
      Char("0"); RETURN
    END;

    isNeg := i < 0;
    IF isNeg THEN i := -i END;

    j := 0;
    WHILE i > 0 DO
      buf[j] := CHR(i MOD 10 + ORD("0"));
      i := i DIV 10;
      INC(j)
    END;

    IF isNeg THEN
      buf[j] := "-"; INC(j)
    END;

    k := j - 1;
    WHILE k >= 0 DO
      Char(buf[k]);
      DEC(k)
    END
  END Int;

  (* Ln: write newline via semihosting SYS_WRITEC *)
  PROCEDURE Ln*;
  VAR ch: CHAR;
  BEGIN ch := 0AX; Char(ch)
  END Ln;

  (* Exit: semihosting SYS_EXIT (op=18H) *)
  PROCEDURE Exit*(res: LONGINT);
  CODE {SYSTEM.riscv}
    ADDI  a1, x0, 0
    ADDI  a0, x0, 24
    SLLI  x0, x0, 31
    EBREAK
    SRAI  x0, x0, 7
  loop:
    WFI
    JAL   x0, loop
  END Exit;

BEGIN
  String("Hello from Oberon raw out!"); Ln
END RawOut.
