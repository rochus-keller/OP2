(*
   Low-level Out module for ARM32 (or QEMU) using ARM Semihosting
   instead of x86 I/O ports.
   Spec: ARM IHI0031 (Semihosting for AArch32 and AArch64)
     SYS_WRITEC          = 0x03  R1 = address of character byte
     SYS_WRITE0          = 0x04  R1 = address of null-terminated string
     SYS_EXIT_EXTENDED   = 0x20  R1 = address of {reason, exit_code}
     ADP_Stopped_ApplicationExit = 0x20026
   Trap (ARM state): SVC #1193046
   The OP2 compiler generates a prologue (PUSH {FP,LR}; MOV FP,SP) for all
   procedures including CODE blocks. Parameters are on the stack frame:
     [FP+8] = first parameter, [FP+12] = second parameter, etc.
   For open-array parameters the compiler copies the array to the local
   stack and replaces the pointer at [FP+8] with the local copy address.
   (c) 2025 me@rochus-keller.ch
*)

MODULE RawOut;

  IMPORT SYSTEM;

  (* Write a single character via SYS_WRITEC.
     SYS_WRITEC requires R1 to point to the character byte in memory.
     The parameter ch is at [FP+8] on the stack frame (compiler pushes it
     before the call and generates PUSH {FP,LR}; MOV FP,SP prologue).
     We can point R1 directly at [FP+8] since the byte is already in memory. *)
  PROCEDURE Char*(ch: CHAR);
  CODE {SYSTEM.arm}
    ADD  R1, R11, #8      (* R1 = address of ch on stack frame [FP+8] *)
    MOV  R0, #3           (* SYS_WRITEC *)
    SVC  #1193046         (* semihosting trap, ARM state, 0x123456 *)
  END Char;
  
  (* Write a null-terminated string via SYS_WRITE0.
     Open-array parameter: the compiler copies the array to the local stack
     and replaces [FP+8] with the address of the local copy.
     SYS_WRITE0 expects R1 = address of null-terminated string. *)
  PROCEDURE String*(str: ARRAY OF CHAR);
  CODE {SYSTEM.arm}
    LDR  R1, [R11, #8]    (* R1 = string address from stack frame [FP+8] *)
    MOV  R0, #4           (* SYS_WRITE0 *)
    SVC  #1193046         (* semihosting trap *)
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
      buf[j] := CHR(i MOD 10 + 48); (* 48 is ASCII '0' *)
      i := i DIV 10;
      INC(j)
    END;

    IF isNeg THEN
      buf[j] := "-"; INC(j)
    END;

    (* Print digits in reverse order *)
    k := j - 1;
    WHILE k >= 0 DO
      Char(buf[k]);
      DEC(k)
    END
  END Int;

  (* Ln has no parameters, so the CODE block is self-contained.
     R0/R1 are scratch and not holding any parameter. *)
  PROCEDURE Ln*;
  CODE {SYSTEM.arm}
    MOV  R0, #0AH         (* ASCII LF = 10 *)
    STRB R0, [SP, #-4]!   (* push newline byte onto stack; SP -= 4 *)
    MOV  R1, SP           (* R1 = address of newline byte *)
    MOV  R0, #3           (* SYS_WRITEC *)
    SVC  #1193046         (* semihosting trap *)
    ADD  SP, SP, #4       (* restore SP *)
  END Ln;

  (* Exit via SYS_EXIT_EXTENDED (0x20), which is the only way to pass an
     actual numeric exit code from a 32-bit semihosting caller.
     Builds a two-word block {ADP_Stopped_ApplicationExit, exit_code} on
     the stack and passes its address in R1.
     0x20026 = ADP_Stopped_ApplicationExit, assembled as two ORR-able immediates. *)
  (* Exit parameter res is at [FP+8] on the stack frame. *)
  PROCEDURE Exit*(res: LONGINT);
  CODE {SYSTEM.arm}
    LDR  R0, [R11, #8]    (* load res (exit_code) from stack frame *)
    STR  R0, [SP, #-4]!   (* push exit_code; SP -= 4, [SP] = exit_code *)
    MOV  R1, #020000H     (* build ADP_Stopped_ApplicationExit ... *)
    ORR  R1, R1, #026H    (* ... R1 = 0x20026 *)
    STR  R1, [SP, #-4]!   (* push reason; SP -= 4, [SP] = reason *)
    MOV  R1, SP           (* R1 = address of {reason, exit_code} block *)
    MOV  R0, #020H        (* Sys exit extended *)
    SVC  #1193046         (* semihosting trap *)
    ADD  SP, SP, #8       (* restore stack (not normally reached) *)
  loop:
    B    loop             (* loop in case of spurious wakeup / NMI *)
  END Exit;

BEGIN
  String("Hello from Oberon raw out!"); Ln
END RawOut.

