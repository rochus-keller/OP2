(* 
   This is a low-level Out module for the i386 PC platform (or QEMU) using
   Host Console Output (Port 0xE9) and 
   QEMU exit with a status code (Port 0xF4) 
   (c) 2026 me@rochus-keller.ch
*)
   
MODULE RawOut;

  IMPORT SYSTEM;

  PROCEDURE Char*(ch: CHAR);
  CODE {SYSTEM.i386}
    MOV AL, ch[EBP]    (* Load the character parameter from the stack into AL *)
    OUT 0E9H, AL       (* Write AL to QEMU's debug console port 0xE9 *)
  END Char;

  PROCEDURE String*(str: ARRAY OF CHAR);
  VAR i: LONGINT; ch: CHAR;
  BEGIN
    i := 0;
    ch := str[i];
    WHILE ch # 0X DO
      Char(ch);
      INC(i);
      ch := str[i]
    END
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

    (* Print backwards *)
    k := j - 1;
    WHILE k >= 0 DO
      Char(buf[k]);
      DEC(k)
    END
  END Int;

  PROCEDURE Ln*;
  CODE {SYSTEM.i386}
    MOV AL, 0AH        (* ASCII 10 (Newline) *)
    OUT 0E9H, AL       (* Write to Port 0xE9 *)
  END Ln;

  PROCEDURE Exit*(res: LONGINT);
  CODE {SYSTEM.i386}
    MOV EAX, res[EBP]  (* Load the exit code parameter into EAX *)
    
    (* QEMU isa-debug-exit expects the exit code to be shifted.
       If we write 'res' to port 0xF4, QEMU exits with status: (res << 1) | 1 *)
    OUT 0F4H, AL       (* Write the lowest byte of the exit code to Port 0xF4 *)
    
    (* If we are here, port 0xF4 wasn't caught by QEMU (maybe running on real hardware). 
       We halt the CPU. *)
  loop:
    CLI                (* Disable interrupts *)
    DB 0F4H            (* HLT, Halt the CPU *)
    JMP loop           (* Infinite loop just in case an NMI wakes us up *)
  END Exit;

BEGIN
  String("Hello from Oberon raw out!"); Ln
END RawOut.

