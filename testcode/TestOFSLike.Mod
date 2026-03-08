MODULE TestOFSLike;
(* Test 6: OFSAosFiles-like regression test (scaled to fit the default 8KB stack).

   The original OFSAosFiles issue is a very large local stack frame, which forces
   stack-relative LDR/STR with offsets > 4096.

   Note: the current multibootlinker reserves STACK_SIZE=8192 bytes, so this test
   keeps each procedure's local frame below 8KB while still forcing >4096 offsets.
*)
IMPORT O := RawOut;

VAR pass, fail: LONGINT;

 PROCEDURE Check(name: ARRAY OF CHAR; got, expected: LONGINT);
 BEGIN
  O.String(name);
  IF got = expected THEN
   O.String(" OK"); INC(pass)
  ELSE
   O.String(" FAIL got="); O.Int(got, 0);
   O.String(" expected="); O.Int(expected, 0);
   INC(fail)
  END;
  O.Ln
 END Check;

 PROCEDURE TestOFSLocals;
  TYPE
   DirPage = RECORD
    data: ARRAY 1024 OF LONGINT   (* 4096 bytes *)
   END;
  VAR
   dp: DirPage;
   diskAdr: ARRAY 900 OF LONGINT;  (* 3600 bytes; starts at offset 4096 *)
   result: LONGINT;
 BEGIN
  O.String("--- OFS-like locals (offsets >4096, frame <8KB) ---"); O.Ln;

  dp.data[0] := 1;
  dp.data[512] := 2;
  dp.data[1023] := 3;

  diskAdr[0] := 1000;
  diskAdr[450] := 2000;
  diskAdr[899] := 3000;

  Check("dp[0]", dp.data[0], 1);
  Check("dp[512]", dp.data[512], 2);
  Check("dp[1023]", dp.data[1023], 3);
  Check("disk[0]", diskAdr[0], 1000);
  Check("disk[450]", diskAdr[450], 2000);
  Check("disk[899]", diskAdr[899], 3000);

  (* Cross-structure computation *)
  result := dp.data[0] + diskAdr[0];
  Check("cross-sum", result, 1001)
 END TestOFSLocals;

 PROCEDURE TestOFSLoop;
  (* Loop with scalar locals placed after a 4KB record, so i/sum sit at offsets >= 4096. *)
  TYPE Sector = RECORD
   data: ARRAY 1024 OF LONGINT
  END;
  VAR s: Sector; i, sum: LONGINT;
 BEGIN
  O.String("--- OFS loop (i/sum at offsets >=4096) ---"); O.Ln;
  i := 0;
  WHILE i < 1024 DO
   s.data[i] := 1024 - i;
   INC(i)
  END;
  sum := 0;
  i := 0;
  WHILE i < 1024 DO
   sum := sum + s.data[i];
   INC(i)
  END;
  (* Sum of 1..1024 = 1024*1025/2 = 524800 *)
  Check("loop-sum", sum, 524800)
 END TestOFSLoop;

BEGIN
 pass := 0; fail := 0;
 O.String("=== TestOFSLike: large frame regression ==="); O.Ln;
 TestOFSLocals;
 TestOFSLoop;
 O.Ln;
 O.String("TestOFSLike: "); O.Int(pass, 0);
 O.String(" passed, "); O.Int(fail, 0);
 O.String(" failed"); O.Ln;
 O.Exit(fail)
END TestOFSLike.
