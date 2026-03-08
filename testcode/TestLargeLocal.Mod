MODULE TestLargeLocal;
(* Test 1: LDR/STR with large offset (>4096 bytes).
   A record with a 1024-element LONGINT array (4096 bytes) followed by a flag
   field at offset 4096 -- exactly the limit for ARM LDR/STR 12-bit immediate. *)
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

 PROCEDURE TestBigRecord;
  TYPE BigRec = RECORD
   data: ARRAY 1024 OF LONGINT;  (* 4096 bytes *)
   flag: LONGINT                  (* at offset 4096 -- exceeds 12-bit limit *)
  END;
  VAR r: BigRec;
 BEGIN
  O.String("--- BigRecord (offset 4096) ---"); O.Ln;
  r.data[0] := 11111;
  r.data[512] := 22222;
  r.data[1023] := 33333;
  r.flag := 99999;
  Check("data[0]", r.data[0], 11111);
  Check("data[512]", r.data[512], 22222);
  Check("data[1023]", r.data[1023], 33333);
  Check("flag@4096", r.flag, 99999)
 END TestBigRecord;

 PROCEDURE TestEvenLarger;
  TYPE HugeRec = RECORD
   pad: ARRAY 2048 OF LONGINT;   (* 8192 bytes *)
   val: LONGINT                   (* at offset 8192 *)
  END;
  VAR h: HugeRec;
 BEGIN
  O.String("--- HugeRecord (offset 8192) ---"); O.Ln;
  h.pad[0] := 100;
  h.pad[2047] := 200;
  h.val := 54321;
  Check("pad[0]", h.pad[0], 100);
  Check("pad[2047]", h.pad[2047], 200);
  Check("val@8192", h.val, 54321)
 END TestEvenLarger;

BEGIN
 pass := 0; fail := 0;
 O.String("=== TestLargeLocal: LDR/STR large offset ==="); O.Ln;
 TestBigRecord;
 TestEvenLarger;
 O.Ln;
 O.String("TestLargeLocal: "); O.Int(pass, 0);
 O.String(" passed, "); O.Int(fail, 0);
 O.String(" failed"); O.Ln;
 O.Exit(fail)
END TestLargeLocal.
