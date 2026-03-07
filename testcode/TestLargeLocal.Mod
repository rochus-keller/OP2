MODULE TestLargeLocal;
(* Test 1: LDR/STR with large offset (>4096 bytes).
   A record with a 1024-element LONGINT array (4096 bytes) followed by a flag
   field at offset 4096 -- exactly the limit for ARM LDR/STR 12-bit immediate. *)
IMPORT RawOut;

VAR pass, fail: LONGINT;

 PROCEDURE Check(name: ARRAY OF CHAR; got, expected: LONGINT);
 BEGIN
  RawOut.String(name);
  IF got = expected THEN
   RawOut.String(" OK"); INC(pass)
  ELSE
   RawOut.String(" FAIL got="); RawOut.Int(got, 0);
   RawOut.String(" expected="); RawOut.Int(expected, 0);
   INC(fail)
  END;
  RawOut.Ln
 END Check;

 PROCEDURE TestBigRecord;
  TYPE BigRec = RECORD
   data: ARRAY 1024 OF LONGINT;  (* 4096 bytes *)
   flag: LONGINT                  (* at offset 4096 -- exceeds 12-bit limit *)
  END;
  VAR r: BigRec;
 BEGIN
  RawOut.String("--- BigRecord (offset 4096) ---"); RawOut.Ln;
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
  RawOut.String("--- HugeRecord (offset 8192) ---"); RawOut.Ln;
  h.pad[0] := 100;
  h.pad[2047] := 200;
  h.val := 54321;
  Check("pad[0]", h.pad[0], 100);
  Check("pad[2047]", h.pad[2047], 200);
  Check("val@8192", h.val, 54321)
 END TestEvenLarger;

BEGIN
 pass := 0; fail := 0;
 RawOut.String("=== TestLargeLocal: LDR/STR large offset ==="); RawOut.Ln;
 TestBigRecord;
 TestEvenLarger;
 RawOut.Ln;
 RawOut.String("TestLargeLocal: "); RawOut.Int(pass, 0);
 RawOut.String(" passed, "); RawOut.Int(fail, 0);
 RawOut.String(" failed"); RawOut.Ln;
 RawOut.Exit(fail)
END TestLargeLocal.
