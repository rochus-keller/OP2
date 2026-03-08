MODULE TestVFPLarge;
(* Test 5: VLDR/VSTR with large offset (>1024 bytes).
   VFP load/store uses 8-bit word-aligned offset, so the limit is 1024 bytes.
   A record with 256 LONGINTs (1024 bytes) of padding followed by a REAL
   field at offset 1024 triggers the fix. *)
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

 PROCEDURE CheckReal(name: ARRAY OF CHAR; got, expected: REAL);
 BEGIN
  O.String(name);
  IF got = expected THEN
   O.String(" OK"); INC(pass)
  ELSE
   O.String(" FAIL");
   INC(fail)
  END;
  O.Ln
 END CheckReal;

 PROCEDURE TestFloatAt1024;
  TYPE Rec1K = RECORD
   pad: ARRAY 256 OF LONGINT;   (* 1024 bytes *)
   f: REAL                       (* at offset 1024 -- exceeds VFP 8-bit limit *)
  END;
  VAR r: Rec1K;
 BEGIN
  O.String("--- REAL at offset 1024 ---"); O.Ln;
  r.pad[0] := 1;
  r.pad[255] := 255;
  r.f := 3.14;
  Check("pad[0]", r.pad[0], 1);
  Check("pad[255]", r.pad[255], 255);
  CheckReal("f@1024", r.f, 3.14)
 END TestFloatAt1024;

 PROCEDURE TestFloatAt2048;
  TYPE Rec2K = RECORD
   pad: ARRAY 512 OF LONGINT;   (* 2048 bytes *)
   f: REAL                        (* at offset 2048 *)
  END;
  VAR r: Rec2K;
 BEGIN
  O.String("--- REAL at offset 2048 ---"); O.Ln;
  r.pad[0] := 10;
  r.pad[511] := 511;
  r.f := 5.0;
  Check("pad[0]", r.pad[0], 10);
  Check("pad[511]", r.pad[511], 511);
  (* Verify the float can be read back and used in arithmetic *)
  CheckReal("f@2048", r.f, 5.0);
  r.f := r.f + 2.0;
  CheckReal("f+2", r.f, 7.0)
 END TestFloatAt2048;

 PROCEDURE TestFloatCompute;
  (* Compute with floats stored past VFP offset limit *)
  TYPE BigFloat = RECORD
   pad: ARRAY 512 OF LONGINT;   (* 2048 bytes *)
   a: REAL;
   b: REAL;
   c: REAL
  END;
  VAR r: BigFloat;
 BEGIN
  O.String("--- Float compute past 1024 ---"); O.Ln;
  r.a := 10.0;
  r.b := 3.0;
  r.c := r.a + r.b;
  CheckReal("a+b", r.c, 13.0);
  r.c := r.a * r.b;
  CheckReal("a*b", r.c, 30.0);
  r.c := r.a - r.b;
  CheckReal("a-b", r.c, 7.0)
 END TestFloatCompute;

BEGIN
 pass := 0; fail := 0;
 O.String("=== TestVFPLarge: VLDR/VSTR large offset ==="); O.Ln;
 TestFloatAt1024;
 TestFloatAt2048;
 TestFloatCompute;
 O.Ln;
 O.String("TestVFPLarge: "); O.Int(pass, 0);
 O.String(" passed, "); O.Int(fail, 0);
 O.String(" failed"); O.Ln;
 O.Exit(fail)
END TestVFPLarge.
