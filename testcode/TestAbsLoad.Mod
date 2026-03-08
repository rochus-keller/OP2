MODULE TestAbsLoad;
(* Test: Absolute load with sign/zero extension (Bug 2 fix).
   Verifies that loading global INTEGER (16-bit) and SHORTINT (8-bit)
   variables via absolute addressing correctly dereferences memory
   before sign/zero-extending. *)
IMPORT O := RawOut;

VAR
 pass, fail: LONGINT;
 gInt: INTEGER;      (* 16-bit signed, global *)
 gSInt: SHORTINT;    (* 8-bit signed, global *)
 gBool: BOOLEAN;     (* 8-bit, global *)

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

 PROCEDURE TestGlobalInt;
  VAR x: LONGINT;
 BEGIN
  O.String("--- Global INTEGER load ---"); O.Ln;
  gInt := 4;
  x := gInt;
  Check("gInt=4", x, 4);
  gInt := 100;
  x := gInt;
  Check("gInt=100", x, 100);
  gInt := -1;
  x := gInt;
  Check("gInt=-1", x, -1);
  gInt := -500;
  x := gInt;
  Check("gInt=-500", x, -500);
  gInt := 32767;
  x := gInt;
  Check("gInt=32767", x, 32767);
  gInt := -32768;
  x := gInt;
  Check("gInt=-32768", x, -32768)
 END TestGlobalInt;

 PROCEDURE TestGlobalSInt;
  VAR x: LONGINT;
 BEGIN
  O.String("--- Global SHORTINT load ---"); O.Ln;
  gSInt := 4;
  x := gSInt;
  Check("gSInt=4", x, 4);
  gSInt := 127;
  x := gSInt;
  Check("gSInt=127", x, 127);
  gSInt := -1;
  x := gSInt;
  Check("gSInt=-1", x, -1);
  gSInt := -128;
  x := gSInt;
  Check("gSInt=-128", x, -128)
 END TestGlobalSInt;

 PROCEDURE TestGlobalBool;
  VAR x: LONGINT;
 BEGIN
  O.String("--- Global BOOLEAN load ---"); O.Ln;
  gBool := TRUE;
  IF gBool THEN x := 1 ELSE x := 0 END;
  Check("gBool=TRUE", x, 1);
  gBool := FALSE;
  IF gBool THEN x := 1 ELSE x := 0 END;
  Check("gBool=FALSE", x, 0)
 END TestGlobalBool;

 PROCEDURE TestIntInExpr;
  VAR base, offset: LONGINT;
 BEGIN
  O.String("--- INTEGER in expressions ---"); O.Ln;
  gInt := 4;
  base := 1000;
  offset := base + gInt;
  Check("1000+gInt(4)", offset, 1004);
  gInt := -10;
  offset := base + gInt;
  Check("1000+gInt(-10)", offset, 990)
 END TestIntInExpr;

 PROCEDURE TestSIntInExpr;
  VAR base, offset: LONGINT;
 BEGIN
  O.String("--- SHORTINT in expressions ---"); O.Ln;
  gSInt := 8;
  base := 500;
  offset := base + gSInt;
  Check("500+gSInt(8)", offset, 508);
  gSInt := -5;
  offset := base + gSInt;
  Check("500+gSInt(-5)", offset, 495)
 END TestSIntInExpr;

BEGIN
 pass := 0; fail := 0;
 O.String("=== TestAbsLoad: absolute load sign/zero ext ==="); O.Ln;
 TestGlobalInt;
 TestGlobalSInt;
 TestGlobalBool;
 TestIntInExpr;
 TestSIntInExpr;
 O.Ln;
 O.String("TestAbsLoad: "); O.Int(pass, 0);
 O.String(" passed, "); O.Int(fail, 0);
 O.String(" failed"); O.Ln;
 O.Exit(fail)
END TestAbsLoad.
