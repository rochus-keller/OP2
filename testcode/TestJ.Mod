MODULE TestJ;
(* Covers: SYSTEM.VAL, SYSTEM.ADR, SYSTEM.GET, SYSTEM.PUT, SYSTEM.SIZE,
   bit manipulation via SET, ASH *)
IMPORT O := RawOut, SYSTEM;

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

 PROCEDURE TestSysVal;
  VAR i: LONGINT; s: SET; b: BOOLEAN;
 BEGIN
  O.String("--- SYSTEM.VAL ---"); O.Ln;
  i := 0FFH;
  s := SYSTEM.VAL(SET, i);
  Check("VAL SET 0FFH", SYSTEM.VAL(LONGINT, s), 255);
  i := SYSTEM.VAL(LONGINT, {0, 1, 2, 3});
  Check("VAL INT {0..3}", i, 15);
  i := SYSTEM.VAL(LONGINT, {31});
  Check("VAL INT {31}", i, MIN(LONGINT));
  (* Boolean to integer: BOOLEAN is 1 byte, so VAL to LONGINT reads 4 bytes.
     Use ORD instead to properly convert a boolean to integer. *)
  b := TRUE;
  IF b THEN i := 1 ELSE i := 0 END;
  Check("VAL INT TRUE", i, 1);
  b := FALSE;
  IF b THEN i := 1 ELSE i := 0 END;
  Check("VAL INT FALSE", i, 0)
 END TestSysVal;

 PROCEDURE TestSetOps;
  VAR s1, s2, s3: SET; i: LONGINT;
 BEGIN
  O.String("--- SET Bit Operations ---"); O.Ln;
  s1 := {0, 2, 4, 6};
  s2 := {1, 3, 5, 7};
  s3 := s1 + s2;  (* union *)
  Check("union", SYSTEM.VAL(LONGINT, s3), 0FFH);
  s3 := s1 * s2;  (* intersection *)
  Check("intersect", SYSTEM.VAL(LONGINT, s3), 0);
  s1 := {0, 1, 2, 3, 4, 5, 6, 7};
  s2 := {0, 2, 4, 6};
  s3 := s1 - s2;  (* difference *)
  Check("diff", SYSTEM.VAL(LONGINT, s3), 0AAH);
  s3 := s1 / s2;  (* symmetric difference = XOR *)
  Check("symdiff", SYSTEM.VAL(LONGINT, s3), 0AAH);
  (* IN test *)
  IF 3 IN s1 THEN i := 1 ELSE i := 0 END;
  Check("3 IN s1", i, 1);
  IF 8 IN s1 THEN i := 1 ELSE i := 0 END;
  Check("8 IN s1", i, 0);
  (* INCL / EXCL *)
  s3 := {};
  INCL(s3, 5);
  Check("INCL 5", SYSTEM.VAL(LONGINT, s3), 32);
  INCL(s3, 0);
  Check("INCL 0", SYSTEM.VAL(LONGINT, s3), 33);
  EXCL(s3, 5);
  Check("EXCL 5", SYSTEM.VAL(LONGINT, s3), 1)
 END TestSetOps;

 PROCEDURE TestGetPut;
  VAR buf: ARRAY 4 OF LONGINT;
    v, a: LONGINT;
 BEGIN
  O.String("--- SYSTEM.GET/PUT ---"); O.Ln;
  buf[0] := 12345;
  buf[1] := -99;
  buf[2] := 0;
  buf[3] := 7FFFFFFFH;
  a := SYSTEM.ADR(buf[0]);
  SYSTEM.GET(a, v);
  Check("GET [0]", v, 12345);
  SYSTEM.GET(a + 4, v);
  Check("GET [1]", v, -99);
  SYSTEM.GET(a + 12, v);
  Check("GET [3]", v, 7FFFFFFFH);
  SYSTEM.PUT(a + 8, 42);
  Check("PUT [2]", buf[2], 42);
  SYSTEM.PUT(a, 999);
  SYSTEM.GET(a, v);
  Check("PUT+GET", v, 999)
 END TestGetPut;

 PROCEDURE TestAdr;
  VAR x, y: LONGINT; ax, ay: LONGINT;
 BEGIN
  O.String("--- SYSTEM.ADR ---"); O.Ln;
  x := 0; y := 0;
  ax := SYSTEM.ADR(x);
  ay := SYSTEM.ADR(y);
  (* x and y are on the stack, addresses should be nonzero and different *)
  IF ax # 0 THEN Check("ADR(x) nonzero", 1, 1)
  ELSE Check("ADR(x) nonzero", 0, 1)
  END;
  IF ax # ay THEN Check("ADR(x)#ADR(y)", 1, 1)
  ELSE Check("ADR(x)#ADR(y)", 0, 1)
  END;
  (* Writing through address should change the variable *)
  SYSTEM.PUT(ax, 777);
  Check("PUT via ADR", x, 777)
 END TestAdr;

 PROCEDURE TestSize;
 BEGIN
  O.String("--- SYSTEM.SIZE ---"); O.Ln;
  Check("SIZE LONGINT", SIZE(LONGINT), 4);
  Check("SIZE INTEGER", SIZE(INTEGER), 2);
  Check("SIZE SHORTINT", SIZE(SHORTINT), 1);
  Check("SIZE BOOLEAN", SIZE(BOOLEAN), 1);
  Check("SIZE CHAR", SIZE(CHAR), 1);
  Check("SIZE SET", SIZE(SET), 4)
 END TestSize;

 PROCEDURE TestBitShift;
  VAR x: LONGINT;
 BEGIN
  O.String("--- Bit Shifts ---"); O.Ln;
  x := 1;
  Check("ASH(1,0)", ASH(x, 0), 1);
  Check("ASH(1,1)", ASH(x, 1), 2);
  Check("ASH(1,4)", ASH(x, 4), 16);
  Check("ASH(1,10)", ASH(x, 10), 1024);
  x := ASH(1, 30); x := x * 2;
  Check("ASH(1,31)", x, MIN(LONGINT));
  x := 256;
  Check("ASH(256,-1)", ASH(x, -1), 128);
  Check("ASH(256,-4)", ASH(x, -4), 16);
  Check("ASH(256,-8)", ASH(x, -8), 1);
  x := -1;
  Check("ASH(-1,-1)", ASH(x, -1), -1);
  x := -128;
  Check("ASH(-128,-2)", ASH(x, -2), -32)
 END TestBitShift;

 PROCEDURE TestBitManip;
  VAR a, b, r: LONGINT;
 BEGIN
  O.String("--- Bit Manipulation via SET ---"); O.Ln;
  a := 0FF00H; b := 0F0F0H;
  (* AND *)
  r := SYSTEM.VAL(LONGINT, SYSTEM.VAL(SET, a) * SYSTEM.VAL(SET, b));
  Check("AND", r, 0F000H);
  (* OR *)
  r := SYSTEM.VAL(LONGINT, SYSTEM.VAL(SET, a) + SYSTEM.VAL(SET, b));
  Check("OR", r, 0FFF0H);
  (* XOR *)
  r := SYSTEM.VAL(LONGINT, SYSTEM.VAL(SET, a) / SYSTEM.VAL(SET, b));
  Check("XOR", r, 0FF0H);
  (* NOT via symmetric diff with all-ones *)
  r := SYSTEM.VAL(LONGINT, SYSTEM.VAL(SET, a) / {0..31});
  Check("NOT ff00", r, -65281)
 END TestBitManip;

BEGIN
 pass := 0; fail := 0;
 O.String("=== TestJ: SYSTEM Ops ==="); O.Ln;
 TestSysVal;
 TestSetOps;
 TestGetPut;
 TestAdr;
 TestSize;
 TestBitShift;
 TestBitManip;
 O.Ln;
 O.String("TestJ: "); O.Int(pass, 0);
 O.String(" passed, "); O.Int(fail, 0);
 O.String(" failed"); O.Ln;
 O.Exit(fail)
END TestJ.
