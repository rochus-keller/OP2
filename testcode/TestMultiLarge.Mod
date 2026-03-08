MODULE TestMultiLarge;
(* Test 2: Multiple large local records with cumulative offset > 4096.
   Two Page records (4096 bytes each) + extra LONGINT, testing that the
   compiler correctly materializes large offsets for each variable. *)
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

 PROCEDURE TestTwoPages;
  TYPE Page = RECORD
   data: ARRAY 1024 OF LONGINT  (* 4096 bytes *)
  END;
  VAR p1, p2: Page; x: LONGINT;
 BEGIN
  O.String("--- Two Pages + extra var ---"); O.Ln;
  p1.data[0] := 1000;
  p1.data[511] := 2000;
  p1.data[1023] := 3000;
  p2.data[0] := 4000;
  p2.data[511] := 5000;
  p2.data[1023] := 6000;
  x := 7777;
  Check("p1[0]", p1.data[0], 1000);
  Check("p1[511]", p1.data[511], 2000);
  Check("p1[1023]", p1.data[1023], 3000);
  Check("p2[0]", p2.data[0], 4000);
  Check("p2[511]", p2.data[511], 5000);
  Check("p2[1023]", p2.data[1023], 6000);
  Check("x", x, 7777)
 END TestTwoPages;

 PROCEDURE TestCrossAccess;
  (* Copy values between two large records *)
  TYPE Page = RECORD
   data: ARRAY 1024 OF LONGINT
  END;
  VAR src, dst: Page; i: LONGINT;
 BEGIN
  O.String("--- Cross-copy large records ---"); O.Ln;
  src.data[0] := 100;
  src.data[500] := 200;
  src.data[1023] := 300;
  dst.data[0] := src.data[0] + 1;
  dst.data[500] := src.data[500] + 1;
  dst.data[1023] := src.data[1023] + 1;
  Check("dst[0]", dst.data[0], 101);
  Check("dst[500]", dst.data[500], 201);
  Check("dst[1023]", dst.data[1023], 301)
 END TestCrossAccess;

BEGIN
 pass := 0; fail := 0;
 O.String("=== TestMultiLarge: Multiple large locals ==="); O.Ln;
 TestTwoPages;
 TestCrossAccess;
 O.Ln;
 O.String("TestMultiLarge: "); O.Int(pass, 0);
 O.String(" passed, "); O.Int(fail, 0);
 O.String(" failed"); O.Ln;
 O.Exit(fail)
END TestMultiLarge.
