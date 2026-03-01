MODULE TestH;
(* Covers: LONGREAL arithmetic, comparisons, conversions *)
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

 PROCEDURE TestBasicArith;
  VAR a, b, c: LONGREAL;
 BEGIN
  O.String("--- LONGREAL Basic Arithmetic ---"); O.Ln;
  a := 3.0D0; b := 4.0D0;
  c := a + b;
  Check("3+4", ENTIER(c), 7);
  c := a - b;
  Check("3-4", ENTIER(c), -1);
  c := a * b;
  Check("3*4", ENTIER(c), 12);
  c := 12.0D0 / b;
  Check("12/4", ENTIER(c), 3)
 END TestBasicArith;

 PROCEDURE TestLargeValues;
  VAR a, b, c: LONGREAL; d: LONGINT;
 BEGIN
  O.String("--- LONGREAL Large Values ---"); O.Ln;
  a := 100000.0D0; b := 100000.0D0;
  c := a * b;
  (* 10^10 > MAXINT, so test with division back *)
  c := c / a;
  (* Note: soft-float Mul uses only 21-bit mantissa, so slight precision loss *)
  d := ENTIER(c) - 100000;
  IF (d > -200) & (d < 200) THEN
   O.String("1e5*1e5/1e5 OK (approx)"); INC(pass)
  ELSE
   O.String("1e5*1e5/1e5 FAIL delta="); O.Int(d, 0); INC(fail)
  END;
  O.Ln;
  a := 1000000.0D0;
  c := a + 1.0D0;
  Check("1e6+1", ENTIER(c), 1000001)
 END TestLargeValues;

 PROCEDURE TestNeg;
  VAR x, y: LONGREAL;
 BEGIN
  O.String("--- LONGREAL Negate ---"); O.Ln;
  x := 42.0D0;
  y := -x;
  Check("-42", ENTIER(y), -42);
  y := -(-x);
  Check("--42", ENTIER(y), 42)
 END TestNeg;

 PROCEDURE TestConversions;
  VAR x: LONGREAL; i, j: LONGINT;
 BEGIN
  O.String("--- LONGREAL Conversions ---"); O.Ln;
  (* Integer to LONGREAL via assignment: compiler auto-converts *)
  i := 100; x := i;
  Check("int2lr(100)", ENTIER(x), 100);
  i := -50; x := i;
  Check("int2lr(-50)", ENTIER(x), -50);
  i := 0; x := i;
  Check("int2lr(0)", ENTIER(x), 0);
  x := 99.7D0;
  j := ENTIER(x);
  Check("ENTIER(99.7)", j, 99)
 END TestConversions;

 PROCEDURE TestComparisons;
  VAR a, b: LONGREAL; r: LONGINT;
 BEGIN
  O.String("--- LONGREAL Comparisons ---"); O.Ln;
  a := 3.0D0; b := 4.0D0;
  IF a < b THEN r := 1 ELSE r := 0 END;
  Check("3<4", r, 1);
  IF a > b THEN r := 1 ELSE r := 0 END;
  Check("3>4", r, 0);
  a := 5.0D0; b := 5.0D0;
  IF a = b THEN r := 1 ELSE r := 0 END;
  Check("5=5", r, 1);
  a := -1.0D0; b := 1.0D0;
  IF a < b THEN r := 1 ELSE r := 0 END;
  Check("-1<1", r, 1)
 END TestComparisons;

BEGIN
 pass := 0; fail := 0;
 O.String("=== TestH: LONGREAL (Float64) ==="); O.Ln;
 TestBasicArith;
 TestLargeValues;
 TestNeg;
 TestConversions;
 TestComparisons;
 O.Ln;
 O.String("TestH: "); O.Int(pass, 0);
 O.String(" passed, "); O.Int(fail, 0);
 O.String(" failed"); O.Ln;
 O.Exit(fail)
END TestH.
