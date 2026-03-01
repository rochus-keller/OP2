MODULE TestG;
(* Covers: REAL arithmetic, comparisons, conversions, mixed expressions *)
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
  VAR a, b, c: REAL;
 BEGIN
  O.String("--- REAL Basic Arithmetic ---"); O.Ln;
  a := 3.0; b := 4.0;
  c := a + b;
  Check("3.0+4.0", ENTIER(c), 7);
  c := a - b;
  Check("3.0-4.0", ENTIER(c), -1);
  c := a * b;
  Check("3.0*4.0", ENTIER(c), 12);
  c := 12.0 / b;
  Check("12.0/4.0", ENTIER(c), 3);
  a := 100.0; b := 3.0;
  c := a / b;
  Check("100.0/3.0", ENTIER(c), 33)
 END TestBasicArith;

 PROCEDURE TestNegation;
  VAR x, y: REAL;
 BEGIN
  O.String("--- REAL Negation ---"); O.Ln;
  x := 5.0;
  y := -x;
  Check("-5.0", ENTIER(y), -5);
  y := -(-x);
  Check("--5.0", ENTIER(y), 5);
  x := -7.5;
  Check("-7.5 trunc", ENTIER(x), -7)
 END TestNegation;

 PROCEDURE TestComparisons;
  VAR a, b: REAL; r: LONGINT;
 BEGIN
  O.String("--- REAL Comparisons ---"); O.Ln;
  a := 3.0; b := 4.0;
  IF a < b THEN r := 1 ELSE r := 0 END;
  Check("3<4", r, 1);
  IF a > b THEN r := 1 ELSE r := 0 END;
  Check("3>4", r, 0);
  IF a = b THEN r := 1 ELSE r := 0 END;
  Check("3=4", r, 0);
  a := 5.0; b := 5.0;
  IF a = b THEN r := 1 ELSE r := 0 END;
  Check("5=5", r, 1);
  IF a <= b THEN r := 1 ELSE r := 0 END;
  Check("5<=5", r, 1);
  IF a >= b THEN r := 1 ELSE r := 0 END;
  Check("5>=5", r, 1);
  a := -1.0; b := 1.0;
  IF a < b THEN r := 1 ELSE r := 0 END;
  Check("-1<1", r, 1)
 END TestComparisons;

 PROCEDURE TestConversions;
  VAR x: REAL; i, j: LONGINT;
 BEGIN
  O.String("--- REAL Conversions ---"); O.Ln;
  (* Integer to REAL via assignment: compiler auto-converts *)
  i := 42; x := i;
  Check("int2real(42)", ENTIER(x), 42);
  i := -10; x := i;
  Check("int2real(-10)", ENTIER(x), -10);
  i := 0; x := i;
  Check("int2real(0)", ENTIER(x), 0);
  x := 99.9;
  j := ENTIER(x);
  Check("ENTIER(99.9)", j, 99);
  x := -3.7;
  j := ENTIER(x);
  Check("ENTIER(-3.7)", j, -3)
 END TestConversions;

 PROCEDURE TestGlobalVar;
  VAR g: REAL;
 BEGIN
  O.String("--- REAL Global/Local ---"); O.Ln;
  g := 2.5;
  g := g * 4.0;
  Check("2.5*4", ENTIER(g), 10);
  g := 1.0;
  g := g + g + g + g + g;
  Check("1+1+1+1+1", ENTIER(g), 5)
 END TestGlobalVar;

 PROCEDURE TestExpressions;
  VAR a, b, c: REAL;
 BEGIN
  O.String("--- REAL Expressions ---"); O.Ln;
  a := 2.0; b := 3.0; c := 4.0;
  Check("a*b+c", ENTIER(a*b+c), 10);
  Check("a*(b+c)", ENTIER(a*(b+c)), 14);
  Check("(a+b)*(a+c)", ENTIER((a+b)*(a+c)), 30)
 END TestExpressions;

 PROCEDURE TestAbs;
  VAR x: REAL;
 BEGIN
  O.String("--- REAL ABS ---"); O.Ln;
  x := -5.0;
  Check("ABS(-5.0)", ENTIER(ABS(x)), 5);
  x := 7.0;
  Check("ABS(7.0)", ENTIER(ABS(x)), 7);
  x := 0.0;
  Check("ABS(0.0)", ENTIER(ABS(x)), 0)
 END TestAbs;

BEGIN
 pass := 0; fail := 0;
 O.String("=== TestG: REAL (FPU) ==="); O.Ln;
 TestBasicArith;
 TestNegation;
 TestComparisons;
 TestConversions;
 TestGlobalVar;
 TestExpressions;
 TestAbs;
 O.Ln;
 O.String("TestG: "); O.Int(pass, 0);
 O.String(" passed, "); O.Int(fail, 0);
 O.String(" failed"); O.Ln;
 O.Exit(fail)
END TestG.
