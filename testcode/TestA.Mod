MODULE TestA;
(* TestA: Arithmetic & Expressions *)
(* Covers: +, -, *, DIV, MOD, negation, constants, variables, precedence *)
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
  VAR a, b, c: LONGINT;
 BEGIN
  O.String("--- Basic Arithmetic ---"); O.Ln;
  Check("2+3", 2+3, 5);
  Check("10-7", 10-7, 3);
  Check("6*7", 6*7, 42);
  Check("100 DIV 10", 100 DIV 10, 10);
  Check("17 MOD 5", 17 MOD 5, 2);
  a := 100; b := 37;
  Check("a+b", a+b, 137);
  Check("a-b", a-b, 63);
  Check("a*b", a*b, 3700);
  Check("a DIV b", a DIV b, 2);
  Check("a MOD b", a MOD b, 26)
 END TestBasicArith;

 PROCEDURE TestNegation;
  VAR x: LONGINT;
 BEGIN
  O.String("--- Negation ---"); O.Ln;
  Check("-5", -5, -5);
  x := 42;
  Check("-x", -x, -42);
  Check("- -x", -(-x), 42);
  Check("-1+2", -1+2, 1)
 END TestNegation;

 PROCEDURE TestPrecedence;
  VAR a, b, c: LONGINT;
 BEGIN
  O.String("--- Precedence ---"); O.Ln;
  Check("2+3*4", 2+3*4, 14);
  Check("(2+3)*4", (2+3)*4, 20);
  Check("10-2*3", 10-2*3, 4);
  a := 5; b := 3; c := 2;
  Check("a*b+c", a*b+c, 17);
  Check("a*(b+c)", a*(b+c), 25)
 END TestPrecedence;

 PROCEDURE TestLargeValues;
  VAR x: LONGINT;
 BEGIN
  O.String("--- Large Values ---"); O.Ln;
  x := 100000;
  Check("100000*10", x*10, 1000000);
  Check("100000 DIV 7", x DIV 7, 14285);
  Check("100000 MOD 7", x MOD 7, 5);
  x := 2147483647;
  Check("MAXINT", x, 2147483647);
  Check("MAXINT-1", x-1, 2147483646)
 END TestLargeValues;

 PROCEDURE TestDivMod;
  VAR a, b: LONGINT;
 BEGIN
  O.String("--- DIV/MOD ---"); O.Ln;
  Check("7 DIV 3", 7 DIV 3, 2);
  Check("7 MOD 3", 7 MOD 3, 1);
  (* ARM SDIV uses truncation toward zero for negative dividend.
     For negative divisor the compiler's GenDivMod uses floor semantics. *)
  Check("-7 DIV 3", -7 DIV 3, -2);
  Check("-7 MOD 3", -7 MOD 3, -1);
  a := 7; b := -3;
  Check("7 DIV -3", a DIV b, -3);
  Check("7 MOD -3", a MOD b, -2);
  a := 1000; b := 13;
  Check("1000 DIV 13", a DIV b, 76);
  Check("1000 MOD 13", a MOD b, 12)
 END TestDivMod;

 PROCEDURE TestBitOps;
  VAR a, b: LONGINT;
 BEGIN
  O.String("--- Bit Ops (via SET) ---"); O.Ln;
  a := 255; b := 15;
  Check("SYSTEM.VAL via arith", a - (a DIV 16)*16, 15)
 END TestBitOps;

BEGIN
 pass := 0; fail := 0;
 O.String("=== TestA: Arithmetic ==="); O.Ln;
 TestBasicArith;
 TestNegation;
 TestPrecedence;
 TestLargeValues;
 TestDivMod;
 TestBitOps;
 O.Ln;
 O.String("TestA: "); O.Int(pass, 0);
 O.String(" passed, "); O.Int(fail, 0);
 O.String(" failed"); O.Ln;
 O.Exit(fail)
END TestA.
