MODULE TestC;
(* TestC: Procedures & Functions *)
(* Covers: value params, VAR params, return values, local vars, nested procs, recursion *)
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

 PROCEDURE Add(a, b: LONGINT): LONGINT;
 BEGIN RETURN a + b
 END Add;

 PROCEDURE Max(a, b: LONGINT): LONGINT;
 BEGIN
  IF a > b THEN RETURN a ELSE RETURN b END
 END Max;

 PROCEDURE Swap(VAR a, b: LONGINT);
  VAR t: LONGINT;
 BEGIN t := a; a := b; b := t
 END Swap;

 PROCEDURE Fact(n: LONGINT): LONGINT;
 BEGIN
  IF n <= 1 THEN RETURN 1
  ELSE RETURN n * Fact(n - 1)
  END
 END Fact;

 PROCEDURE Fib(n: LONGINT): LONGINT;
 BEGIN
  IF n <= 0 THEN RETURN 0
  ELSIF n = 1 THEN RETURN 1
  ELSE RETURN Fib(n - 1) + Fib(n - 2)
  END
 END Fib;

 PROCEDURE SumTo(n: LONGINT): LONGINT;
 BEGIN
  IF n <= 0 THEN RETURN 0
  ELSE RETURN n + SumTo(n - 1)
  END
 END SumTo;

 PROCEDURE TestBasicProcs;
 BEGIN
  O.String("--- Basic Procedures ---"); O.Ln;
  Check("Add(3,4)", Add(3, 4), 7);
  Check("Add(-5,5)", Add(-5, 5), 0);
  Check("Max(5,3)", Max(5, 3), 5);
  Check("Max(3,5)", Max(3, 5), 5);
  Check("Max(-1,-2)", Max(-1, -2), -1)
 END TestBasicProcs;

 PROCEDURE TestVarParams;
  VAR a, b: LONGINT;
 BEGIN
  O.String("--- VAR Parameters ---"); O.Ln;
  a := 10; b := 20;
  Swap(a, b);
  Check("Swap a", a, 20);
  Check("Swap b", b, 10);
  a := -5; b := 5;
  Swap(a, b);
  Check("Swap neg a", a, 5);
  Check("Swap neg b", b, -5)
 END TestVarParams;

 PROCEDURE TestRecursion;
 BEGIN
  O.String("--- Recursion ---"); O.Ln;
  Check("Fact(1)", Fact(1), 1);
  Check("Fact(5)", Fact(5), 120);
  Check("Fact(10)", Fact(10), 3628800);
  Check("Fib(0)", Fib(0), 0);
  Check("Fib(1)", Fib(1), 1);
  Check("Fib(10)", Fib(10), 55);
  Check("SumTo(100)", SumTo(100), 5050)
 END TestRecursion;

 PROCEDURE TestNested;
  VAR x: LONGINT;

  PROCEDURE Inner(a: LONGINT): LONGINT;
  BEGIN RETURN a * 2
  END Inner;

  PROCEDURE InnerAdd(a, b: LONGINT): LONGINT;
  BEGIN RETURN a + b
  END InnerAdd;

 BEGIN
  O.String("--- Nested Procedures ---"); O.Ln;
  x := Inner(21);
  Check("Inner(21)", x, 42);
  Check("InnerAdd(10,20)", InnerAdd(10, 20), 30);
  Check("Inner+InnerAdd", Inner(5) + InnerAdd(3, 7), 20)
 END TestNested;

 PROCEDURE TestMultipleLocals;
  VAR a, b, c, d, e: LONGINT;
 BEGIN
  O.String("--- Multiple Locals ---"); O.Ln;
  a := 1; b := 2; c := 3; d := 4; e := 5;
  Check("sum 5 locals", a+b+c+d+e, 15);
  a := a * 10; b := b * 10; c := c * 10;
  Check("scaled sum", a+b+c, 60)
 END TestMultipleLocals;

BEGIN
 pass := 0; fail := 0;
 O.String("=== TestC: Procedures ==="); O.Ln;
 TestBasicProcs;
 TestVarParams;
 TestRecursion;
 TestNested;
 TestMultipleLocals;
 O.Ln;
 O.String("TestC: "); O.Int(pass, 0);
 O.String(" passed, "); O.Int(fail, 0);
 O.String(" failed"); O.Ln;
 O.Exit(fail)
END TestC.
