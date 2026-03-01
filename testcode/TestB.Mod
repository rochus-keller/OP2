MODULE TestB;
(* TestB: Control Flow *)
(* Covers: IF/ELSIF/ELSE, WHILE, REPEAT, FOR, FOR with step, LOOP/EXIT, nested loops, boolean ops *)
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

 PROCEDURE TestIf;
  VAR x, r: LONGINT;
 BEGIN
  O.String("--- IF/ELSIF/ELSE ---"); O.Ln;
  x := 5;
  IF x < 0 THEN r := -1
  ELSIF x = 0 THEN r := 0
  ELSIF x < 10 THEN r := 1
  ELSE r := 2
  END;
  Check("ELSIF x=5", r, 1);
  x := -3;
  IF x < 0 THEN r := -1 ELSE r := 1 END;
  Check("IF x=-3", r, -1);
  x := 0;
  IF x < 0 THEN r := -1
  ELSIF x = 0 THEN r := 0
  ELSE r := 1
  END;
  Check("ELSIF x=0", r, 0)
 END TestIf;

 PROCEDURE TestWhile;
  VAR i, sum: LONGINT;
 BEGIN
  O.String("--- WHILE ---"); O.Ln;
  i := 1; sum := 0;
  WHILE i <= 10 DO sum := sum + i; INC(i) END;
  Check("WHILE 1..10", sum, 55);
  i := 100; sum := 0;
  WHILE i > 0 DO sum := sum + i; DEC(i) END;
  Check("WHILE 100..1", sum, 5050)
 END TestWhile;

 PROCEDURE TestRepeat;
  VAR i, sum: LONGINT;
 BEGIN
  O.String("--- REPEAT ---"); O.Ln;
  i := 1; sum := 0;
  REPEAT sum := sum + i; INC(i) UNTIL i > 10;
  Check("REPEAT 1..10", sum, 55);
  i := 0; sum := 1;
  REPEAT sum := sum * 2; INC(i) UNTIL i = 10;
  Check("REPEAT 2^10", sum, 1024)
 END TestRepeat;

 PROCEDURE TestFor;
  VAR i, sum: LONGINT;
 BEGIN
  O.String("--- FOR ---"); O.Ln;
  sum := 0;
  FOR i := 1 TO 10 DO sum := sum + i END;
  Check("FOR 1..10", sum, 55);
  sum := 0;
  FOR i := 0 TO 20 BY 2 DO sum := sum + i END;
  Check("FOR step 2", sum, 110);
  sum := 0;
  FOR i := 10 TO 1 BY -1 DO sum := sum + i END;
  Check("FOR step -1", sum, 55)
 END TestFor;

 PROCEDURE TestLoopExit;
  VAR i, count: LONGINT;
 BEGIN
  O.String("--- LOOP/EXIT ---"); O.Ln;
  i := 0; count := 0;
  LOOP
   IF i >= 10 THEN EXIT END;
   INC(count);
   INC(i)
  END;
  Check("LOOP count", count, 10);
  (* nested LOOP *)
  i := 0; count := 0;
  LOOP
   IF i >= 3 THEN EXIT END;
   LOOP
    INC(count);
    IF count MOD 5 = 0 THEN EXIT END
   END;
   INC(i)
  END;
  Check("nested LOOP", count, 15)
 END TestLoopExit;

 PROCEDURE TestBoolOps;
  VAR a, b, r: LONGINT;
 BEGIN
  O.String("--- Boolean Ops ---"); O.Ln;
  a := 5; b := 3;
  IF (a > 0) & (b > 0) THEN r := 1 ELSE r := 0 END;
  Check("AND true", r, 1);
  IF (a > 0) & (b > 10) THEN r := 1 ELSE r := 0 END;
  Check("AND false", r, 0);
  IF (a > 10) OR (b > 0) THEN r := 1 ELSE r := 0 END;
  Check("OR true", r, 1);
  IF (a > 10) OR (b > 10) THEN r := 1 ELSE r := 0 END;
  Check("OR false", r, 0);
  IF ~(a > 10) THEN r := 1 ELSE r := 0 END;
  Check("NOT true", r, 1);
  (* short-circuit: don't divide by zero *)
  a := 0;
  IF (a # 0) & (10 DIV a > 0) THEN r := 1 ELSE r := 0 END;
  Check("AND short-circuit", r, 0);
  IF (a = 0) OR (10 DIV a > 0) THEN r := 1 ELSE r := 0 END;
  Check("OR short-circuit", r, 1)
 END TestBoolOps;

 PROCEDURE TestNested;
  VAR i, j, sum: LONGINT;
 BEGIN
  O.String("--- Nested Loops ---"); O.Ln;
  sum := 0;
  FOR i := 1 TO 5 DO
   FOR j := 1 TO 5 DO
    sum := sum + 1
   END
  END;
  Check("5x5 nested FOR", sum, 25);
  sum := 0; i := 0;
  WHILE i < 3 DO
   j := 0;
   WHILE j < 4 DO
    sum := sum + (i + 1) * (j + 1);
    INC(j)
   END;
   INC(i)
  END;
  Check("nested WHILE", sum, 60)
 END TestNested;

 PROCEDURE TestCompare;
  VAR a, b, r: LONGINT;
 BEGIN
  O.String("--- Comparisons ---"); O.Ln;
  a := 10; b := 20;
  IF a < b THEN r := 1 ELSE r := 0 END;
  Check("10 < 20", r, 1);
  IF a > b THEN r := 1 ELSE r := 0 END;
  Check("10 > 20", r, 0);
  IF a <= 10 THEN r := 1 ELSE r := 0 END;
  Check("10 <= 10", r, 1);
  IF a >= 11 THEN r := 1 ELSE r := 0 END;
  Check("10 >= 11", r, 0);
  IF a = 10 THEN r := 1 ELSE r := 0 END;
  Check("10 = 10", r, 1);
  IF a # b THEN r := 1 ELSE r := 0 END;
  Check("10 # 20", r, 1)
 END TestCompare;

BEGIN
 pass := 0; fail := 0;
 O.String("=== TestB: Control Flow ==="); O.Ln;
 TestIf;
 TestWhile;
 TestRepeat;
 TestFor;
 TestLoopExit;
 TestBoolOps;
 TestNested;
 TestCompare;
 O.Ln;
 O.String("TestB: "); O.Int(pass, 0);
 O.String(" passed, "); O.Int(fail, 0);
 O.String(" failed"); O.Ln;
 O.Exit(fail)
END TestB.
