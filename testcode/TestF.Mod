MODULE TestF;
(* TestF: Sets, CASE, Strings, Type Conversions *)
(* Covers: SET ops, CASE statement, CHAR/ORD/CHR, strings, LONG/SHORT, type tests *)
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

 PROCEDURE TestSets;
  VAR s, t: SET; r: LONGINT;
 BEGIN
  O.String("--- SET Operations ---"); O.Ln;
  s := {1, 3, 5, 7};
  IF 3 IN s THEN r := 1 ELSE r := 0 END;
  Check("3 IN s", r, 1);
  IF 4 IN s THEN r := 1 ELSE r := 0 END;
  Check("4 IN s", r, 0);
  s := s + {2, 4};
  IF 4 IN s THEN r := 1 ELSE r := 0 END;
  Check("union 4", r, 1);
  s := s - {3, 5};
  IF 3 IN s THEN r := 1 ELSE r := 0 END;
  Check("diff 3", r, 0);
  IF 1 IN s THEN r := 1 ELSE r := 0 END;
  Check("diff keeps 1", r, 1);
  t := {1, 7, 9};
  s := s * t;
  IF 1 IN s THEN r := 1 ELSE r := 0 END;
  Check("intersect 1", r, 1);
  IF 2 IN s THEN r := 1 ELSE r := 0 END;
  Check("intersect 2", r, 0);
  IF 7 IN s THEN r := 1 ELSE r := 0 END;
  Check("intersect 7", r, 1)
 END TestSets;

 PROCEDURE CaseVal(n: LONGINT): LONGINT;
  VAR r: LONGINT;
 BEGIN
  CASE n OF
    1: r := 10
  | 2: r := 20
  | 3: r := 30
  | 4, 5: r := 45
  | 6: r := 60
  | 7: r := 70
  | 8: r := 80
  | 9: r := 90
  | 10: r := 100
  ELSE r := -1
  END;
  RETURN r
 END CaseVal;

 PROCEDURE TestCase;
 BEGIN
  O.String("--- CASE Statement ---"); O.Ln;
  Check("CASE 1", CaseVal(1), 10);
  Check("CASE 2", CaseVal(2), 20);
  Check("CASE 3", CaseVal(3), 30);
  Check("CASE 4", CaseVal(4), 45);
  Check("CASE 5", CaseVal(5), 45);
  Check("CASE 6", CaseVal(6), 60);
  Check("CASE 10", CaseVal(10), 100);
  Check("CASE 0", CaseVal(0), -1);
  Check("CASE 99", CaseVal(99), -1)
 END TestCase;

 PROCEDURE TestCharOrd;
  VAR ch: CHAR; i: LONGINT;
 BEGIN
  O.String("--- CHAR/ORD ---"); O.Ln;
  ch := "A";
  Check("ORD(A)", ORD(ch), 65);
  Check("ORD(CHR(66))", ORD(CHR(66)), 66);
  ch := CHR(48 + 7);
  Check("CHR(55)", ORD(ch), 55);
  ch := "z";
  Check("ORD(z)", ORD(ch), 122);
  ch := " ";
  Check("ORD(space)", ORD(ch), 32)
 END TestCharOrd;

 PROCEDURE TestStrings;
  VAR s: ARRAY 20 OF CHAR;
 BEGIN
  O.String("--- Strings ---"); O.Ln;
  s := "Hello";
  Check("s[0]=H", ORD(s[0]), 72);
  Check("s[1]=e", ORD(s[1]), 101);
  Check("s[4]=o", ORD(s[4]), 111);
  Check("s[5]=0X", ORD(s[5]), 0);
  O.String("echo: "); O.String(s); O.Ln
 END TestStrings;

 PROCEDURE TestTypeConv;
  VAR i: INTEGER; l: LONGINT;
 BEGIN
  O.String("--- Type Conversions ---"); O.Ln;
  i := 100;
  l := LONG(i);
  Check("LONG(100)", l, 100);
  l := 200;
  i := SHORT(l);
  Check("SHORT(200)", LONG(i), 200);
  i := -50;
  l := LONG(i);
  Check("LONG(-50)", l, -50)
 END TestTypeConv;

 PROCEDURE TestCharOutput;
 BEGIN
  O.String("--- Char Output ---"); O.Ln;
  O.String("ABC: ");
  O.Char("A"); O.Char("B"); O.Char("C"); O.Ln;
  O.String("digits: ");
  O.Char(CHR(48)); O.Char(CHR(49)); O.Char(CHR(50));
  O.Ln;
  Check("char output", 1, 1)
 END TestCharOutput;

BEGIN
 pass := 0; fail := 0;
 O.String("=== TestF: Sets/CASE/Strings ==="); O.Ln;
 TestSets;
 TestCase;
 TestCharOrd;
 TestStrings;
 TestTypeConv;
 TestCharOutput;
 O.Ln;
 O.String("TestF: "); O.Int(pass, 0);
 O.String(" passed, "); O.Int(fail, 0);
 O.String(" failed"); O.Ln;
 O.Exit(fail)
END TestF.
