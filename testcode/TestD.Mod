MODULE TestD;
(* TestD: Arrays *)
(* Covers: global arrays, local arrays, variable indexing, open array params, array of records *)
IMPORT O := RawOut;

VAR pass, fail: LONGINT;
    ga: ARRAY 10 OF LONGINT;

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

 PROCEDURE SumOpen(a: ARRAY OF LONGINT): LONGINT;
  VAR i, s: LONGINT;
 BEGIN
  s := 0;
  FOR i := 0 TO LEN(a) - 1 DO s := s + a[i] END;
  RETURN s
 END SumOpen;

 PROCEDURE FillArr(VAR a: ARRAY OF LONGINT; start: LONGINT);
  VAR i: LONGINT;
 BEGIN
  FOR i := 0 TO LEN(a) - 1 DO a[i] := start + i END
 END FillArr;

 PROCEDURE TestGlobalArray;
  VAR i, sum: LONGINT;
 BEGIN
  O.String("--- Global Array ---"); O.Ln;
  FOR i := 0 TO 9 DO ga[i] := (i + 1) * 10 END;
  Check("ga[0]", ga[0], 10);
  Check("ga[4]", ga[4], 50);
  Check("ga[9]", ga[9], 100);
  sum := 0;
  FOR i := 0 TO 9 DO sum := sum + ga[i] END;
  Check("sum ga", sum, 550)
 END TestGlobalArray;

 PROCEDURE TestLocalArray;
  VAR a: ARRAY 5 OF LONGINT; i, sum: LONGINT;
 BEGIN
  O.String("--- Local Array ---"); O.Ln;
  FOR i := 0 TO 4 DO a[i] := i * i END;
  Check("a[0]", a[0], 0);
  Check("a[1]", a[1], 1);
  Check("a[2]", a[2], 4);
  Check("a[3]", a[3], 9);
  Check("a[4]", a[4], 16);
  sum := 0;
  FOR i := 0 TO 4 DO sum := sum + a[i] END;
  Check("sum squares", sum, 30)
 END TestLocalArray;

 PROCEDURE TestOpenArray;
  VAR a: ARRAY 5 OF LONGINT; i: LONGINT;
 BEGIN
  O.String("--- Open Array ---"); O.Ln;
  FOR i := 0 TO 4 DO a[i] := (i + 1) * 10 END;
  Check("SumOpen", SumOpen(a), 150);
  FillArr(a, 100);
  Check("FillArr[0]", a[0], 100);
  Check("FillArr[4]", a[4], 104);
  Check("SumOpen filled", SumOpen(a), 510)
 END TestOpenArray;

 PROCEDURE TestArrayCopy;
  VAR a, b: ARRAY 5 OF LONGINT; i: LONGINT;
 BEGIN
  O.String("--- Array Copy ---"); O.Ln;
  FOR i := 0 TO 4 DO a[i] := i + 1 END;
  b := a;
  Check("copy[0]", b[0], 1);
  Check("copy[4]", b[4], 5);
  a[0] := 999;
  Check("independent", b[0], 1)
 END TestArrayCopy;

 PROCEDURE TestNestedIndex;
  VAR a: ARRAY 5 OF LONGINT; i, j: LONGINT;
 BEGIN
  O.String("--- Nested Index ---"); O.Ln;
  FOR i := 0 TO 4 DO a[i] := i + 1 END;
  (* a[a[0]] = a[1] = 2 *)
  Check("a[a[0]]", a[a[0]], 2);
  (* a[a[1]] = a[2] = 3 *)
  Check("a[a[1]]", a[a[1]], 3);
  i := 2; j := a[i];
  Check("indirect idx", j, 3)
 END TestNestedIndex;

BEGIN
 pass := 0; fail := 0;
 O.String("=== TestD: Arrays ==="); O.Ln;
 TestGlobalArray;
 TestLocalArray;
 TestOpenArray;
 TestArrayCopy;
 TestNestedIndex;
 O.Ln;
 O.String("TestD: "); O.Int(pass, 0);
 O.String(" passed, "); O.Int(fail, 0);
 O.String(" failed"); O.Ln;
 O.Exit(fail)
END TestD.
