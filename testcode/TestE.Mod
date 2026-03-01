MODULE TestE;
(* TestE: Records & Pointers *)
(* Covers: local records, global records, record params, VAR record params, nested fields, array of records *)
IMPORT O := RawOut;

VAR pass, fail: LONGINT;

TYPE
 Point = RECORD x, y: LONGINT END;
 Rect = RECORD origin: Point; w, h: LONGINT END;

VAR gp: Point;

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

 PROCEDURE Dist(p: Point): LONGINT;
 BEGIN RETURN p.x + p.y
 END Dist;

 PROCEDURE SetPoint(VAR p: Point; x, y: LONGINT);
 BEGIN p.x := x; p.y := y
 END SetPoint;

 PROCEDURE TestLocalRecord;
  VAR p: Point;
 BEGIN
  O.String("--- Local Record ---"); O.Ln;
  p.x := 10; p.y := 20;
  Check("p.x", p.x, 10);
  Check("p.y", p.y, 20);
  Check("p.x+p.y", p.x + p.y, 30)
 END TestLocalRecord;

 PROCEDURE TestGlobalRecord;
 BEGIN
  O.String("--- Global Record ---"); O.Ln;
  gp.x := 100; gp.y := 200;
  Check("gp.x", gp.x, 100);
  Check("gp.y", gp.y, 200)
 END TestGlobalRecord;

 PROCEDURE TestRecordParams;
  VAR p: Point;
 BEGIN
  O.String("--- Record Params ---"); O.Ln;
  p.x := 3; p.y := 7;
  Check("Dist(3,7)", Dist(p), 10);
  SetPoint(p, 42, 99);
  Check("SetPoint x", p.x, 42);
  Check("SetPoint y", p.y, 99)
 END TestRecordParams;

 PROCEDURE TestNestedRecord;
  VAR r: Rect;
 BEGIN
  O.String("--- Nested Record ---"); O.Ln;
  r.origin.x := 10; r.origin.y := 20;
  r.w := 100; r.h := 50;
  Check("r.origin.x", r.origin.x, 10);
  Check("r.origin.y", r.origin.y, 20);
  Check("r.w", r.w, 100);
  Check("r.h", r.h, 50);
  Check("area", r.w * r.h, 5000)
 END TestNestedRecord;

 PROCEDURE TestArrayOfRecords;
  TYPE Pair = RECORD a, b: LONGINT END;
  VAR pairs: ARRAY 4 OF Pair;
      i, sum: LONGINT;
 BEGIN
  O.String("--- Array of Records ---"); O.Ln;
  FOR i := 0 TO 3 DO
   pairs[i].a := i + 1;
   pairs[i].b := (i + 1) * 10
  END;
  Check("pairs[0].a", pairs[0].a, 1);
  Check("pairs[0].b", pairs[0].b, 10);
  Check("pairs[3].a", pairs[3].a, 4);
  Check("pairs[3].b", pairs[3].b, 40);
  sum := 0;
  FOR i := 0 TO 3 DO sum := sum + pairs[i].a + pairs[i].b END;
  Check("sum pairs", sum, 110)
 END TestArrayOfRecords;

 PROCEDURE TestRecordAssign;
  VAR p1, p2: Point;
 BEGIN
  O.String("--- Record Assign ---"); O.Ln;
  p1.x := 11; p1.y := 22;
  p2 := p1;
  Check("copy x", p2.x, 11);
  Check("copy y", p2.y, 22);
  p1.x := 999;
  Check("independent", p2.x, 11)
 END TestRecordAssign;

BEGIN
 pass := 0; fail := 0;
 O.String("=== TestE: Records ==="); O.Ln;
 TestLocalRecord;
 TestGlobalRecord;
 TestRecordParams;
 TestNestedRecord;
 TestArrayOfRecords;
 TestRecordAssign;
 O.Ln;
 O.String("TestE: "); O.Int(pass, 0);
 O.String(" passed, "); O.Int(fail, 0);
 O.String(" failed"); O.Ln;
 O.Exit(fail)
END TestE.
