MODULE TestIndexedLarge;
(* Test 4: Indexed array access within large-offset records.
   Two Page records (4096 bytes each) with indexed array access.
   Tests that AdjustLargeOffset is applied BEFORE index computation. *)
IMPORT RawOut;

VAR pass, fail: LONGINT;

 PROCEDURE Check(name: ARRAY OF CHAR; got, expected: LONGINT);
 BEGIN
  RawOut.String(name);
  IF got = expected THEN
   RawOut.String(" OK"); INC(pass)
  ELSE
   RawOut.String(" FAIL got="); RawOut.Int(got, 0);
   RawOut.String(" expected="); RawOut.Int(expected, 0);
   INC(fail)
  END;
  RawOut.Ln
 END Check;

 PROCEDURE TestIndexedWrite;
  TYPE Page = RECORD
   data: ARRAY 1024 OF LONGINT  (* 4096 bytes *)
  END;
  VAR p1, p2: Page; i: LONGINT;
 BEGIN
  RawOut.String("--- Indexed write to large records ---"); RawOut.Ln;
  i := 0;
  WHILE i < 1024 DO
   p1.data[i] := i;
   p2.data[i] := i * 2;
   INC(i)
  END;
  Check("p1[0]", p1.data[0], 0);
  Check("p1[100]", p1.data[100], 100);
  Check("p1[511]", p1.data[511], 511);
  Check("p1[1023]", p1.data[1023], 1023);
  Check("p2[0]", p2.data[0], 0);
  Check("p2[100]", p2.data[100], 200);
  Check("p2[511]", p2.data[511], 1022);
  Check("p2[1023]", p2.data[1023], 2046)
 END TestIndexedWrite;

 PROCEDURE TestIndexedReadBack;
  (* Variable index into large record *)
  TYPE BigArr = RECORD
   arr: ARRAY 2048 OF LONGINT  (* 8192 bytes *)
  END;
  VAR b: BigArr; i, sum: LONGINT;
 BEGIN
  RawOut.String("--- Indexed read-back from 8K record ---"); RawOut.Ln;
  i := 0;
  WHILE i < 2048 DO
   b.arr[i] := i MOD 100;
   INC(i)
  END;
  sum := 0;
  i := 0;
  WHILE i < 2048 DO
   sum := sum + b.arr[i];
   INC(i)
  END;
  (* Sum of (i MOD 100) for i=0..2047:
     20 full cycles of 0+1+...+99 = 20*4950 = 99000
     plus partial cycle 0+1+...+47 = 48*47/2 = 1128
     total = 100128 *)
  Check("sum", sum, 100128)
 END TestIndexedReadBack;

 PROCEDURE TestDynIndex;
  (* Dynamic index computed at runtime past large offset *)
  TYPE Page = RECORD
   data: ARRAY 1024 OF LONGINT
  END;
  VAR p: Page; idx: LONGINT;
 BEGIN
  RawOut.String("--- Dynamic index into large record ---"); RawOut.Ln;
  idx := 900;
  p.data[idx] := 42;
  Check("p[900]", p.data[idx], 42);
  idx := 1023;
  p.data[idx] := -1;
  Check("p[1023]", p.data[idx], -1)
 END TestDynIndex;

BEGIN
 pass := 0; fail := 0;
 RawOut.String("=== TestIndexedLarge: Indexed access + large offset ==="); RawOut.Ln;
 TestIndexedWrite;
 TestIndexedReadBack;
 TestDynIndex;
 RawOut.Ln;
 RawOut.String("TestIndexedLarge: "); RawOut.Int(pass, 0);
 RawOut.String(" passed, "); RawOut.Int(fail, 0);
 RawOut.String(" failed"); RawOut.Ln;
 RawOut.Exit(fail)
END TestIndexedLarge.
