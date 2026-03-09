MODULE TestLeaIdx;
(* TestLeaIdx: Indexed array record field access (Lea IP clobber fix)
   Bug 3: In Lea, when indexed array access (box[i].field) produces memBase=IP,
   and displacement is too large for ARM rotated-8-bit immediate, EmitAddImm
   falls back to LoadImm32(IP, disp); ADD Rd, IP, IP - clobbering IP with the
   immediate and destroying the base+index address. Result = 2*disp (garbage).
   Fix: copy memBase to instr.reg first, then EmitAddImm(instr.reg, instr.reg, disp). *)
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

 (* Record with fields at various offsets.
    The bug triggers when field displacement > 255 (can't fit in rotated-8-bit). *)
 TYPE
  SmallRec = RECORD
   x, y: LONGINT
  END;

  (* Large record to push field offsets beyond 255 bytes *)
  BigRec = RECORD
   pad: ARRAY 64 OF LONGINT;  (* 256 bytes of padding *)
   a: LONGINT;                 (* offset 256 - beyond rotated-8-bit for some cases *)
   b: LONGINT;                 (* offset 260 *)
   c: LONGINT                  (* offset 264 *)
  END;

  (* Medium record *)
  MedRec = RECORD
   w: LONGINT;
   pad: ARRAY 30 OF LONGINT;  (* 120 bytes padding *)
   v: LONGINT                  (* offset 124 *)
  END;

 VAR
  small: ARRAY 8 OF SmallRec;
  big: ARRAY 4 OF BigRec;
  med: ARRAY 4 OF MedRec;

 PROCEDURE TestSmallRecArray;
  VAR i: LONGINT;
 BEGIN
  O.String("--- Small Record Array ---"); O.Ln;
  (* Small displacements - should always work *)
  FOR i := 0 TO 7 DO
   small[i].x := i * 10;
   small[i].y := i * 10 + 1
  END;
  Check("small[0].x", small[0].x, 0);
  Check("small[0].y", small[0].y, 1);
  Check("small[3].x", small[3].x, 30);
  Check("small[3].y", small[3].y, 31);
  Check("small[7].x", small[7].x, 70);
  Check("small[7].y", small[7].y, 71)
 END TestSmallRecArray;

 PROCEDURE TestSmallIndexed;
  VAR i, sum: LONGINT;
 BEGIN
  O.String("--- Small Indexed Access ---"); O.Ln;
  FOR i := 0 TO 7 DO
   small[i].x := i;
   small[i].y := i * 2
  END;
  (* Access via variable index *)
  i := 5;
  Check("small[i].x i=5", small[i].x, 5);
  Check("small[i].y i=5", small[i].y, 10);
  i := 0;
  Check("small[i].x i=0", small[i].x, 0);
  (* Sum over indexed accesses *)
  sum := 0;
  FOR i := 0 TO 7 DO
   sum := sum + small[i].x + small[i].y
  END;
  Check("sum x+y", sum, 28 + 56)  (* sum(0..7) + 2*sum(0..7) = 28+56 = 84 *)
 END TestSmallIndexed;

 PROCEDURE TestBigRecArray;
  VAR i: LONGINT;
 BEGIN
  O.String("--- Big Record Array (large offset) ---"); O.Ln;
  (* Fields a,b,c at offsets 256,260,264 - displacement > 255 triggers the bug *)
  FOR i := 0 TO 3 DO
   big[i].a := i * 100;
   big[i].b := i * 100 + 1;
   big[i].c := i * 100 + 2
  END;
  Check("big[0].a", big[0].a, 0);
  Check("big[0].b", big[0].b, 1);
  Check("big[0].c", big[0].c, 2);
  Check("big[1].a", big[1].a, 100);
  Check("big[1].b", big[1].b, 101);
  Check("big[2].c", big[2].c, 202);
  Check("big[3].a", big[3].a, 300);
  Check("big[3].c", big[3].c, 302)
 END TestBigRecArray;

 PROCEDURE TestBigIndexed;
  VAR i: LONGINT;
 BEGIN
  O.String("--- Big Indexed Access (Lea IP clobber test) ---"); O.Ln;
  FOR i := 0 TO 3 DO
   big[i].a := (i + 1) * 1000;
   big[i].b := (i + 1) * 1000 + 500;
   big[i].c := (i + 1) * 1000 + 999
  END;
  (* Variable index - this is the critical path that triggers Lea with IP as memBase *)
  i := 0;
  Check("big[i].a i=0", big[i].a, 1000);
  Check("big[i].b i=0", big[i].b, 1500);
  Check("big[i].c i=0", big[i].c, 1999);
  i := 1;
  Check("big[i].a i=1", big[i].a, 2000);
  Check("big[i].b i=1", big[i].b, 2500);
  i := 2;
  Check("big[i].a i=2", big[i].a, 3000);
  Check("big[i].c i=2", big[i].c, 3999);
  i := 3;
  Check("big[i].a i=3", big[i].a, 4000);
  Check("big[i].b i=3", big[i].b, 4500);
  Check("big[i].c i=3", big[i].c, 4999)
 END TestBigIndexed;

 PROCEDURE TestMedIndexed;
  VAR i: LONGINT;
 BEGIN
  O.String("--- Medium Record Indexed ---"); O.Ln;
  FOR i := 0 TO 3 DO
   med[i].w := i;
   med[i].v := i * 77
  END;
  i := 0;
  Check("med[i].w i=0", med[i].w, 0);
  Check("med[i].v i=0", med[i].v, 0);
  i := 2;
  Check("med[i].w i=2", med[i].w, 2);
  Check("med[i].v i=2", med[i].v, 154);
  i := 3;
  Check("med[i].v i=3", med[i].v, 231)
 END TestMedIndexed;

 PROCEDURE TestExprIndex;
  VAR i, j: LONGINT;
 BEGIN
  O.String("--- Expression Index ---"); O.Ln;
  FOR i := 0 TO 7 DO
   small[i].x := i * 3;
   small[i].y := i * 7
  END;
  i := 2; j := 3;
  Check("small[i+j].x", small[i+j].x, 15);
  Check("small[i+j].y", small[i+j].y, 35);
  Check("small[i*j+1].x", small[i*j+1].x, 21)
 END TestExprIndex;

BEGIN
 pass := 0; fail := 0;
 O.String("=== TestLeaIdx: Lea Indexed Record Field ==="); O.Ln;
 TestSmallRecArray;
 TestSmallIndexed;
 TestBigRecArray;
 TestBigIndexed;
 TestMedIndexed;
 TestExprIndex;
 O.Ln;
 O.String("TestLeaIdx: "); O.Int(pass, 0);
 O.String(" passed, "); O.Int(fail, 0);
 O.String(" failed"); O.Ln;
 O.Exit(fail)
END TestLeaIdx.
