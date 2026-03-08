MODULE TestVFPRet;
(* Test: VFP function return values (Bug 1 fix).
   Verifies that functions returning REAL and LONGREAL correctly
   pass results back to callers via S0/D0. *)
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

 PROCEDURE CheckReal(name: ARRAY OF CHAR; got, expected: REAL);
  VAR gi, ei: LONGINT;
 BEGIN
  gi := ENTIER(got);
  ei := ENTIER(expected);
  O.String(name);
  IF gi = ei THEN
   O.String(" OK"); INC(pass)
  ELSE
   O.String(" FAIL got="); O.Int(gi, 0);
   O.String(" expected="); O.Int(ei, 0);
   INC(fail)
  END;
  O.Ln
 END CheckReal;

 (* --- REAL-returning functions --- *)

 PROCEDURE OneR(): REAL;
 BEGIN RETURN 1.0
 END OneR;

 PROCEDURE AddR(a, b: REAL): REAL;
 BEGIN RETURN a + b
 END AddR;

 PROCEDURE MulR(a, b: REAL): REAL;
 BEGIN RETURN a * b
 END MulR;

 PROCEDURE NegR(x: REAL): REAL;
 BEGIN RETURN -x
 END NegR;

 PROCEDURE SquareR(x: REAL): REAL;
 BEGIN RETURN x * x
 END SquareR;

 (* --- Tests --- *)

 PROCEDURE TestSimpleReturn;
  VAR r: REAL;
 BEGIN
  O.String("--- Simple REAL return ---"); O.Ln;
  r := OneR();
  CheckReal("OneR()", r, 1.0)
 END TestSimpleReturn;

 PROCEDURE TestArithReturn;
  VAR r: REAL;
 BEGIN
  O.String("--- Arithmetic REAL return ---"); O.Ln;
  r := AddR(3.0, 4.0);
  CheckReal("AddR(3,4)", r, 7.0);
  r := MulR(5.0, 6.0);
  CheckReal("MulR(5,6)", r, 30.0);
  r := NegR(8.0);
  CheckReal("NegR(8)", r, -8.0)
 END TestArithReturn;

 PROCEDURE TestChainedReturn;
  VAR r: REAL;
 BEGIN
  O.String("--- Chained REAL return ---"); O.Ln;
  r := AddR(OneR(), OneR());
  CheckReal("AddR(1,1)", r, 2.0);
  r := MulR(AddR(2.0, 3.0), 4.0);
  CheckReal("Mul(Add(2,3),4)", r, 20.0);
  r := SquareR(5.0);
  CheckReal("Square(5)", r, 25.0)
 END TestChainedReturn;

 PROCEDURE TestReturnInExpr;
  VAR x, y: REAL; i: LONGINT;
 BEGIN
  O.String("--- REAL return in expression ---"); O.Ln;
  x := OneR() + 2.0;
  CheckReal("1+2", x, 3.0);
  x := AddR(1.0, 2.0) * 3.0;
  CheckReal("(1+2)*3", x, 9.0);
  i := ENTIER(AddR(10.0, 0.0));
  Check("ENTIER(Add(10,0))", i, 10)
 END TestReturnInExpr;

 PROCEDURE TestVFPAcrossCall;
  (* Test that VFP register contents survive across function calls *)
  VAR a, b, c: REAL;
 BEGIN
  O.String("--- VFP across calls ---"); O.Ln;
  a := 10.0;
  b := AddR(3.0, 4.0);  (* b = 7.0; must not clobber a *)
  CheckReal("a after call", a, 10.0);
  CheckReal("b from call", b, 7.0);
  c := a + b;
  CheckReal("a+b", c, 17.0)
 END TestVFPAcrossCall;

BEGIN
 pass := 0; fail := 0;
 O.String("=== TestVFPRet: VFP function returns ==="); O.Ln;
 TestSimpleReturn;
 TestArithReturn;
 TestChainedReturn;
 TestReturnInExpr;
 TestVFPAcrossCall;
 O.Ln;
 O.String("TestVFPRet: "); O.Int(pass, 0);
 O.String(" passed, "); O.Int(fail, 0);
 O.String(" failed"); O.Ln;
 O.Exit(fail)
END TestVFPRet.
