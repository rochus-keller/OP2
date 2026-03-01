MODULE TestI;
(* TestI: Multi-module state, imported variables, imported constants *)
(* Covers: cross-module variable access, imported constants, exported procedures *)
IMPORT O := RawOut, H := TestIHelper;

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

 PROCEDURE TestImportedConst;
 BEGIN
  O.String("--- Imported Constants ---"); O.Ln;
  Check("MaxVal", H.MaxVal, 1000);
  Check("MinVal", H.MinVal, -500);
  Check("Pi100", H.Pi100, 314);
  Check("MaxVal+MinVal", H.MaxVal + H.MinVal, 500)
 END TestImportedConst;

 PROCEDURE TestImportedVar;
 BEGIN
  O.String("--- Imported Variables ---"); O.Ln;
  (* TestIHelper body sets counter=42, flag=TRUE, shared=99 *)
  Check("init counter", H.counter, 42);
  Check("init shared", H.shared, 99);
  IF H.flag THEN Check("init flag", 1, 1)
  ELSE Check("init flag", 0, 1)
  END
 END TestImportedVar;

 PROCEDURE TestCrossModuleProcs;
 BEGIN
  O.String("--- Cross-module Procedures ---"); O.Ln;
  H.Reset;
  Check("after Reset", H.counter, 0);
  H.Inc;
  Check("after Inc", H.counter, 1);
  H.Inc; H.Inc; H.Inc;
  Check("after 3xInc", H.counter, 4);
  H.IncBy(10);
  Check("after IncBy(10)", H.counter, 14);
  Check("GetCounter", H.GetCounter(), 14);
  Check("Add(17,25)", H.Add(17, 25), 42)
 END TestCrossModuleProcs;

 PROCEDURE TestSharedState;
 BEGIN
  O.String("--- Shared State ---"); O.Ln;
  H.SetShared(123);
  Check("SetShared(123)", H.GetShared(), 123);
  Check("direct read", H.shared, 123);
  H.shared := 456;
  Check("direct write", H.GetShared(), 456);
  H.SetShared(H.GetShared() + 100);
  Check("increment", H.shared, 556)
 END TestSharedState;

 PROCEDURE TestMixedExpr;
  VAR local: LONGINT;
 BEGIN
  O.String("--- Mixed Expressions ---"); O.Ln;
  H.Reset;
  H.IncBy(H.MaxVal);
  Check("IncBy(MaxVal)", H.counter, 1000);
  local := H.GetCounter() + H.MinVal;
  Check("counter+MinVal", local, 500);
  H.SetShared(H.Add(H.counter, local));
  Check("Add(counter,local)", H.shared, 1500)
 END TestMixedExpr;

BEGIN
 pass := 0; fail := 0;
 O.String("=== TestI: Multi-module ==="); O.Ln;
 TestImportedConst;
 TestImportedVar;
 TestCrossModuleProcs;
 TestSharedState;
 TestMixedExpr;
 O.Ln;
 O.String("TestI: "); O.Int(pass, 0);
 O.String(" passed, "); O.Int(fail, 0);
 O.String(" failed"); O.Ln;
 O.Exit(fail)
END TestI.
