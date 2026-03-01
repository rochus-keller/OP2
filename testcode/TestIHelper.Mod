MODULE TestIHelper;
(* Helper module for TestI: exports variables and constants for cross-module testing *)

CONST
 MaxVal* = 1000;
 MinVal* = -500;
 Pi100* = 314;

VAR
 counter*: LONGINT;
 flag*: BOOLEAN;
 shared*: LONGINT;

 PROCEDURE Reset*;
 BEGIN counter := 0; flag := FALSE; shared := 0
 END Reset;

 PROCEDURE Inc*;
 BEGIN INC(counter)
 END Inc;

 PROCEDURE IncBy*(n: LONGINT);
 BEGIN counter := counter + n
 END IncBy;

 PROCEDURE GetCounter*(): LONGINT;
 BEGIN RETURN counter
 END GetCounter;

 PROCEDURE SetShared*(v: LONGINT);
 BEGIN shared := v
 END SetShared;

 PROCEDURE GetShared*(): LONGINT;
 BEGIN RETURN shared
 END GetShared;

 PROCEDURE Add*(a, b: LONGINT): LONGINT;
 BEGIN RETURN a + b
 END Add;

BEGIN
 counter := 42;
 flag := TRUE;
 shared := 99
END TestIHelper.
