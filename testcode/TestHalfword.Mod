MODULE TestHalfword;
(* Test 3: LDRH/STRH with large offset (>256 bytes).
   Halfword (INTEGER = 16-bit) loads/stores use 8-bit split offset encoding,
   so the limit is 256 bytes. A record with 64 LONGINTs (256 bytes) of padding
   followed by an INTEGER field at offset 256 triggers the fix. *)
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

 PROCEDURE TestHalfAt256;
  TYPE Rec256 = RECORD
   pad: ARRAY 64 OF LONGINT;   (* 256 bytes *)
   h: INTEGER                   (* at offset 256 -- exceeds 8-bit limit *)
  END;
  VAR r: Rec256;
 BEGIN
  O.String("--- Halfword at offset 256 ---"); O.Ln;
  r.pad[0] := 1;
  r.pad[63] := 63;
  r.h := 12345;
  Check("pad[0]", r.pad[0], 1);
  Check("pad[63]", r.pad[63], 63);
  Check("h@256", r.h, 12345)
 END TestHalfAt256;

 PROCEDURE TestHalfAt512;
  TYPE Rec512 = RECORD
   pad: ARRAY 128 OF LONGINT;  (* 512 bytes *)
   h1: INTEGER;                 (* at offset 512 *)
   h2: INTEGER                  (* at offset 514 *)
  END;
  VAR r: Rec512;
 BEGIN
  O.String("--- Halfword at offset 512 ---"); O.Ln;
  r.pad[0] := 100;
  r.pad[127] := 200;
  r.h1 := 30000;
  r.h2 := -10000;
  Check("pad[0]", r.pad[0], 100);
  Check("pad[127]", r.pad[127], 200);
  Check("h1@512", r.h1, 30000);
  Check("h2@514", r.h2, -10000)
 END TestHalfAt512;

 PROCEDURE TestHalfArray;
  (* Array of INTEGERs past the 256-byte boundary *)
  TYPE BigHalf = RECORD
   pad: ARRAY 64 OF LONGINT;     (* 256 bytes *)
   arr: ARRAY 16 OF INTEGER      (* 32 bytes starting at offset 256 *)
  END;
  VAR r: BigHalf; i: LONGINT;
 BEGIN
  O.String("--- Halfword array past 256 ---"); O.Ln;
  i := 0;
  WHILE i < 16 DO
   r.arr[i] := SHORT(i * 1000);
   INC(i)
  END;
  Check("arr[0]", r.arr[0], 0);
  Check("arr[7]", r.arr[7], 7000);
  Check("arr[15]", r.arr[15], 15000)
 END TestHalfArray;

BEGIN
 pass := 0; fail := 0;
 O.String("=== TestHalfword: LDRH/STRH large offset ==="); O.Ln;
 TestHalfAt256;
 TestHalfAt512;
 TestHalfArray;
 O.Ln;
 O.String("TestHalfword: "); O.Int(pass, 0);
 O.String(" passed, "); O.Int(fail, 0);
 O.String(" failed"); O.Ln;
 O.Exit(fail)
END TestHalfword.
