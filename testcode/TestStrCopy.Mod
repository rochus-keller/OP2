MODULE TestStrCopy;
(* TestStrCopy: String assignment / GenRepMovs halfword copy fix
   Bug 2: GenRepMovs used GenLDRPost/GenSTRPost (word load/store) for Bit16 copies.
   MoveBlock promotes even-length byte copies to halfword, but GenRepMovs had no
   halfword load/store, so it used word ops with step=2 causing unaligned access.
   Key pattern: 14-byte strings (even length, not divisible by 4) trigger halfword path. *)
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

 PROCEDURE CheckStr(name: ARRAY OF CHAR; got, expected: ARRAY OF CHAR);
  VAR i: LONGINT; eq: BOOLEAN;
 BEGIN
  O.String(name);
  i := 0; eq := TRUE;
  WHILE (got[i] # 0X) & (expected[i] # 0X) & eq DO
   IF got[i] # expected[i] THEN eq := FALSE END;
   INC(i)
  END;
  IF (got[i] # 0X) OR (expected[i] # 0X) THEN eq := FALSE END;
  IF eq THEN
   O.String(" OK"); INC(pass)
  ELSE
   O.String(" FAIL got="); O.String(got);
   O.String(" expected="); O.String(expected);
   INC(fail)
  END;
  O.Ln
 END CheckStr;

 PROCEDURE StrLen(s: ARRAY OF CHAR): LONGINT;
  VAR i: LONGINT;
 BEGIN
  i := 0;
  WHILE s[i] # 0X DO INC(i) END;
  RETURN i
 END StrLen;

 PROCEDURE TestOddLengths;
  VAR s: ARRAY 64 OF CHAR;
 BEGIN
  O.String("--- Odd Length Copies (byte path) ---"); O.Ln;
  (* 1 byte + null = 2 bytes total, but string content = 1 char *)
  s := "A";
  CheckStr("1ch copy", s, "A");
  Check("1ch len", StrLen(s), 1);

  (* 3 chars + null = 4 bytes -> word copy *)
  s := "ABC";
  CheckStr("3ch copy", s, "ABC");
  Check("3ch len", StrLen(s), 3);

  (* 5 chars + null = 6 bytes -> halfword candidate (6%4!=0, 6%2=0) *)
  s := "Hello";
  CheckStr("5ch copy", s, "Hello");
  Check("5ch len", StrLen(s), 5);

  (* 13 chars + null = 14 bytes -> halfword candidate (14%4!=0, 14%2=0) *)
  s := "ARM Native 12";
  CheckStr("13ch copy", s, "ARM Native 12");
  Check("13ch len", StrLen(s), 13)
 END TestOddLengths;

 PROCEDURE TestEvenLengths;
  VAR s: ARRAY 64 OF CHAR;
 BEGIN
  O.String("--- Even Length Copies (halfword/word path) ---"); O.Ln;
  (* 2 chars + null = 3 bytes -> odd -> byte path *)
  s := "AB";
  CheckStr("2ch copy", s, "AB");
  Check("2ch len", StrLen(s), 2);

  (* 4 chars + null = 5 bytes -> odd -> byte path *)
  s := "ABCD";
  CheckStr("4ch copy", s, "ABCD");
  Check("4ch len", StrLen(s), 4);

  (* 6 chars + null = 7 bytes -> odd -> byte path *)
  s := "ABCDEF";
  CheckStr("6ch copy", s, "ABCDEF");
  Check("6ch len", StrLen(s), 6)
 END TestEvenLengths;

 PROCEDURE TestCriticalSizes;
  VAR s: ARRAY 64 OF CHAR;
 BEGIN
  O.String("--- Critical Sizes (halfword promotion) ---"); O.Ln;
  (* These are the critical sizes: content+null is even AND not div by 4
     Content of 1,5,9,13,17,... chars -> 2,6,10,14,18,... bytes *)

  (* 5 chars + null = 6 bytes: 6%4=2, 6%2=0 -> halfword *)
  s := "12345";
  CheckStr("5ch(6B)", s, "12345");

  (* 9 chars + null = 10 bytes: 10%4=2, 10%2=0 -> halfword *)
  s := "123456789";
  CheckStr("9ch(10B)", s, "123456789");

  (* 13 chars + null = 14 bytes: 14%4=2, 14%2=0 -> halfword *)
  s := "ARM Native123";
  CheckStr("13ch(14B)", s, "ARM Native123");

  (* 17 chars + null = 18 bytes: 18%4=2, 18%2=0 -> halfword *)
  s := "ABCDEFGHIJKLMNOPQ";
  CheckStr("17ch(18B)", s, "ABCDEFGHIJKLMNOPQ");

  (* 7 chars + null = 8 bytes: 8%4=0 -> word path *)
  s := "1234567";
  CheckStr("7ch(8B)word", s, "1234567");

  (* 11 chars + null = 12 bytes: 12%4=0 -> word path *)
  s := "12345678901";
  CheckStr("11ch(12B)word", s, "12345678901");

  (* 15 chars + null = 16 bytes: 16%4=0 -> word path *)
  s := "123456789012345";
  CheckStr("15ch(16B)word", s, "123456789012345")
 END TestCriticalSizes;

 PROCEDURE TestVarToVar;
  VAR s1, s2: ARRAY 64 OF CHAR;
 BEGIN
  O.String("--- Var-to-Var Copy ---"); O.Ln;
  s1 := "ARM Native123";
  s2 := s1;
  CheckStr("v2v 13ch", s2, "ARM Native123");

  s1 := "Even length!12";
  s2 := s1;
  CheckStr("v2v 14ch", s2, "Even length!12");
  Check("v2v 14ch len", StrLen(s2), 14)
 END TestVarToVar;

BEGIN
 pass := 0; fail := 0;
 O.String("=== TestStrCopy: String Copy / GenRepMovs ==="); O.Ln;
 TestOddLengths;
 TestEvenLengths;
 TestCriticalSizes;
 TestVarToVar;
 O.Ln;
 O.String("TestStrCopy: "); O.Int(pass, 0);
 O.String(" passed, "); O.Int(fail, 0);
 O.String(" failed"); O.Ln;
 O.Exit(fail)
END TestStrCopy.
