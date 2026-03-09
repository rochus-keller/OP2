MODULE TestStrCmp;
(* TestStrCmp: String comparison (GenCmpString byte-load fix)
   Bug 1: GenCmpString used GenLDRPost (word load) instead of GenLDRBPost (byte load).
   On strict-alignment ARM, the 2nd iteration does LDR from addr+1 = unaligned fault.
   This test exercises string comparisons of various lengths and positions. *)
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

 PROCEDURE BoolInt(b: BOOLEAN): LONGINT;
 BEGIN
  IF b THEN RETURN 1 ELSE RETURN 0 END
 END BoolInt;

 PROCEDURE TestBasicCmp;
  VAR s1, s2: ARRAY 32 OF CHAR;
 BEGIN
  O.String("--- Basic String Compare ---"); O.Ln;
  (* Equal strings *)
  s1 := "Hello";
  s2 := "Hello";
  Check("Hello=Hello", BoolInt(s1 = s2), 1);

  (* Different strings *)
  s2 := "World";
  Check("Hello#World", BoolInt(s1 # s2), 1);

  (* Less than *)
  s1 := "ABC";
  s2 := "ABD";
  Check("ABC<ABD", BoolInt(s1 < s2), 1);

  (* Greater than *)
  Check("ABD>ABC", BoolInt(s2 > s1), 1);

  (* Prefix comparison *)
  s1 := "AB";
  s2 := "ABC";
  Check("AB<ABC", BoolInt(s1 < s2), 1)
 END TestBasicCmp;

 PROCEDURE TestLengthVariations;
  VAR s1, s2: ARRAY 32 OF CHAR;
 BEGIN
  O.String("--- Length Variations ---"); O.Ln;
  (* Single char *)
  s1 := "A";
  s2 := "A";
  Check("A=A", BoolInt(s1 = s2), 1);

  s2 := "B";
  Check("A<B", BoolInt(s1 < s2), 1);

  (* 2 chars - triggers 2nd iteration which was unaligned *)
  s1 := "AB";
  s2 := "AB";
  Check("AB=AB", BoolInt(s1 = s2), 1);

  s2 := "AC";
  Check("AB<AC", BoolInt(s1 < s2), 1);

  (* 3 chars *)
  s1 := "XYZ";
  s2 := "XYZ";
  Check("XYZ=XYZ", BoolInt(s1 = s2), 1);

  (* 4 chars - word boundary *)
  s1 := "ABCD";
  s2 := "ABCD";
  Check("ABCD=ABCD", BoolInt(s1 = s2), 1);

  s2 := "ABCE";
  Check("ABCD<ABCE", BoolInt(s1 < s2), 1);

  (* 5 chars - crosses word boundary *)
  s1 := "Hello";
  s2 := "Hello";
  Check("Hello=Hello(5)", BoolInt(s1 = s2), 1)
 END TestLengthVariations;

 PROCEDURE TestLongerStrings;
  VAR s1, s2: ARRAY 64 OF CHAR;
 BEGIN
  O.String("--- Longer Strings ---"); O.Ln;
  (* 13 chars - odd length *)
  s1 := "ARM Native 12";
  s2 := "ARM Native 12";
  Check("13ch equal", BoolInt(s1 = s2), 1);

  (* 14 chars - even length, was problematic with halfword promotion *)
  s1 := "ARM Native 123";
  s2 := "ARM Native 123";
  Check("14ch equal", BoolInt(s1 = s2), 1);

  s2 := "ARM Native 124";
  Check("14ch differ", BoolInt(s1 < s2), 1);

  (* 15 chars *)
  s1 := "ARM Native12345";
  s2 := "ARM Native12345";
  Check("15ch equal", BoolInt(s1 = s2), 1);

  (* 16 chars - 4-word aligned *)
  s1 := "0123456789ABCDEF";
  s2 := "0123456789ABCDEF";
  Check("16ch equal", BoolInt(s1 = s2), 1);

  s2 := "0123456789ABCDEG";
  Check("16ch last diff", BoolInt(s1 < s2), 1)
 END TestLongerStrings;

 PROCEDURE TestConstantCmp;
  VAR s: ARRAY 32 OF CHAR;
 BEGIN
  O.String("--- Constant Compare ---"); O.Ln;
  s := "Kernel";
  Check("s=Kernel", BoolInt(s = "Kernel"), 1);
  Check("s#Other", BoolInt(s # "Other"), 1);
  Check("s>Aaa", BoolInt(s > "Aaa"), 1);
  Check("s<Zzzz", BoolInt(s < "Zzzz"), 1)
 END TestConstantCmp;

 PROCEDURE TestEmptyStr;
  VAR s1, s2: ARRAY 16 OF CHAR;
 BEGIN
  O.String("--- Empty String ---"); O.Ln;
  s1 := "";
  s2 := "";
  Check("empty=empty", BoolInt(s1 = s2), 1);

  s2 := "A";
  Check("empty<A", BoolInt(s1 < s2), 1);
  Check("A>empty", BoolInt(s2 > s1), 1)
 END TestEmptyStr;

BEGIN
 pass := 0; fail := 0;
 O.String("=== TestStrCmp: String Comparison ==="); O.Ln;
 TestBasicCmp;
 TestLengthVariations;
 TestLongerStrings;
 TestConstantCmp;
 TestEmptyStr;
 O.Ln;
 O.String("TestStrCmp: "); O.Int(pass, 0);
 O.String(" passed, "); O.Int(fail, 0);
 O.String(" failed"); O.Ln;
 O.Exit(fail)
END TestStrCmp.
