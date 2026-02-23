MODULE MainLoop;

IMPORT RawOut;

PROCEDURE Run;
VAR time, count: LONGINT;
BEGIN
 count := 0;
 time := 0;
 LOOP
   IF time = 10000000 THEN
     RawOut.String("tick ");
     RawOut.Int(count,6);
     RawOut.Ln;
     time := 0;
     INC(count);
   END;
   INC(time);
 END
END Run;

BEGIN
  Run
END MainLoop.
