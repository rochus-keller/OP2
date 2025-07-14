MODULE Modules;

TYPE
  Module* = POINTER TO RECORD END;
  
VAR
  extension*: ARRAY 32 OF CHAR;

PROCEDURE FindMod*(name: ARRAY OF CHAR):Module;
BEGIN (* TODO *)
  RETURN NIL
END FindMod;

END Modules.
