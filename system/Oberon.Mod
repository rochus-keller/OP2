MODULE Oberon;

  IMPORT Texts;

TYPE
  ParList* = POINTER TO RECORD END;
  
VAR
  Log*: Texts.Text;	(** The Oberon log. *)
  Par*: ParList;	

PROCEDURE Collect*;
BEGIN (* TODO *)
END Collect;

(** Execute an Oberon command. Name should be a string of the form 
"M.P", where M is the module and P is the procedure of the command. 
Par is the command parameter record; it will be assigned to Oberon.Par 
so that the command can pick up its parameters. The new flag indicates 
if the module M should be reloaded from disk (obly possible if M is a "top" 
module, i.e. it has no clients. Res indicates success (res = 0) or failure (res # 0). *)
PROCEDURE Call* (name: ARRAY OF CHAR; par: ParList; new: BOOLEAN; VAR res: INTEGER);
BEGIN (* TODO *)
END Call;

END Oberon.
