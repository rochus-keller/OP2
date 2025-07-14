MODULE Oberon;

  IMPORT Texts, Display;
  
  CONST

    (** Message ids: *)
    defocus* = 0; neutralize* = 1; mark* = 2; (** ControlMsg*)
    consume* = 0; track* = 1; (** InputMsg*)
    get* = 0; set* = 1; reset* = 2; (** CaretMsg id, SelectMsg id*)
    drop* = 0; integrate* = 1; (** ConsumeMsg id*)
    
  TYPE
    CaretMsg* = RECORD (Display.FrameMsg)	(** Text caret handling. *)
      id*: INTEGER;	(** get, set, reset *)
      car*: Display.Frame;	(** Destination frame, returned frame. *)
      text*: Texts.Text;	(** Text represented by car. *)
      pos*: LONGINT	(** Caret position. *)
    END;
    
    ControlMsg* = RECORD (Display.FrameMsg)
      id*: INTEGER;	(** defocus, neutralize, mark (with F1) *)
      X*, Y*: INTEGER	(** Absolute mark position. *)
    END;

  	Cursor* = RECORD
  	    on*: BOOLEAN;	(** Is cursor shown? *)
  	    X*, Y*: INTEGER	(** Absolute cursor position. *)
  	END;
	
	  ParList* = POINTER TO ParRec;

    ParRec* = RECORD	(** Area for passing command parameters. *)
      text*: Texts.Text;	(** Text parameter to be passed to command. *)
      pos*: LONGINT	(** Starting position in text of parameter. *)
    END;
    
  VAR
    Log*: Texts.Text;	(** The Oberon log. *)
	  OptionChar*: CHAR;
	  Pointer*: Cursor;
    Par*: ParList;	(** Actual parameters of executed command. *)

 (** Fade cursor if visible. *)
 	PROCEDURE FadeCursor* (VAR c: Cursor);
  BEGIN (* TODO *)
  END FadeCursor;
 
(** Returns the selected stretch [beg, end[ of the current selected text T. 
Time indicates the time of selection; time < 0 indicate that no text is currently selected. *)
    PROCEDURE GetSelection* (VAR text: Texts.Text; VAR beg, end, time: LONGINT);
    BEGIN (* TODO *)
    END GetSelection; 
    
    PROCEDURE MarkedText*(): Texts.Text;
    BEGIN (* TODO *)
      RETURN NIL
    END MarkedText;
    
    PROCEDURE MarkedFrame*():Display.Frame;
    BEGIN (* TODO *)
      RETURN NIL
    END MarkedFrame;
   
PROCEDURE OpenText*(str: ARRAY OF CHAR; t: Texts.Text; w, h: INTEGER);
BEGIN (* TODO *)
END OpenText;

PROCEDURE Collect*;
BEGIN (* TODO *)
END Collect;

PROCEDURE OpenScanner*(s: Texts.Scanner; str: ARRAY OF CHAR);
BEGIN (* TODO *)
END OpenScanner;

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
