MODULE Texts;

IMPORT Fonts, SYSTEM;

CONST

    CR = 0DX;

TYPE
    Text* = POINTER TO RECORD END;

    Buffer* = POINTER TO BufDesc;	(** Temporary container of text stretches. *)

    BufDesc* = RECORD
      len*, cap*: LONGINT;  (* Length and Capacity of the buffer *)
      data*: SYSTEM.PTR;    (* Pointer to the C char array *)
    END;

    Writer* = RECORD	(** Used to write a stream of textual data in a buffer. *)
      buf*: Buffer;	(** Associated buffer. *)
      pos*: LONGINT;        (* Current writing position in the buffer *)
    END;
    
    Reader* = RECORD	(** Character-wise reader of a text strean. *)
      eot*: BOOLEAN;	(** Reader has reached end of the text stream. *)
      lib*: Fonts.Font;  (* stub *)
      fp: SYSTEM.PTR;       (* C File Pointer  *)
      pos: LONGINT;         (* Current file position *)
      len: LONGINT;         (* File length *)
    END;

(** Open a new writer W. *)
PROCEDURE~ OpenWriter* (VAR W: Writer); (* TODO *)

(** Write integer x to W's buffer. Spaces are padded to the left until the number field is at least n characters long. *)
PROCEDURE~ WriteInt* (VAR W: Writer; x, n: LONGINT); (* TODO *)

(** Write a hexadecimal representation of x to W's buffer. *)
PROCEDURE~ WriteHex* (VAR W: Writer; x: LONGINT); (* TODO *)

(** Open reader R from file specified by name. *) 
PROCEDURE~ OpenReader* (VAR R: Reader; name: ARRAY OF CHAR): BOOLEAN; (* TODO *) 
  
(** Return reader's position within the text. *)
PROCEDURE~ Pos* (VAR R: Reader): LONGINT; (* TODO *)

(** Read next character into ch. R.eot is set when the end of the text is reached. The fields lib, voff and col of R give information about the last character read. *)
PROCEDURE~ Read* (VAR R: Reader; VAR ch: CHAR); (* TODO *)

(** Write string s to W's buffer. *)
PROCEDURE WriteString* (VAR W: Writer; s: ARRAY OF CHAR);
  VAR i: INTEGER;
BEGIN i := 0;
  WHILE s[i] # 0X DO Write(W, s[i]); INC(i) END
END WriteString;

(** Write character ch to writer W's buffer. *)
PROCEDURE~ Write* (VAR W: Writer; ch: CHAR); (* TODO *)

(** Write an end-of-line character to W's buffer. *)
PROCEDURE WriteLn* (VAR W: Writer);
BEGIN Write(W, CR)
END WriteLn;

(** Append buffer to the end of text T. B is emptied. *)
PROCEDURE~ Append* (T: Text; B: Buffer); (* TODO *)

END Texts.
