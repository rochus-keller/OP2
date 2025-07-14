MODULE Texts;

IMPORT Files, Fonts;

CONST

    (** Scanner symbol classes.*)
    Inval* = 0;           (** Invalid symbol. *)
    Name* = 1;        (** Name s (of length len).*)
    String* = 2;        (** Quoted string s (length len). *)
    Int* = 3;             (** Integer i (decimal or hexadecimal). *)
    Real* = 4;          (** Real number x. *)
    LongReal* = 5;  (** Long real number y. *)
    Char* = 6;          (** Special character c. *)

    TAB = 9X; CR = 0DX;
    OldTextBlockId = 1X; OldTextSpex = 0F0X;

TYPE
    Text* = POINTER TO TextDesc;

    TextDesc* = RECORD 
      len*: LONGINT;	(** Text consists of characters 0 to T.len - 1. *)
     END;

    Buffer* = POINTER TO BufDesc;	(** Temporary container of text stretches. *)

    BufDesc* = RECORD
      len*: LONGINT;	(** # characters in buffer. *)
    END;

    Writer* = RECORD	(** Used to write a stream of textual data in a buffer. *)
      buf*: Buffer;	(** Associated buffer. *)
      col*: SHORTINT;	(** Current color of text being written. *)
      voff*: SHORTINT	(** Current vertical offset of text being written. *)
    END;
    
    Reader* = RECORD	(** Character-wise reader of a text strean. *)
      eot*: BOOLEAN;	(** Reader has reached end of the text stream. *)
      col*: SHORTINT;	(** Color index of last character read. *)
      voff*: SHORTINT;	(** vertical offset of last character read. *)
      lib*: Fonts.Font  (* stub *)
    END;

    Scanner* = RECORD (Reader)	(** Scanner for symbol streams. *)
      nextCh*: CHAR;	(** Character immediately following the last symbol scanned. *)
      line*: INTEGER;	(** # carriage returns scanned so far. *)
      class*: INTEGER;	(** Scan result: Int, Real, String etc. *)
      i*: LONGINT;
      x*: REAL;
      y*: LONGREAL;
      c*: CHAR;
      len*: SHORTINT;	(** Length of name or string scanned. *)
      s*: ARRAY 64 OF CHAR
    END;

(** Open a new writer W. *)
  PROCEDURE OpenWriter* (VAR W: Writer);
  BEGIN (* TODO *)
  END OpenWriter;

(** Write integer x to W's buffer. Spaces are padded to the left until the number field is at least n characters long. *)
PROCEDURE WriteInt* (VAR W: Writer; x, n: LONGINT);
BEGIN (* TODO *)
END WriteInt;

(** Write a hexadecimal representation of x to W's buffer. *)
PROCEDURE WriteHex* (VAR W: Writer; x: LONGINT);
BEGIN (* TODO *)
END WriteHex;

(** Write LONGREAL x in a fixed point notation. n is the overall minimal length for the output field, f the number of fraction digits following the decimal point, D the fixed exponent (printed only when D # 0). *)
PROCEDURE WriteLongRealFix* (VAR W: Writer; x: LONGREAL; n, f, D: LONGINT);
BEGIN (* TODO *)
END WriteLongRealFix;

(** Write real x in a fixed point notation. n is the overall minimal length for the output field, f the number of fraction digits following the decimal point, E the fixed exponent (printed only when E # 0). *)
PROCEDURE WriteRealFix* (VAR W: Writer; x: REAL; n, f, E: LONGINT);
BEGIN (* TODO *)
END WriteRealFix;

(** Return reader's position within the text. *)
  PROCEDURE Pos* (VAR R: Reader): LONGINT;
  BEGIN RETURN 0 (* TODO *)
  END Pos;  

(** Open text T from file specified by name. A new text is opened when name = "". *)
  PROCEDURE Open* (T: Text; name: ARRAY OF CHAR);
  BEGIN (* TODO *)
  END Open;
  
(** Open text reader R and set it up at position pos in text T. *) 
  PROCEDURE OpenReader* (VAR R: Reader; T: Text; pos: LONGINT);
  BEGIN (* TODO *)
  END OpenReader;
  
(** Open text scanner S and set it up at position pos in text T. *)
  PROCEDURE OpenScanner* (VAR S: Scanner; T: Text; pos: LONGINT);
  BEGIN (* TODO *)
  END OpenScanner;

(** Read the next symbol. Whitespace is ignored. CR increments the line counter. *)
  PROCEDURE Scan* (VAR S: Scanner);
  BEGIN (* TODO *)
  END Scan; 
  
(** Read next character into ch. R.eot is set when the end of the text is reached. The fields lib, voff and col of R give information about the last character read. *)
  PROCEDURE Read* (VAR R: Reader; VAR ch: CHAR);
  BEGIN (* TODO *)
  END Read;

(** Write string s to W's buffer. *)
  PROCEDURE WriteString* (VAR W: Writer; s: ARRAY OF CHAR);
    VAR i: INTEGER;
  BEGIN i := 0;
    WHILE s[i] # 0X DO Write(W, s[i]); INC(i) END
  END WriteString;

(** Write character ch to writer W's buffer. *)
  PROCEDURE Write* (VAR W: Writer; ch: CHAR);
  BEGIN (* TODO *)
  END Write;
  
(** Write an end-of-line character to W's buffer. *)
  PROCEDURE WriteLn* (VAR W: Writer);
  BEGIN Write(W, CR)
  END WriteLn;
  
(** Append buffer to the end of text T. B is emptied. *)
  PROCEDURE Append* (T: Text; B: Buffer);
  BEGIN (* TODO *)
  END Append;


END Texts.
