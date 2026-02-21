MODULE Files;

IMPORT SYSTEM;

TYPE
  File*   = POINTER TO RECORD END;	(** A file descriptor *)
		Rider* = RECORD 	
				eof*: BOOLEAN;	(** Rider has reached the end of the file. *)
				res*: LONGINT;  
    file: File;     (* Internal handle to the open file *)
    pos:  LONGINT;  (* Current byte offset *)
		END ;
    
(** Writes a byte into the file at the Rider position, advancing the Rider by one. *)
PROCEDURE~ Write*(VAR r: Rider; x: SYSTEM.BYTE); (* TODO *)

PROCEDURE WriteLInt*(VAR R: Rider; x: LONGINT);
BEGIN WriteBytes(R, x, 4)
END WriteLInt;

PROCEDURE WriteInt*(VAR R: Rider; x: INTEGER);
BEGIN Write(R, SHORT(x)); Write(R, SHORT(x DIV 100H))
END WriteInt;

PROCEDURE WriteSet*(VAR R: Rider; x: SET);
BEGIN WriteBytes(R, x, 4)
END WriteSet;

PROCEDURE WriteReal*(VAR R: Rider; x: REAL);
BEGIN WriteBytes(R, x, 4)
END WriteReal;

PROCEDURE WriteLReal*(VAR R: Rider; x: LONGREAL);
BEGIN WriteBytes(R, x, 8)
END WriteLReal;

(** Writes a number in a compressed format. *)
PROCEDURE WriteNum*(VAR R: Rider; x: LONGINT);
BEGIN
 WHILE (x < - 64) OR (x > 63) DO Write(R, CHR(x MOD 128 + 128)); x := x DIV 128 END;
 Write(R, CHR(x MOD 128))
END WriteNum;

(** Writes the buffer x containing n bytes into a file at the Rider position. *)
PROCEDURE~ WriteBytes*(VAR r: Rider; VAR x: ARRAY OF SYSTEM.BYTE; n: LONGINT); (* TODO *)

(** Open an existing file. The same file descriptor is returned if a file is opened multiple times. *)
PROCEDURE~ Old*(name: ARRAY OF CHAR): File; (* TODO *)

(** Positions a Rider at a certain position in a file. Multiple Riders can be positioned 
at different locations in a file. A Rider cannot be positioned beyond the end of a file. *)
PROCEDURE~ Set*(VAR r: Rider; f: File; pos: LONGINT); (* TODO *)

(** Read a byte from a file, advancing the Rider one byte further. R.eof indicates if the end 
of the file has been reached. *)
PROCEDURE~ Read*(VAR r: Rider; VAR x: SYSTEM.BYTE); (* TODO *)

PROCEDURE ReadInt*(VAR R: Rider; VAR x: INTEGER);
	VAR x0, x1: SHORTINT;
BEGIN Read(R, x0); Read(R, x1);
	x := LONG(x1) * 100H + LONG(x0) MOD 100H
END ReadInt;

PROCEDURE ReadString*(VAR R: Rider; VAR x: ARRAY OF CHAR);
	VAR i: INTEGER; ch: CHAR;
BEGIN i := 0;
	LOOP
		Read(R, ch); x[i] := ch; INC(i);
		IF ch = 0X THEN EXIT END;
		IF i = LEN(x) THEN x[i-1] := 0X;
			REPEAT Read(R, ch) UNTIL ch = 0X;
			EXIT
		END
	END
END ReadString;

PROCEDURE ReadReal*(VAR R: Rider; VAR x: REAL);
BEGIN ReadBytes(R, x, 4)
END ReadReal;

PROCEDURE ReadSet*(VAR R: Rider; VAR x: SET);
BEGIN ReadBytes(R, x, 4)
END ReadSet;

(** Reads a number in compressed variable length notation using the minimum amount of bytes. *)
PROCEDURE~ ReadNum*(VAR R: Rider; VAR x: LONGINT); (* TODO *)

(** Flushes the changes made to a file to disk. Register will automatically Close a file. *) 
PROCEDURE~ Close*(f: File); (* TODO *)

PROCEDURE ReadLReal*(VAR R: Rider; VAR x: LONGREAL);
BEGIN ReadBytes(R, x, 8)
END ReadLReal;

(** Reads a sequence of length n bytes into the buffer x, advancing the Rider. Less bytes 
will be read when reading over the length of the file. r.res indicates the number of unread bytes. *)
PROCEDURE~ ReadBytes*(VAR r: Rider; VAR x: ARRAY OF SYSTEM.BYTE; n: LONGINT); (* TODO *)

(** Returns the offset of a Rider positioned on a file. *)
PROCEDURE~ Pos*(VAR r: Rider): LONGINT; (* TODO *)

(** Returns the current length of a file. *)
PROCEDURE~ Length*(f: File): LONGINT; (* TODO *)

(** Returns the File a Rider is based on. *)
PROCEDURE~ Base*(VAR r: Rider): File; (* TODO *)

(** Register a file created with New in the directory, replacing the previous file in the 
directory with the same name. The file is automatically closed. *)
PROCEDURE~ Register*(f: File); (* TODO *)

(** Creates a new file with the specified name. *)
PROCEDURE~ New*(name: ARRAY OF CHAR): File; (* TODO *)

END Files.
