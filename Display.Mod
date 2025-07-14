MODULE Display;

TYPE
			Frame* = POINTER TO FrameDesc;	(** Base type of all displayable objects. *)
			FrameDesc* = RECORD 
				next*, dsc*: Frame;	(** Sibling, child pointers. *)
				X*, Y*, W*, H*: INTEGER	(** Coordinates. *)
			END;

			FrameMsg* = RECORD 	(** Base type of messages sent to frames. *)
				F*: Frame; (*target*)	(** Message target, NIL for broadcast. *)
				x*, y*: INTEGER;	(** Message origin. *)
				res*: INTEGER	(** Result code: <0 = error or no response, >=0 response. *)
			END;

PROCEDURE Broadcast*(VAR msg: FrameMsg);
BEGIN (* TODO *)
END Broadcast;

END Display.
