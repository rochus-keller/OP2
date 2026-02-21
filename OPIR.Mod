(* OPIR - Intermediate Representation for the OP2 compiler *)
(* Defines the pseudo-RISC instruction set opcodes and pseudo registers *)
(* These definitions are target-independent and shared between the code generator (OPC) *)
(* and the target-specific lowering modules (e.g. OPL for i386) *)

MODULE OPIR;

 CONST
  (* opcode of pseudo RISC processor *)
  (* integer operations *)
  ld* = 32; ldbdw* = 64; ldwdw* = 96; ldbw* = 128; 
  ldbdwu* = 160; ldwdwu* = 196; ldbwu* = 224; getReg* = 256 ;
  putReg* = 288; ldProc* = 320; ldXProc* = 352; lea* = 384; 
  store* = 416; push* = 448; pop* = 480; add* = 512; 
  sub* = 544; mul* = 576; div* = 608; mod* = 640; 
  neg*= 960; abs* = 992; cmp* = 1056; je* = 1504; 
  jne* = 1536; jl* = 1568; jle* = 1600; jg* = 1632; 
  jge* = 1664; ja* = 1696; jae* = 1728; jb* = 1760; 
  jbe* = 1792; jc* = 1824; jnc* = 1856; jmp* = 1888; 
  jmpReg* = 1920; sete* = 1120; setne* = 1152; setl* = 1184; 
  setle* = 1216; setg* = 1248; setge* = 1280; seta* = 1312; 
  setae* = 1344; setb* = 1376; setbe* = 1408; setc* = 1440; 
  setnc* = 1472; te* = 1952; tne* = 1984; tle* = 2944;
  ta* = 2016; tae* = 2880; to* = 2912; 
  trap* = 2048; or* = 672; xor* = 704; and* = 736; 
  not* = 1024; bt* = 1088; btr* = 768; bts* = 800; test* = 3424;
  call* = 2080; callReg* = 2112; xcall* = 2144; ret* = 2176; 
  enter* = 2208; leave* = 2240; sal* = 832; sar* = 864; 
  shr* = 896; rol* = 928; cld* = 2272; repMovs* = 2304; 
  cmpString* = 2336; pushReg* = 2368; popReg* = 2400; case* = 2432; 
  short* = 2976; phi* = 2464; label* = 2496; entier* = 3104;
  cli* = 3168; sti* = 3200; in* = 3232; out* = 3264;
  assembler* = 3296;
  clear*= 3328; std*= 3392;

  (* floating point operations *)
  fload*= 2528; fstore* = 2560; fist*= 2592; fild* = 2624;
  fadd* = 2656; fsub* = 2688; fmul* = 2720; fdiv* = 2752;
  fabs* = 2784; fchs* = 2816; fcmp* = 2848;

  newStat* = 3136;

  (* predefined registers of the pseudo RISC machine *)
  none* = -1; FP* = -2; SP* = -3;

  (* hints for the pseudo machine *)
  noHint* = -1;

END OPIR.
