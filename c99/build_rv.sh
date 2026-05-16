gcc *.c ../system/*.c ./system/*.c ./rv32/*.c ../tools/driver.c -I. -Isystem -Irv32 -lm -lgc -std=c99 -O2 -o op2
