gcc *.c ../system/*.c ./system/*.c ./arm32/*.c ../tools/driver.c -I. -Isystem -Iarm32 -lm -lgc -std=c99 -O2 -o op2
