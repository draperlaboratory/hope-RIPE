# Makefile for RIPE
# @author John Wilander & Nick Nikiforakis
# Modified for RISC-V by John Merrill

#Depending on how you test your system you may want to comment, or uncomment
#the following
CFLAGS= -fno-stack-protector -z execstack
CC=riscv64-unknown-elf-gcc

all: ripe_attack_generator

clean:
	rm -rf build/ out/

ripe_attack_generator: ./source/ripe_attack_generator.c
	mkdir -p build/ out/
	$(CC) \
		./source/ripe_attack_generator.c -o ./build/ripe_attack_generator
