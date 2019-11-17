This is a compact 16-bit assembly implementation of the basE91 encoder for DOS.
It encodes from standard input to standard output. Minimum system requirements:
DOS 2.0, 8086 processor

Example usage:

	b91enc < file.bin > file.b91


Assemble with NASM [http://nasm.sourceforge.net/]:

	nasm -O2 -o b91enc.com b91enc.asm
