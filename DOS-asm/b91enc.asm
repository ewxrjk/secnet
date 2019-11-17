; basE91 encoder for DOS
;
; Copyright (c) 2005-2006 Joachim Henke
; All rights reserved.
;
; Redistribution and use in source and binary forms, with or without
; modification, are permitted provided that the following conditions are met:
;
;  - Redistributions of source code must retain the above copyright notice,
;    this list of conditions and the following disclaimer.
;  - Redistributions in binary form must reproduce the above copyright notice,
;    this list of conditions and the following disclaimer in the documentation
;    and/or other materials provided with the distribution.
;  - Neither the name of Joachim Henke nor the names of his contributors may
;    be used to endorse or promote products derived from this software without
;    specific prior written permission.
;
; THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
; AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
; IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
; ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
; LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
; CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
; SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
; INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
; CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
; ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
; POSSIBILITY OF SUCH DAMAGE.

bits 16
cpu 8086
org 256

	xor sp, sp
	mov si, ld_0	; create lookup table
	mov bp, 90
lc_0:
	mov bx, 90
	mov ah, [bp + si]
lc_1:
	mov al, [bx + si]
	push ax
	dec bx
	jns lc_1
	dec bp
	jns lc_0

	inc bx
	mov sp, a_stck
lc_2:
	push bx
	push bx
	jmp short lc_5
lc_3:
	mov ax, [si]
	cmp cl, 6	; bits in queue + 8 < 14?
	sbb dx, dx
	inc si
	mov ch, ah
	add bp, dx
	sbb dx, dx
	xor ch, al
	and ah, dl
	and ch, dl
	sub si, dx
	xor ch, al
	shl ax, cl
	add cl, 8
	or bx, ax
	test bp, bp
	js lc_4

	and bh, 0x1F	; keep 13 bits
	and dl, 8
	and ah, 0x3F
	cmp bx, byte 89	; value in bit queue < 89?
	sbb al, al
	add dl, cl
	and ah, al
	mov cl, 13
	or bh, ah	; take 13 or 14 bits
	sub cl, al
	add bx, bx
	mov ax, [bx + a_ltab]
	mov bx, cx
	add cl, 16
	sub cl, dl
	sub dl, bl
	shr bx, cl	; restore bit queue
	mov cl, dl
	stosw
	dec bp
	jns lc_3
lc_4:
	push bx
	mov ah, 0x40
	push cx
	mov bx, 1
	lea cx, [di - a_obuf]
	mov dx, a_obuf
	int 0x21	; write to standard output

	dec bx
lc_5:
	mov ah, 0x3F
	mov cx, s_ibuf
	mov dx, a_ibuf
	int 0x21	; read from standard input

	cld
	pop cx
	mov si, dx
	mov di, a_obuf
	pop bx
	add bp, ax	; ax = 0 -> EOF
	jc lc_3

	push ax
	test cl, cl
	jz lc_6

	cmp bx, byte 91	; value in bit queue < 91?
	sbb dx, dx
	cmp cl, 8	; less than 8 bits in queue?
	sbb cx, cx
	add bx, bx
	and cx, dx
	mov dx, a_obuf
	mov ax, [bx + a_ltab]
	inc cx
	mov bx, 1
	inc cx
	stosw
	mov ah, 0x40
	int 0x21	; write out 1 or 2 bytes
lc_6:
	retn	; exit program
ld_0:
	db 'ABCDEFGHIJKLM'
	db 'NOPQRSTUVWXYZ'
	db 'abcdefghijklm'
	db 'nopqrstuvwxyz'
	db '0123456789!#$'
	db '%&()*+,./:;<='
	db '>?@[]^_`{|}~"'


a_stck equ ((lc_2 - $$) + 256) & 510
a_ltab equ 48974
a_obuf equ ((ld_0 - $$) + 257) & 510
s_ibuf equ ((a_ltab - a_obuf - 2) << 4) / 29
a_ibuf equ a_ltab - s_ibuf
