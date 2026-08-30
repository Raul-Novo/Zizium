; SPDX-License-Identifier: GPL-3.0-or-later
;
; Limine enters using the x86-64 System V ABI. This leaf bridge supplies the
; Microsoft x64 shadow space and alignment expected by every Zizium C routine.

bits 64
default rel

section .text

global ZkBootEntry
global ZkArchOut8
global ZkArchIn8
global ZkArchPause
global ZkArchHalt
global ZkArchBootstrapStackTop
extern ZkKernelMain

ZkBootEntry:
    cli
    cld
    ; Base revision 6 deliberately leaves x86 SIMD disabled. Microsoft x64 C
    ; assumes SSE2, which every x86-64 processor provides, so enable the OS
    ; support bits before crossing into any C routine.
    mov rax, cr0
    and rax, ~4
    or rax, 2
    mov cr0, rax
    mov rax, cr4
    or rax, 0x600
    mov cr4, rax
    lea rsp, [rel ZkBootstrapStackTopValue]
    and rsp, -16
    sub rsp, 32
    call ZkKernelMain
    jmp ZkArchHalt

; Microsoft x64: RCX is the port and RDX is the byte value.
ZkArchOut8:
    mov eax, edx
    mov dx, cx
    out dx, al
    ret

ZkArchIn8:
    mov dx, cx
    xor eax, eax
    in al, dx
    ret

ZkArchPause:
    pause
    ret

ZkArchBootstrapStackTop:
    lea rax, [rel ZkBootstrapStackTopValue]
    ret

ZkArchHalt:
    cli
.halt:
    hlt
    jmp .halt

section .bss align=16

ZkBootstrapStackBottom:
    resb 65536
ZkBootstrapStackTopValue:
