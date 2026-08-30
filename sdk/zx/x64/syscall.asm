; SPDX-License-Identifier: GPL-3.0-or-later
;
; Microsoft x64 public calls are converted to the Zizium syscall ABI by moving
; argument one from RCX to R10. RCX and R11 are clobbered by SYSCALL.

bits 64

section .text

global ZxCloseHandle
global ZxWaitForObject
global ZxExitProcess
global ZxCreateProcess
global ZxAllocateVirtualMemory
global ZxSendChannel
global ZxReceiveChannel
global ZxGetBootstrapChannel
global ZxDebugWrite

ZxCloseHandle:
    mov r10, rcx
    mov eax, 0x0000
    syscall
    ret

ZxWaitForObject:
    mov r10, rcx
    mov eax, 0x0001
    syscall
    ret

ZxExitProcess:
    mov r10, rcx
    mov eax, 0x0100
    syscall
    ret

ZxCreateProcess:
    mov r10, rcx
    mov eax, 0x0101
    syscall
    ret

ZxAllocateVirtualMemory:
    mov r10, rcx
    mov eax, 0x0200
    syscall
    ret

ZxSendChannel:
    mov r10, rcx
    mov eax, 0x0500
    syscall
    ret

ZxReceiveChannel:
    mov r10, rcx
    mov eax, 0x0501
    syscall
    ret

ZxGetBootstrapChannel:
    mov r10, rcx
    mov eax, 0x0502
    syscall
    ret

ZxDebugWrite:
    mov r10, rcx
    mov eax, 0x0900
    syscall
    ret
