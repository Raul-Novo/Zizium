; SPDX-License-Identifier: GPL-3.0-or-later
;
; Essential x64 instructions which C17 cannot express portably. The normal
; callable surface follows the Microsoft x64 ABI.

bits 64
default rel

section .text

global ZkArchCpuid
global ZkArchReadMsr
global ZkArchWriteMsr
global ZkArchReadTimestamp
global ZkArchReadCr2
global ZkArchReadCr3
global ZkArchLoadCr3
global ZkArchInvalidatePage
global ZkArchMemoryBarrier
global ZkArchEnablePagingProtections
global ZkArchSwitchStackAndCall
global ZkArchDisableInterrupts
global ZkArchRestoreInterrupts
global ZkArchEnableInterrupts
global ZkArchLoadGdt
global ZkArchLoadIdt
global ZkArchSaveFxState
global ZkArchTriggerInvalidOpcode
global ZkArchTriggerPageFault
global __chkstk

extern ZkArchHalt

ZkArchCpuid:
    push rbx
    mov r10, r8
    mov eax, ecx
    mov ecx, edx
    cpuid
    mov [r10], eax
    mov [r10 + 4], ebx
    mov [r10 + 8], ecx
    mov [r10 + 12], edx
    pop rbx
    ret

ZkArchReadMsr:
    rdmsr
    shl rdx, 32
    or rax, rdx
    ret

ZkArchWriteMsr:
    mov r8, rdx
    mov eax, r8d
    shr r8, 32
    mov edx, r8d
    wrmsr
    ret

ZkArchReadTimestamp:
    rdtsc
    shl rdx, 32
    or rax, rdx
    ret

ZkArchReadCr2:
    mov rax, cr2
    ret

ZkArchReadCr3:
    mov rax, cr3
    ret

ZkArchLoadCr3:
    mov cr3, rcx
    ret

ZkArchInvalidatePage:
    invlpg [rcx]
    ret

ZkArchMemoryBarrier:
    mfence
    ret

ZkArchEnablePagingProtections:
    mov rax, cr0
    bts rax, 16
    mov cr0, rax
    mov rax, cr4
    bts rax, 7
    mov cr4, rax
    ret

; RCX is the new stack top, RDX the callback, and R8 its single argument.
; The callback is required not to return.
ZkArchSwitchStackAndCall:
    mov r11, rdx
    mov rax, r8
    mov rsp, rcx
    and rsp, -16
    sub rsp, 32
    mov rcx, rax
    call r11
    jmp ZkArchHalt

ZkArchDisableInterrupts:
    pushfq
    pop rax
    cli
    ret

ZkArchRestoreInterrupts:
    test rcx, 0x200
    jz .keep_disabled
    sti
    ret
.keep_disabled:
    cli
    ret

ZkArchEnableInterrupts:
    sti
    ret

; RCX is the descriptor base, DX the inclusive limit, and R8W the TSS selector.
ZkArchLoadGdt:
    sub rsp, 16
    mov [rsp], dx
    mov [rsp + 2], rcx
    lgdt [rsp]

    mov ax, 0x10
    mov ds, ax
    mov es, ax
    mov ss, ax
    xor eax, eax
    mov fs, ax
    mov gs, ax

    push qword 0x08
    lea rax, [rel .code_reloaded]
    push rax
    retfq
.code_reloaded:
    mov ax, r8w
    ltr ax
    add rsp, 16
    ret

; RCX is the table base and DX is its inclusive limit.
ZkArchLoadIdt:
    sub rsp, 16
    mov [rsp], dx
    mov [rsp + 2], rcx
    lidt [rsp]
    add rsp, 16
    ret

ZkArchSaveFxState:
    fxsave64 [rcx]
    ret

; Microsoft x64 stack-probe helper. RAX contains the pending allocation size
; and must remain intact for the caller's subsequent subtraction from RSP.
; R10 and R11 are volatile. Touching every intervening page makes a kernel
; guard-page overflow deterministic instead of skipping across the guard.
__chkstk:
    lea r11, [rsp + 8]
    mov r10, rax
.probe_page:
    cmp r10, 0x1000
    jbe .probe_tail
    sub r11, 0x1000
    test byte [r11], 0
    sub r10, 0x1000
    jmp .probe_page
.probe_tail:
    sub r11, r10
    test byte [r11], 0
    ret

ZkArchTriggerInvalidOpcode:
    ud2
    int3

ZkArchTriggerPageFault:
    mov rax, 0x0000400000000000
    mov rax, [rax]
    ud2
