; SPDX-License-Identifier: GPL-3.0-or-later
;
; The SYSCALL boundary is the only direct transition from untrusted Ring 3
; state. It captures every input before reuse, switches to a trusted stack,
; and returns only after C policy has validated the complete frame.

bits 64
default rel

%define ZI_CPU_KERNEL_STACK_TOP 8
%define ZI_CPU_KERNEL_CR3 16
%define ZI_CPU_RESUME_RSP 24
%define ZI_CPU_RESUME_RIP 32
%define ZI_CPU_USER_RSP 48
%define ZI_CPU_TERMINATION_VALUE 56

%define ZI_FRAME_ACTION 8
%define ZI_FRAME_R15 16
%define ZI_FRAME_R14 24
%define ZI_FRAME_R13 32
%define ZI_FRAME_R12 40
%define ZI_FRAME_R11 48
%define ZI_FRAME_R10 56
%define ZI_FRAME_R9 64
%define ZI_FRAME_R8 72
%define ZI_FRAME_RDI 80
%define ZI_FRAME_RSI 88
%define ZI_FRAME_RBP 96
%define ZI_FRAME_RBX 104
%define ZI_FRAME_RDX 112
%define ZI_FRAME_RCX 120
%define ZI_FRAME_RAX 128
%define ZI_FRAME_NUMBER 136
%define ZI_FRAME_ARGUMENT_1 144
%define ZI_FRAME_ARGUMENT_2 152
%define ZI_FRAME_ARGUMENT_3 160
%define ZI_FRAME_ARGUMENT_4 168
%define ZI_FRAME_USER_RIP 176
%define ZI_FRAME_USER_RSP 184
%define ZI_FRAME_USER_FLAGS 192
%define ZI_FRAME_RESULT 200
%define ZI_FRAME_SIZE 208
%define ZI_SHADOW_SPACE 32

section .text

global ZkX64SyscallEntry
global ZkArchRunUser
global ZkArchRunNestedUser
global ZkX64UserFaultResume
extern ZkDispatchSyscall

ZkX64SyscallEntry:
    swapgs
    mov [gs:ZI_CPU_USER_RSP], rsp
    mov rsp, [gs:ZI_CPU_KERNEL_STACK_TOP]
    sub rsp, ZI_SHADOW_SPACE + ZI_FRAME_SIZE

    mov dword [rsp + ZI_SHADOW_SPACE], ZI_FRAME_SIZE
    mov dword [rsp + ZI_SHADOW_SPACE + 4], 1
    mov dword [rsp + ZI_SHADOW_SPACE + ZI_FRAME_ACTION], 0
    mov dword [rsp + ZI_SHADOW_SPACE + 12], 0
    mov [rsp + ZI_SHADOW_SPACE + ZI_FRAME_R15], r15
    mov [rsp + ZI_SHADOW_SPACE + ZI_FRAME_R14], r14
    mov [rsp + ZI_SHADOW_SPACE + ZI_FRAME_R13], r13
    mov [rsp + ZI_SHADOW_SPACE + ZI_FRAME_R12], r12
    mov [rsp + ZI_SHADOW_SPACE + ZI_FRAME_R11], r11
    mov [rsp + ZI_SHADOW_SPACE + ZI_FRAME_R10], r10
    mov [rsp + ZI_SHADOW_SPACE + ZI_FRAME_R9], r9
    mov [rsp + ZI_SHADOW_SPACE + ZI_FRAME_R8], r8
    mov [rsp + ZI_SHADOW_SPACE + ZI_FRAME_RDI], rdi
    mov [rsp + ZI_SHADOW_SPACE + ZI_FRAME_RSI], rsi
    mov [rsp + ZI_SHADOW_SPACE + ZI_FRAME_RBP], rbp
    mov [rsp + ZI_SHADOW_SPACE + ZI_FRAME_RBX], rbx
    mov [rsp + ZI_SHADOW_SPACE + ZI_FRAME_RDX], rdx
    mov [rsp + ZI_SHADOW_SPACE + ZI_FRAME_RCX], rcx
    mov [rsp + ZI_SHADOW_SPACE + ZI_FRAME_RAX], rax
    mov [rsp + ZI_SHADOW_SPACE + ZI_FRAME_NUMBER], rax
    mov [rsp + ZI_SHADOW_SPACE + ZI_FRAME_ARGUMENT_1], r10
    mov [rsp + ZI_SHADOW_SPACE + ZI_FRAME_ARGUMENT_2], rdx
    mov [rsp + ZI_SHADOW_SPACE + ZI_FRAME_ARGUMENT_3], r8
    mov [rsp + ZI_SHADOW_SPACE + ZI_FRAME_ARGUMENT_4], r9
    mov [rsp + ZI_SHADOW_SPACE + ZI_FRAME_USER_RIP], rcx
    mov rax, [gs:ZI_CPU_USER_RSP]
    mov [rsp + ZI_SHADOW_SPACE + ZI_FRAME_USER_RSP], rax
    mov [rsp + ZI_SHADOW_SPACE + ZI_FRAME_USER_FLAGS], r11
    mov qword [rsp + ZI_SHADOW_SPACE + ZI_FRAME_RESULT], 0

    lea rcx, [rsp + ZI_SHADOW_SPACE]
    call ZkDispatchSyscall
    lea rdx, [rsp + ZI_SHADOW_SPACE]
    cmp dword [rdx + ZI_FRAME_ACTION], 1
    je .terminate
    cmp dword [rdx + ZI_FRAME_ACTION], 0
    jne .terminate

    mov r15, [rdx + ZI_FRAME_R15]
    mov r14, [rdx + ZI_FRAME_R14]
    mov r13, [rdx + ZI_FRAME_R13]
    mov r12, [rdx + ZI_FRAME_R12]
    mov r10, [rdx + ZI_FRAME_R10]
    mov r9, [rdx + ZI_FRAME_R9]
    mov r8, [rdx + ZI_FRAME_R8]
    mov rdi, [rdx + ZI_FRAME_RDI]
    mov rsi, [rdx + ZI_FRAME_RSI]
    mov rbp, [rdx + ZI_FRAME_RBP]
    mov rbx, [rdx + ZI_FRAME_RBX]
    mov rax, [rdx + ZI_FRAME_RESULT]
    mov rcx, [rdx + ZI_FRAME_USER_RIP]
    mov r11, [rdx + ZI_FRAME_USER_FLAGS]
    lfence
    mov rsp, [rdx + ZI_FRAME_USER_RSP]
    mov rdx, [rdx + ZI_FRAME_RDX]
    swapgs
    o64 sysret

.terminate:
    mov rax, [rdx + ZI_FRAME_RESULT]
    mov [gs:ZI_CPU_TERMINATION_VALUE], rax
    mov r10, [gs:ZI_CPU_KERNEL_CR3]
    mov cr3, r10
    mov rsp, [gs:ZI_CPU_RESUME_RSP]
    mov r10, [gs:ZI_CPU_RESUME_RIP]
    swapgs
    jmp r10

; Microsoft x64: RCX entry, RDX user RSP, R8 process CR3, R9 CPU state,
; and the fifth argument at [RSP+40] is the process-parameter address.
ZkArchRunUser:
    mov r11, rcx
    mov r10, [rsp + 40]
    push rbx
    push rbp
    push rsi
    push rdi
    push r12
    push r13
    push r14
    push r15
    mov [r9 + ZI_CPU_RESUME_RSP], rsp
    lea rax, [rel .user_return]
    mov [r9 + ZI_CPU_RESUME_RIP], rax
    mov rax, cr3
    mov [r9 + ZI_CPU_KERNEL_CR3], rax
    mov cr3, r8
    push qword 0x1b
    push rdx
    push qword 0x202
    push qword 0x23
    push r11
    mov rcx, r10
    iretq
.user_return:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbp
    pop rbx
    ret

; A nested child is entered while its parent syscall has kernel GS active.
; Restore the user GS state around the ordinary entry helper, then restore the
; parent's kernel GS state before C resumes its syscall dispatch.
ZkArchRunNestedUser:
    mov rax, [rsp + 40]
    sub rsp, 40
    mov [rsp + 32], rax
    swapgs
    call ZkArchRunUser
    swapgs
    add rsp, 40
    ret

; A user exception returns through IRET to this trusted same-ring trampoline.
ZkX64UserFaultResume:
    swapgs
    mov rax, [gs:ZI_CPU_TERMINATION_VALUE]
    mov r10, [gs:ZI_CPU_KERNEL_CR3]
    mov cr3, r10
    mov rsp, [gs:ZI_CPU_RESUME_RSP]
    mov r10, [gs:ZI_CPU_RESUME_RIP]
    swapgs
    jmp r10
