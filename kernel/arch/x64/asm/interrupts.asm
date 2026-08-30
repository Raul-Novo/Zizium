; SPDX-License-Identifier: GPL-3.0-or-later
;
; Per-vector entry is generated to keep the hardware frame exact. All policy,
; decoding, scheduling, and diagnostics remain in C.

bits 64
default rel

section .text

global ZkArchSetActiveFxState
extern ZkX64InterruptDispatch
extern ZkX64UserFaultResume

ZkArchSetActiveFxState:
    mov [rel ZkX64ActiveFxState], rcx
    ret

%assign zi_vector 0
%rep 256
global ZkX64InterruptStub%+zi_vector
ZkX64InterruptStub%+zi_vector:
%if zi_vector = 8 || zi_vector = 10 || zi_vector = 11 || zi_vector = 12 || zi_vector = 13 || zi_vector = 14 || zi_vector = 17 || zi_vector = 21 || zi_vector = 29 || zi_vector = 30
    push qword zi_vector
%else
    push qword 0
    push qword zi_vector
%endif
    jmp ZkX64InterruptCommon
%assign zi_vector zi_vector + 1
%endrep

ZkX64InterruptCommon:
    cld
    push rax
    push rcx
    push rdx
    push rbx
    push rbp
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15

    mov r12, rsp
    mov rax, [rel ZkX64ActiveFxState]
    test rax, rax
    jz .state_saved
    fxsave64 [rax]
.state_saved:

    and rsp, -16
    sub rsp, 32
    mov rcx, r12
    call ZkX64InterruptDispatch
    test rax, rax
    cmovz rax, r12
    mov r13, rax

    mov rax, [rel ZkX64ActiveFxState]
    test rax, rax
    jz .state_restored
    fxrstor64 [rax]
.state_restored:
    cmp qword [r13 + 120], -1
    je ZkX64UserFaultResume
    mov rsp, r13

    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rbp
    pop rbx
    pop rdx
    pop rcx
    pop rax
    add rsp, 16
    iretq

section .rdata align=8

global ZkX64InterruptStubTable
ZkX64InterruptStubTable:
%assign zi_vector 0
%rep 256
    dq ZkX64InterruptStub%+zi_vector
%assign zi_vector zi_vector + 1
%endrep

section .data align=8

ZkX64ActiveFxState:
    dq 0
