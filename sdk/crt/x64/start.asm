; SPDX-License-Identifier: GPL-3.0-or-later

bits 64

section .text

global ZiCrtStart
global ZiCrtInvokeMain
extern ZiCrtStartC
extern main

ZiCrtStart:
    cld
    sub rsp, 40
    call ZiCrtStartC
.unexpected_return:
    pause
    jmp .unexpected_return

; The implementation invokes either standard form of main through the common
; Microsoft x64 machine-level contract. A main(void) simply ignores RCX/RDX.
ZiCrtInvokeMain:
    sub rsp, 40
    call main
    add rsp, 40
    ret
