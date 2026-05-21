section .data
    wSystemCall dd 0

section .text
global HellsGate
global HellDescent

HellsGate:
    mov dword [rel wSystemCall], 0
    mov dword [rel wSystemCall], ecx
    ret

HellDescent:
    mov r10, rcx
    mov eax, [rel wSystemCall]
    syscall
    ret