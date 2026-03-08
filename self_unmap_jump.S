.text
.globl self_unmap_and_jump
.type self_unmap_and_jump, @function

self_unmap_and_jump:
    # rdi = parasite_start, rsi = parasite_size, rdx = target_rip, rcx = target_rsp
    mov %rcx, %r15      # save target rsp
    mov %rdx, %r14      # save target rip
    mov $11, %rax       # SYS_munmap
    syscall             # unmap ourselves (clobbers rcx and r11)
    mov %r15, %rsp      # restore target stack pointer
    jmp *%r14           # jump to restored RIP — parasite is gone
