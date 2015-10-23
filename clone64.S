#include <asm/mman.h>
#include <asm/unistd.h>

#ifndef __aarch64__
#error  This is Aarch64 source.
#endif

/* int clone(int clone_flags, void *(*func)(void *), void *func_arg, size_t stack_size); 
   Returns -1 on error, cloned tid otherwise. */
.text
.align 4
clone:
	mov	x7, x8
	stp	x0, x3, [sp,-16]		/* flag, stack_size */
	stp	x2, x1, [sp,-32]		/* func_arg, func */
	mov	x0, xzr				/* pref addr */
	mov	x1, x3				/* stack size */
	mov	x2, (PROT_READ|PROT_WRITE|PROT_EXEC)
	mov	x3, (MAP_ANONYMOUS|MAP_PRIVATE|MAP_NORESERVE)
	mov	x4, -1				/* fd */
	mov	x5, xzr				/* offs */
	mov	x8, __NR_mmap			
	svc	0				/* allocate stack */
	cmn	x0, 1
	b.eq	.parent_or_error
	mov	x4, x0
	ldp	x2, x3, [sp,-32]		/* func_arg, func */
	ldp	x0, x5, [sp,-16]		/* flags, stack_size */
	add	x1, x4, x5			/* top of stack */	
	str	x4, [sp,-16]			/* stack_base [, stack_size] */
	stp	x4, x5, [x1,-16]!		/* stack_base, stack_size to child stack */
	stp	x2, x3, [x1,-16]!		/* func_arg, func to child stack */
	mov	x8, __NR_clone
	svc	0
	cbnz	x0, .parent_or_error
	ldp	x0, x1, [sp]			/* func_arg, func */
	blr	x1	
	mov	x5, x0				/* exit code */
	ldp	x0, x1, [sp,16]			/* stack_base, stack_size */
	mov	x8, __NR_munmap
	svc	0
	mov	x0, x5
	mov	x8, __NR_exit
	svc	0
   .parent_or_error:
	mov	x8, x7
	brk	0	
	ret					/* not reached */
clone_size:
	.word . - clone

.align  4
spawn:
	stp	x7, x8, [sp,-16]!
	mov	x0, xzr
	mov	x1, xzr
	mov	x2, xzr
	mov	x3, xzr
	mov	x4, xzr
	mov	x5, xzr
	mov	x6, xzr
	mov	x7, xzr
	mov	x8, __NR_clone
	svc	0
	cbnz	x0, .parent
	ldr	x1, .argv
	ldr	x2, .arge
	ldr	x0, [x1]
	mov	x8, __NR_execve
	svc	0
	add	sp, sp, 16
	mov	x0, xzr
	mov	x8, __NR_exit
	svc	0
.parent:
	ldp	x7, x8, [sp], 16
	brk	0
	ret

.align 4
.argv:
	.quad	0
.arge:
	.quad	0
spawn_argv:
	.quad	(.argv - spawn)
spawn_arge:
	.quad	(.arge - spawn)
spawn_size:
	.word	(. - spawn)

.global clone, clone_size
.global spawn, spawn_size, spawn_argv, spawn_arge



