#include <asm/unistd.h>
#ifdef __linux__
#include <machine/asm.h>
#endif

/* see arm/kernel/ptrace.c */
#define BREAKINST_THUMB		0xde01

/* int clone(int clone_flags, void *(*func)(void *), void *func_arg, size_t stack_size); 
   Returns -1 on error, cloned tid otherwise. */

.code 16
.align 4
.syntax unified
clone:
	push	{r0-r7}
	mov	r1,r3			@ stack_size
	adr	r6,.mmap_parms
	ldm	r6!,{r0,r2,r3,r4,r5,r7}
	svc	0
	cmp	r0,r4			@ -1
	beq	.mmap_error
	mov	r4,r0			@ r4 = stack_base
	pop	{r0,r1,r2,r6}		@ r0 -> clone_flags, r2 -> func_arg, r6 -> stack_size
	mov	r3,r1			@ r3 -> func
	adds	r1,r4,r6		@ r1 -> stack_base + stack_size
	subs	r1,16			@ child_stack: ref r1
	mov	r5,r1
	stm	r5!,{r2,r3,r4,r6}	@ r1: [0] -> func_arg, [4] -> func, [8] -> stack_base, [12] -> stack_size
	movs	r7,__NR_clone	
	svc	0
	tst	r0,r0
	bne	.parent_or_error
	pop	{r0,r1}			@ r0 -> func_arg, r1 -> func
	blx	r1			@ execute thread
	mov	r4,r0			@ r4 -> exit code
	pop	{r0,r1}			@ r0 -> stack_base, r1 -> stack_size
	movs	r7,__NR_munmap
	svc	0
	mov	r0,r4			@ exit_thread
	movs	r7,__NR_exit
	svc	0
    .mmap_error:
	add	sp,16
    .parent_or_error:
	pop     {r4-r7}
	.short  BREAKINST_THUMB
	bx	lr			@ not reached

.align 4
    .mmap_parms: 
  	.word  0, 3, 0x4022, -1, 0, __NR_mmap2 @ addr, prot, flags, fd, offset
clone_size:  .word (. - clone)    	

.align 4
spawn:
	push	{r4-r7}
	mov	r0, 0
	mov	r1, r0
	mov	r2, r0
	mov	r3, r0
	mov	r4, r0 
	mov	r5, r0
	mov	r6, r0
/*	mov	r0, 17	 SIGCHLD: <asm/signal.h> sucks */
	mov	r7, __NR_clone
	svc	0
	tst	r0, r0
	bne	.parent
	adr	r1, .argv
	ldr	r1, [r1]
	adr	r2, .arge
	ldr	r2, [r2]
	ldr	r0, [r1]
	mov	r7, __NR_execve
	svc	0
	pop	{r4-r7} /* Should execve fail, we must exit here */
	mvn	r0, 1
	mov	r7, __NR_exit
	svc	0
    .parent:
	pop	{r4-r7}
	.short	BREAKINST_THUMB
	bx      lr			@ not reached
.align 4
.argv:
	.word	0
.arge:
	.word	0
spawn_argv:
	.word	(.argv - spawn)
spawn_arge:
	.word	(.arge - spawn)
spawn_size:	
	.word (. - spawn)

.global clone
.global clone_size
.global spawn
.global spawn_size, spawn_argv, spawn_arge


