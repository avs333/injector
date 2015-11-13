#include "common.h"
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/ptrace.h>
#include <asm/unistd.h>
#include <asm/ptrace.h>
#include <linux/sched.h>
#include <signal.h>
#include <limits.h>

#ifndef EM_ARM
#define EM_ARM		40
#endif
#ifndef EM_AARCH64
#define EM_AARCH64	183
#endif

#define ADD_FORKEXEC	1
//#undef ADD_FORKEXEC	

/* defined in cloneXX.S */
extern void *clone, *spawn;
extern int clone_size, spawn_size;
extern off_t spawn_argv, spawn_arge;

/* main entry points */
static int injector(int argc, char **argv);
#if ADD_FORKEXEC
static int forkexec(int argc, char **argv);
#endif

int verbose = 1;		/* single global variable */	

int main(int argc, char **argv) {
    char *prog = strrchr(argv[0], '/');
    if(!prog) prog = argv[0];
    else prog++;
    if(strncmp(prog, "injector", strlen("injector")) == 0) 
	return injector(argc, argv);	
#if ADD_FORKEXEC
    else if(strncmp(prog, "spawn", strlen("spawn")) == 0) 
	return forkexec(argc, argv);
#endif
    return fprintf(stderr, "Can't recognise my name: please call me \"injector*\" or \"spawn*\".\n");
}

#define INJDUMP_INFO	"jdump.txt"
#define INJDUMP_BIN	"jdump.elf"
static void dump(layout *dlay)
{ 
    int fd, k;
    char msg[512];
	if(!dlay) return;

	fd = open(INJDUMP_INFO, O_CREAT|O_TRUNC|O_WRONLY, 0644);
	if(fd < 0) return;
	snprintf(msg, sizeof(msg), 
	"base 0x%lx mem 0x%lx\n"
	"plt 0x%lx size %lx\n"
	"got 0x%lx size %lx\n"
	"bss 0x%lx size %lx\n"
	"entry 0x%lx\n",
	(long) dlay->base, (long) dlay->mem, 
	(long) dlay->mem + dlay->plt, (long) dlay->plt_size,
	(long) dlay->mem + dlay->got, (long) dlay->got_size,
	(long) dlay->mem + dlay->bss, (long) dlay->bss_size, 
	(long) dlay->mem + dlay->entry_offs);
	k = write(fd, msg, strlen(msg));
	close(fd);

	if(k < 0) return;
	if(!dlay->mem || !dlay->bss) return;

	fd = open(INJDUMP_BIN, O_CREAT|O_TRUNC|O_WRONLY, 0644);
	if(fd < 0) return;
	(void) write(fd, dlay->mem, dlay->bss + dlay->bss_size);
	close(fd);
}

#if 0
void exit_on_fault(int sig, siginfo_t *info, void *context) {
#ifdef __arm__
    struct sigcontext *ctx = &(((ucontext_t*)context)->uc_mcontext);
	if(ctx) printf("Fault at PC %08lx (LR %08lx)\n", ctx->arm_pc, ctx->arm_lr);
	else printf("no ctx\n");
#endif
	log_err("Exiting on signal %d\n", sig);
    _exit(1);
}
static struct sigaction sact = { .sa_sigaction = exit_on_fault };
void catch_abnormals()
{
    sigaction(SIGTRAP, &sact, 0);		
    sigaction(SIGILL, &sact, 0);		
    sigaction(SIGBUS, &sact, 0);		
    sigaction(SIGSEGV, &sact, 0);
    sigaction(SIGFPE, &sact, 0);
    sigaction(SIGSTKFLT, &sact, 0);
}
#endif

static void free_loaded_libs(lib_info *loaded_libs)
{
    lib_info *lib, *lib_next;
	for(lib = loaded_libs; lib; lib = lib_next) {
	    lib_next = lib->next;	
	    if(lib->name) free(lib->name); 
	    if(lib->dlhandle) dlclose(lib->dlhandle);
	    if(lib->img != MAP_FAILED) munmap(lib->img,lib->img_size);
	    free(lib);	
	}
}

static void free_commons(comm_sym *commons)
{
    comm_sym *s, *next;
	for(s = commons; s; s = next) {
	    next = s->next;
	    free(s);
	}
}

static int find_process(char *cmdline)
{
    int fd, i, k, pid = -1;
    struct dirent *d;
    DIR *dir;
    char tmp[512];
	dir = opendir("/proc");
	if(!dir) return -1;
	while((d = readdir(dir)) != 0) { /* find target pid in /proc */
	    k = atoi(d->d_name);
	    if(k <= 0 || k > 65535) continue;
	    sprintf(tmp, "/proc/%d/cmdline", k);
	    if((fd = open(tmp, O_RDONLY, 0644)) < 0) continue;
	    i = read(fd, tmp, sizeof(tmp));
	    close(fd);
	    if(i < 0) continue;	
	    if(strcmp(tmp,cmdline) == 0) {
	        pid = k;
	        break;
	    }
	}
	closedir(dir);
    return pid;
}

static int wait_stop(pid_t pid, int signal)
{
    long pt;
    int sig;	
    int status;

    while(1) {
	waitpid(pid, &status, __WALL);
	if(WIFEXITED(status)) {
	    log_err("error: pid %d exited with status %d\n", pid, WEXITSTATUS(status));
	    return -1; 	
	} else if(WIFSIGNALED(status)) {
	    sig = WTERMSIG(status);
	    log_err("error: pid %d terminated by signal %d\n", pid, sig);
	    return -1;	
	} else if(WIFSTOPPED(status)) {
	    sig = WSTOPSIG(status);
	    if(sig == signal) return 0;
#if 0
	    /* Regular arm bkpt instructions generate this for some high-minded reason */	
	    if(sig == SIGBUS) {
		log_info("prefetch abort\n");
		return 0;
	    }	
#endif
	    log_info("spurious signal %d caught, continue\n", sig);
	    pt = ptrace(PTRACE_CONT, pid, 0, (void *) (long) sig);
	    if(pt != 0) {
		log_err("cannot inject signal %d after ptrace_attach\n", sig);
		return -1;
	    }
	}
    }
}

#ifdef __arm__
static inline long getregs(pid_t pid, struct pt_regs *regs) {
    return ptrace(PTRACE_GETREGS, pid, 0, regs);
}
static inline long setregs(pid_t pid, struct pt_regs *regs) {
    return ptrace(PTRACE_SETREGS, pid, 0, regs);
}
static inline void info_regs(pid_t pid, struct pt_regs *regs, char *info) {
   log_info("%s at %lx:\tr0=%lx r7=%lx ip=%lx cpsr=%lx\n",
       info, regs->ARM_pc, regs->ARM_r0, regs->ARM_r7, regs->ARM_ip, regs->ARM_cpsr);
}
#else
static inline long getregs(pid_t pid, struct user_pt_regs *regs) {
    struct iovec iov = { regs, sizeof(*regs) };
    return ptrace(PTRACE_GETREGSET, pid, (void *) NT_PRSTATUS, &iov);
}
static inline long setregs(pid_t pid, struct user_pt_regs *regs) {
    struct iovec iov = { regs, sizeof(*regs) };
    return ptrace(PTRACE_SETREGSET, pid, (void *) NT_PRSTATUS, &iov);
}
static inline void info_regs(pid_t pid, struct user_pt_regs *regs, char *info) {
    log_info("%s at %llx:\tx0=%llx x7=%llx x8=%llx pstate=%llx\n",
	info, regs->pc, regs->regs[0], regs->regs[7], /* x7 is like ip on arm */ regs->regs[8], regs->pstate);
}
#endif

/* Allocates (when mem=0) or frees len bytes in process memory.
   In the first case, returns 0 on error, and address of allocated mem otherwise.
   In the second case, returns non-zero value on error, 0 on success.
 */
static void *map_unmap_process_mem(pid_t pid, void *mem, size_t len)
{
    long pt;
    void *ret = MAP_FAILED;

#ifdef __arm__
    uint32_t addr = 0;
    uint32_t old_instr[2], new_instr[2] = { 0xef000000, 0xe7f001f0 };	/* svc #0 + BREAKINST_ARM from arch/arm/kernel/ptrace.c */
    struct pt_regs old_regs, new_regs;
#else
    uint64_t addr = 0;
    uint64_t old_instr[2], new_instr[2] = { 0, 0xd4200000d4000001 };	/* first elem to be set below, second = svc #0; brk #0 */
    struct user_pt_regs old_regs, new_regs;
#endif
/*	log_info("Trying to %s 0x%lx bytes in pid=%d\n", mem ? "free" : "allocate", (long)len, pid); */
	errno = 0;
	pt = ptrace(PTRACE_ATTACH, pid, 0, 0);
	if(pt != 0) {
	    log_err("cannot attach to pid %d: errno=%d\n", pid, errno);
	    return 0;
	}
	errno = 0;
	if(wait_stop(pid, SIGSTOP) != 0) {
	    log_err("pid %d failed to stop after attach: errno=%d\n", pid, errno);	
	    goto out;	
	}
	errno = 0;
	pt = getregs(pid, &old_regs);
	if(pt != 0) {
	    log_err("cannot get old regs after SIGSTOP: errno=%d\n", errno);	
	    goto out;	
	}

	/* info_regs(pid, &old_regs, "on stop: "); */
	memcpy(&new_regs, &old_regs, sizeof(old_regs));

	errno = 0;
#ifdef __arm__
	addr = (old_regs.ARM_pc & ~3) - 4;	/* address of instruction after one at PC in arm mode */

	old_instr[0] = ptrace(PTRACE_PEEKTEXT, pid, (void *) addr, 0);
	old_instr[1] = ptrace(PTRACE_PEEKTEXT, pid, (void *) addr + 4, 0);
	if(errno) {
	    log_err("peektext failed before mmap: errno=%d\n", errno);
	    goto out;
	}
	pt =  ptrace(PTRACE_POKETEXT, pid, (void *) addr+0, (void *) new_instr[0]);
	pt |= ptrace(PTRACE_POKETEXT, pid, (void *) addr+4, (void *) new_instr[1]);
	if(pt != 0) {
	    log_err("poketext failed before mmap: errno=%d\n", errno);
	    goto out; 	
	}
	new_regs.ARM_cpsr = (old_regs.ARM_cpsr & ~PSR_T_BIT);  /* switch to ARM mode if in THUMB */
	new_regs.ARM_pc = addr;
	if(mem) {
	    new_regs.ARM_r0 = (long) mem;
	    new_regs.ARM_r1 = len;
	    new_regs.ARM_r7 = __NR_munmap;
	} else {
	    new_regs.ARM_r0 = 0;	/* req addr */
	    new_regs.ARM_r1 = len;
	    new_regs.ARM_r2 = (PROT_READ|PROT_WRITE|PROT_EXEC);
	    new_regs.ARM_r3 = (MAP_PRIVATE|MAP_ANONYMOUS);
	    new_regs.ARM_r4 = -1;	/* fd */
	    new_regs.ARM_r5 = 0;	/* offset */
	    new_regs.ARM_r7 = __NR_mmap2;
	}
#else
	/* Don't bother splitting 64-bit code between the words as above, 
	   just add an extra "mov" instruction to load x8 register 
	   (otherwise, x8 may change on exit from syscall) */

	addr = old_regs.pc & ~0x7;
	old_instr[0] = ptrace(PTRACE_PEEKTEXT, pid, (void *) addr+0, 0);
	old_instr[1] = ptrace(PTRACE_PEEKTEXT, pid, (void *) addr+8, 0);
	if(errno) {
	    log_err("peektext failed before mmap: errno=%d\n", errno);
	    goto out;
	}
	/* new_instr[0]:   loword = nop; hiword = mov x8, mem ? __NR_mumnap : __NR_mmap */	
	new_instr[0] = mem ? 0xd2801ae8d503201f : 0xd2801bc8d503201f;

	pt  = ptrace(PTRACE_POKETEXT, pid, (void *) addr+0, (void *) new_instr[0]);
	pt |= ptrace(PTRACE_POKETEXT, pid, (void *) addr+8, (void *) new_instr[1]);
	if(pt != 0) {
	    log_err("poketext failed before mmap: errno=%d\n", errno);
	    goto out; 	
	}
	if(mem) {
	    new_regs.regs[0] = (long) mem;
	    new_regs.regs[1] = len;
	} else {
	    new_regs.regs[0] = 0;
	    new_regs.regs[1] = len;
	    new_regs.regs[2] = (PROT_READ|PROT_WRITE|PROT_EXEC);
	    new_regs.regs[3] = (MAP_PRIVATE|MAP_ANONYMOUS);
	    new_regs.regs[4] = -1;
	    new_regs.regs[5] = 0;
	}
#endif
	errno = 0;
	pt = setregs(pid, &new_regs);
	if(pt != 0) {
	    log_err("cannot set new regs: errno=%d\n", errno);	
	    goto out;	
	}
	errno = 0;
	pt = ptrace(PTRACE_CONT, pid, 0, 0);
	if(pt != 0) {
	    log_err("PTRACE_CONT failed: : errno=%d\n", errno);	
	    goto out;
	}
	if(wait_stop(pid, SIGTRAP) != 0) {
	    log_err("no SIGTRAP after CONT\n");
	    goto out;	
	}
	errno = 0;
	pt = getregs(pid, &new_regs);
	if(pt != 0) {
	    log_err("cannot get regs mmap: errno=%d\n", errno);	
	    goto out;	
	}
	/* info_regs(pid, &new_regs, "after mmap: "); */

	errno = 0;
#ifdef __arm__
	ret = (void *) new_regs.ARM_r0;
	pt =  ptrace(PTRACE_POKETEXT, pid, (void *) addr + 0, (void *) old_instr[0]);
	pt |= ptrace(PTRACE_POKETEXT, pid, (void *) addr + 4, (void *) old_instr[1]);
#else
	ret = (void *) new_regs.regs[0];
	pt =  ptrace(PTRACE_POKETEXT, pid, (void *) addr + 0, (void *) old_instr[0]);
	pt |= ptrace(PTRACE_POKETEXT, pid, (void *) addr + 8, (void *) old_instr[1]);
#endif
	if(pt != 0) {
	    log_err("failed to restore old code after mmap: errno=%d\n", errno);
	    goto out; 	
	}
	errno = 0;
	pt = setregs(pid, &old_regs);
	if(pt != 0) {
	    log_err("failed to restore old regs after mmap: errno=%d\n", errno);	
	    goto out;
	}

    out:		
	if(ret == MAP_FAILED) {
	    log_err("mmap syscall failed\n");
	    if(!mem) ret = 0;
	    goto out;
	}
	ptrace(PTRACE_DETACH, pid, 0, 0);

    return ret;	

}

static void *alloc_process_mem(pid_t pid, size_t len) 
{
    return map_unmap_process_mem(pid, 0, len);
}

static int free_process_mem(pid_t pid, void *mem, size_t len) 
{
    return (int) (long) map_unmap_process_mem(pid, mem, len);
}

#if 1
/* len should be at most PAGESIZE */
static int _copy_to_process(pid_t pid, void *base, void *mem, size_t len) 
{
    long pt;
    int k;
    long *mm = (long *) mem;
	if(len == 0) return 0;
	pt = ptrace(PTRACE_ATTACH, pid, 0, 0);
	if(pt != 0) {
	    log_err("cannot attach to pid %d\n", pid);
	    return -1;
	}
	if(wait_stop(pid, SIGSTOP) != 0) {
	    log_err("pid %d failed to stop after attaching\n", pid);	
	    return -1;	
	}
	for(k = 0; k < len/(sizeof(*mm)); k++, base += sizeof(*mm)) {
	    pt = ptrace(PTRACE_POKETEXT, pid, base, (void *) mm[k]);
	    if(pt != 0) {
		log_err("poke failed in %s\n", __func__);
		ptrace(PTRACE_DETACH, pid, 0, 0);
		return -1;
	    }
	}
	ptrace(PTRACE_DETACH, pid, 0, 0);
	log_debug("%d bytes copied\n",  (int) len);
    return 0;	
}
#endif

#undef PAGESIZE
#ifdef __arm__
#define PAGESIZE 4
#else
#define PAGESIZE 8
#endif

static int copy_to_process(pid_t pid, void *base, void *mem, size_t len)
{
    int k, fd = -1;
    char file[128];

	if(len & (sizeof(long) - 1)) {
	    log_err("internal error: image size not multiple of %d\n", (int) sizeof(long));
	    return -1;
	}
	sprintf(file, "/proc/%d/mem", pid);
	fd = open(file, O_RDWR);
	if(fd <= 0) {
	    log_err("failed to open %s\n", file);
	    goto err;		
	}
	if(lseek(fd, (off_t) base, SEEK_SET) != (off_t) base) {
	    log_err("seek to %p failed for %s\n", base, file);
	    goto err;		
	}	
	for(k = 0; k < len/PAGESIZE; k++) {

	    int i;
		errno = 0;
		i = write(fd, mem, PAGESIZE);
	    if(i != PAGESIZE) {
		log_err("write failed at %p for %s, k=%d i=%d %d\n", base, file, k, i, errno);
		goto err;
	    }	
	    mem  += PAGESIZE;
	    base += PAGESIZE;
	}
	log_debug("%d bytes copied\n",  (int) (len/PAGESIZE) * PAGESIZE);
	for(k = 0; k < len % PAGESIZE; k += sizeof(long)) {
	    if(write(fd, mem, sizeof(long)) != sizeof(long)) {
		log_err("write failed at %p for %s\n", base, file);
		goto err;
	    }	
	    mem  += sizeof(long);
	    base += sizeof(long);
	}
	log_debug("%d bytes copied\n",  k);
	
	close(fd);
	return 0;
    err:
	if(fd > 0) close(fd);
	return -1;
}


static pid_t run(pid_t pid, layout *lay, void *start_arg, size_t stack_size)
{
    long pt;
    pid_t ret = -1;
#ifdef __arm__
    struct pt_regs old_regs;
    struct pt_regs new_regs;
#else
    struct user_pt_regs old_regs;
    struct user_pt_regs new_regs;
#endif
	pt = ptrace(PTRACE_ATTACH, pid, 0, 0);
	if(pt != 0) {
	    log_err("cannot attach to pid %d\n", pid);
	    return -1;
	}
	if(wait_stop(pid, SIGSTOP) != 0) {
	    log_err("pid %d failed to stop after attaching\n", pid);	
	    return -1;	
	}
	pt = getregs(pid, &old_regs);
	if(pt != 0) {
	    log_err("cannot get old regs after SIGSTOP\n");	
	    goto out;	
	}
	memcpy(&new_regs, &old_regs, sizeof(old_regs));

#ifdef __arm__
	new_regs.ARM_pc = (long) lay->base + lay->startup_offs;
	new_regs.ARM_cpsr = (old_regs.ARM_cpsr | PSR_T_BIT);	/* thumb code in clone32.S */	
	new_regs.ARM_r0 = CLONE_VM|CLONE_SIGHAND|CLONE_THREAD|CLONE_FILES;
	new_regs.ARM_r1 = (long) lay->base + lay->entry_offs;	/* start func */
	new_regs.ARM_r2 = (long) start_arg;  			/* its arg */	
	new_regs.ARM_r3 = stack_size;
#else
	new_regs.pc = (long) lay->base + lay->startup_offs;
	new_regs.regs[0] = CLONE_VM|CLONE_SIGHAND|CLONE_THREAD|CLONE_FILES;
	new_regs.regs[1] = (long) lay->base + lay->entry_offs;
	new_regs.regs[2] = (long) start_arg;
	new_regs.regs[3] = stack_size;
#endif
	pt = setregs(pid, &new_regs);
	if(pt != 0) {
	    log_err("cannot set new regs\n");	
	    goto out;	
	}
	pt = ptrace(PTRACE_CONT, pid, 0, 0);
	if(pt != 0) {
	    log_err("cannot continue at %lx", (long) lay->base + lay->startup_offs);
	    goto out;    
	}
	if(wait_stop(pid, SIGTRAP) != 0) {
	    log_err("failed to stop process %d at breakpoint\n", pid);	
	    return -1;	
	}
	pt = getregs(pid, &new_regs);
	if(pt != 0) {
	    log_err("cannot get regs after syscall\n");	
	    goto out;	
	}
	pt = setregs(pid, &old_regs);
	if(pt != 0) {
	    log_err("cannot restore old regs\n");	
	    goto out;	
	}
#ifdef __arm__
	ret = (pid_t) new_regs.ARM_r0;
#else
	ret = (pid_t) new_regs.regs[0]; 
#endif

    out:		
	ptrace(PTRACE_DETACH, pid, 0, 0);

    return ret;
}

#define DFL_MAX_PLT_SIZE		0x2000		/* max sizes allocated for PLT and */	
#define DFL_MAX_GOT_SIZE		0x1000		/* GOT at 1st pass  */
#define DFL_STACK_SIZE			0x80000		/* 512k for thread stack */
#define PID_WAIT_MS			20		/* check interval for wait_exit */


static int injector(int argc, char **argv)
{
    int opt, fd = -1, ret = -1;
    size_t img_len = 0, tot_len = 0;
    char *progname, *start_name = "main";
    Elf_Ehdr ehdr;
    lib_info *loaded_libs = 0;		/* linked array of libs for symbol lookups */
    comm_sym *commons = 0;		/* linked array of common symbols */
    void *img = MAP_FAILED;
    pid_t target_pid = 0;
    int firstpassonly = 0;
    int quiet = 0;
    int dump_image = 0;
    int wait_exit = 0;
    void (*startup)(void *) = 0;
    void *start_arg = 0;

    int max_plt_size = DFL_MAX_PLT_SIZE; 
    int max_got_size = DFL_MAX_GOT_SIZE;
    int stack_size = DFL_STACK_SIZE;

    layout lay[1];

    void usage() {
	fprintf(stderr, 
	    "\nInject code to process memory, link it and run in a separate thread.\n\n"
	    "%s [options ...] <file> [libraries...]\n" 
	    "%s cleanup <pid> <start_addr> <len>\n\n" 
	    "<file> -- non-linked object file\n"
	    "[libraries...] -- full paths to libraries it uses\n"
	    "Options:\n"
	    "-e <entry_point> -- start symbol in <file> (default is \"main\")\n"
	    "-i <word> -- argument to pass to <entry_point> (default is 0)\n"
	    "-s <size> -- stack size of execution thread (default is %d)\n"
	/*  "-t/-g <size> -- maximum size of PLT/GOT sections for 1st pass (defaults: 0x%x/0x%x)\n" */
	    "-p <pid> OR -n <proc_name> -- target pid or process name (default is current process)\n"
	    "-w -- wait until the thread has exited (take care to undo process changes if any!)\n"
	    "-v -- verbose output: includes debugging information (may be repeated)\n"
	    "-q -- quiet output: only errors and cleanup string if any\n\n",
		progname, progname, DFL_STACK_SIZE /*, DFL_MAX_PLT_SIZE, DFL_MAX_GOT_SIZE */);
	_exit(-1);
    }

	progname = argv[0];

	if(argc < 2) usage();
#if 0
	catch_abnormals();
#endif
	if(strcmp(argv[1], "cleanup") == 0) {
	    if(argc != 5) usage();
	    target_pid = atoi(argv[2]);
	    img = (void *) strtoul(argv[3], 0, 0);
	    img_len = strtoul(argv[4], 0, 0);
	    ret = free_process_mem(target_pid, img, img_len);
	    log_info("cleanup %s\n", ret == 0 ? "succeeded" : "failed");
	    return ret;
	}

	while((opt = getopt(argc, argv, "e:i:p:n:t:g:l:1qdvw")) != -1) {
	    switch(opt) {
		case 'e':
		    start_name = optarg;
		    break;
		case 'i':
		    start_arg = (void *) strtoul(optarg, 0, 0); 
		    break;
		case 'p':
		    if(target_pid) {
			log_err("only one \"-n\" or \"-p\" option allowed\n");
			goto done;
		    }		
		    target_pid = atoi(optarg); 
		    if(target_pid <= 0) {
			log_err("invalid pid %d\n", target_pid);
			goto done;
		    } else {
			char c[128];
			struct stat st;
			    sprintf(c, "/proc/%d", target_pid);
			    if(stat(c, &st) != 0) {
				log_err("no such pid: %d\n", target_pid);
			        goto done;
			    }	
		    }	
		    break;
		case 'n':
		    if(target_pid) {
			log_err("only one \"-n\" or \"-p\" option allowed\n");
			goto done;
		    }		
		    target_pid = find_process(optarg);
		    if(target_pid < 0) {
			log_err("process named \"%s\" not running\n", optarg);
			goto done;
		    }	
		    break;
		case 'q':
		    quiet = 1;
		    break;
		case 'v':
		    verbose++;
		    break;
		case 'w':
		    wait_exit = 1;
		    break;
		/* Debugging options, not displayed in usage() */
		case 't':
		    max_plt_size = strtoul(optarg, 0, 0);
		    break;		
		case 'g':
		    max_got_size = strtoul(optarg, 0, 0);
		    break;		
		case '1':
		    firstpassonly = 1;
		    break;
		case 'd':
		    dump_image = 1;
		    break;
		default:
		    usage();
		    goto done;		
	    }	
	}
	
	if(optind == argc) {
	    log_err("no file specified\n");
	    goto done;
	}
	fd = open(argv[optind], O_RDONLY);
	if(fd < 0) {
	    log_err("cannot open %s\n", argv[optind]);
	    return -1;
	}
	if(read(fd, &ehdr, sizeof(ehdr)) != sizeof(ehdr)) {
	    log_err("%s unreadable\n", argv[optind]);
	    goto done;
	}
	if(strncmp((char *)&ehdr, ELFMAG, 4) != 0) {
	    log_err("%s: not an elf file\n", argv[optind]);
	    goto done;
	}
	if(ehdr.e_type != ET_REL) {
	    log_err("%s: is not a relocatable object file (ET_TYPE=%d)\n", argv[optind], ehdr.e_type);
	    goto done;	
	}
#ifdef __arm__
	if(ehdr.e_ident[EI_CLASS] != ELFCLASS32 || ehdr.e_machine != EM_ARM)	
#else
	if(ehdr.e_ident[EI_CLASS] != ELFCLASS64 || ehdr.e_machine != EM_AARCH64)	
#endif
	    {
		log_err("%s: 32/64-bit conflict, please use correct executable to inject this file\n", argv[optind]);
		goto done;
	    }

	img_len = lseek(fd, 0, SEEK_END);
	img = mmap(0, img_len, PROT_READ, MAP_PRIVATE, fd, 0);
	close(fd);
	fd = -1;

	if(img == MAP_FAILED) {
	    log_err("mmap failed for file %s, len=%ld\n", argv[optind], (long) img_len);
	    goto done;
	}
		
	while(++optind < argc) 
	    if(add_lib(target_pid, &loaded_libs, argv[optind]) != 0) {
		log_err("warning: failed to add library %s\n", argv[optind]);
		/* goto done; */
	    }	


	memset(lay, 0, sizeof(layout));

	lay->entry_offs = -1;
	lay->mem = img;

	/* Determine lay->entry_offs, lay->bss_size, lay->comm_size
	 and offsets of common symbols */

	if(setup_image(lay, start_name, &commons) != 0) {
	    log_err("image setup failed\n");
	    goto done;		
	}

	if(lay->entry_offs == -1) {
	    log_err("entry point \"%s\" not found\n", start_name);	
	    goto done;
	}

	if(!quiet) log_info("Setup succeeded for %lx: entry=0x%lx, extra memory used: bss=0x%lx, comm=0x%lx\n", 
		(long) lay->mem, (long) lay->entry_offs, (long) lay->bss_size, (long) lay->comm_size);

	/* First pass */

	lay->startup_offs = (img_len & 15) ? img_len + (16 - (img_len & 15)) : img_len;
	tot_len = lay->startup_offs + clone_size;
	if(tot_len & 15) tot_len += (16 - (tot_len & 15));

	lay->plt = tot_len;
	lay->plt_size = 0;	/* to be set in 1st pass */
	lay->max_plt = max_plt_size;
	tot_len += max_plt_size;
	if(tot_len & 15) tot_len += (16 - (tot_len & 15));

	lay->got = tot_len;
	lay->got_size = 0;	/* to be set in 1st pass */
	lay->max_got = max_got_size;
	tot_len += max_got_size;
	if(tot_len & 15) tot_len += (16 - (tot_len & 15));

	lay->bss = tot_len;
	tot_len += lay->bss_size;	/* calculated in setup_image */	
	if(tot_len & 15) tot_len += (16 - (tot_len & 15));

	lay->comm = tot_len;
	tot_len += lay->comm_size;	/* calculated in setup_image */
	if(tot_len & 15) tot_len += (16 - (tot_len & 15));

		
	lay->mem = mmap(0, tot_len, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
	if(lay->mem == MAP_FAILED) {
	    log_err("mmap failed for first pass\n");
	    goto done;
	}
	memcpy(lay->mem, img, img_len);

	if(firstpassonly && verbose < 2) verbose = 2;

	if(relocate_image(lay, loaded_libs, commons) != 0){
	    log_err("First pass failed.\n");
	    goto done;
	}

	if(verbose < 2) verbose = !quiet;

	log_info("First pass succeeded for %lx, extra memory used: plt=0x%lx/0x%lx, got=0x%lx/0x%lx\n", 
		(long) lay->mem, (long) lay->plt_size, (long) lay->max_plt, (long) lay->got_size, (long) lay->max_got);

	if(firstpassonly) {
	    ret = 0;	
	    goto done;	
	}

	/* Prepare to second pass */

	munmap(lay->mem, tot_len);

	tot_len = lay->startup_offs + clone_size;
	if(tot_len & 15) tot_len += (16 - (tot_len & 15));
	
	lay->plt = tot_len;
	lay->max_plt = lay->plt_size;	/* limit size to size allocated in first pass */
	tot_len += lay->plt_size;
	lay->plt_size = 0;		/* allocate it from scratch */
	if(tot_len & 15) tot_len += (16 - (tot_len & 15));

	lay->got = tot_len;
	lay->max_got = lay->got_size;	/* limit size to size allocated in first pass */
	tot_len += lay->got_size;
	lay->got_size = 0;		/* allocate it from scratch */
	if(tot_len & 15) tot_len += (16 - (tot_len & 15));

	lay->bss = tot_len;
	tot_len += lay->bss_size;
	if(tot_len & 15) tot_len += (16 - (tot_len & 15));

	lay->comm = tot_len;
	tot_len += lay->comm_size;
	if(tot_len & 15) tot_len += (16 - (tot_len & 15));
	
	lay->mem = mmap(0, tot_len, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
	if(lay->mem == MAP_FAILED) {
	    log_err("mmap failed for second pass\n");
	    goto done;
	}

	memcpy(lay->mem, img, img_len);
	memcpy(lay->mem + lay->startup_offs, &clone, clone_size);
     /* memset(lay->mem + lay->bss, 0, lay->bss_size); MAP_ANONYMOUS does this */

	munmap(img, img_len);
	img = MAP_FAILED;

	lay->base = 0;

	if(target_pid) {
	    lay->base = alloc_process_mem(target_pid, tot_len);
	    if(!lay->base) {
		log_err("failed to allocate process memory\n");
		goto done;		
	    }
	    log_info("Target process memory allocated at %p\n", lay->base); 
	}

	if(relocate_image(lay, loaded_libs, commons) != 0){
	    log_err("failed to setup sections\n");
	    goto done;
	}

	log_info("Second pass succeeded. Layout:\n");
	log_info("mem=%p plt=%lx got=%lx bss=%lx bss_size=%lx\n",
		lay->mem, (long) lay->plt, (long) lay->got,
		(long) lay->bss, (long) lay->bss_size);
	
	if(dump_image) dump(lay);

	if(target_pid) {
	    int k;
	    log_info("Copying image to pid %d\n", target_pid);	
	    k = _copy_to_process(target_pid, lay->base, lay->mem, tot_len);
	    if(k != 0) {
		log_err("failed to copy object code into process memory\n");
		goto done;
	    }
	    log_info("Image copied\n");

	    k = run(target_pid, lay, start_arg, stack_size);

	    if(k < 0) {
		log_err("failed to run object code\n");
		goto done;
	    }
	    if(wait_exit) {
		char proc_file[64];
		struct stat st;
		int i = 0, out_interval = 1000/PID_WAIT_MS;
		log_info("Started thread %d in process %d, waiting for exit\n", k, target_pid);
		sprintf(proc_file, "/proc/%d/task/%d", target_pid, k);
		while(stat(proc_file, &st) == 0) {
		    if(i % out_interval == 0) log_debug("%d still alive, waiting\n", k);   /* output this each second */
		    usleep(PID_WAIT_MS * 1000);
		    i++;	
		}
		log_info("Thread %d exited, cleaning up\n", k);
		ret = free_process_mem(target_pid, (void *) lay->base, tot_len);
		log_info("Cleanup %s\n", ret == 0 ? "succeeded" : "failed");
	    } else {
		log_info("Started thread %d in process %d, cleanup command:\n", k, target_pid);
		printf("%s cleanup %d 0x%lx 0x%lx\n", progname, target_pid, (long) lay->base, (long) tot_len);
	    }
	} else 	{
	    __builtin___clear_cache(lay->mem, lay->mem + lay->bss); /* _must_ be called, results unpredictable otherwise! */	
	    startup = (typeof(startup)) lay->mem + lay->entry_offs;
	    log_info("launching %s at %p in current addrspace\n", start_name, (void *) startup);
	    startup(start_arg);
	    log_info("%s() returned\n", start_name);
	}
	ret = 0;
    done: 
	if(fd >= 0) close(fd);
	if(img != MAP_FAILED) munmap(img, img_len);
	if(lay->mem != MAP_FAILED) munmap(lay->mem, tot_len);
	free_loaded_libs(loaded_libs);
	free_commons(commons);
    return ret;
}


#if ADD_FORKEXEC
/* Default environment strings (separated by '\0') that should be passed to execve in spawn(). */
#define DFL_SPAWN_ENVIRON	"ANDROID_ROOT=/system\0ANDROID_DATA=/data"

#if 0
static inline void pstack() {
    long sp; asm("mov  %0,sp\n\t" : "=r"(sp));
    log_info("sp=%llx\n", (long long) sp);
}
#endif


/*
NB: zero flag is specified in clone() not to create zombies.
If required, an extra argument may be added for this flag.
*/

static int forkexec(int argc, char **argv) {

    int opt, k, ret = -1;
    size_t len, tot_len;
    static char environ[] = DFL_SPAWN_ENVIRON;		/* ingore libc's environ global */
    int environ_len = sizeof(DFL_SPAWN_ENVIRON);
    char *c, *estrings = 0;
    int estr_len = 0;
    off_t *aptrs = 0, *eptrs = 0, ptrs_offs;
    size_t aptrs_num = 0, eptrs_num = 0;
    void *mem = 0;

    pid_t target_pid = 0;
    int dump_image = 0;
    int quiet = 0;
    int remove_default_env = 0;    

    layout lay[1];
 
    void usage() {
	c = environ;
	while(*c) {
	    if(!*c) {
		*c = ' '; if(c[1] == 0) break;
	    }
	    c++;
	}
	fprintf(stderr, 
	    "\nFork from a process and execute a command as a direct child of that process.\n\n"
	    "%s <-p pid | -n process_name> [options ...] <full_path_to_exe_file> [arguments...]\n\n" 
	    "Options:\n"
	    "-e <key=val> -- add this keyval pair to environment (may be repeated)\n"
	    "-r -- remove envirionment variables %s that are added by default\n"
	    "-v -- verbose output: includes debugging information (may be repeated)\n"
	    "-q -- quiet output: display errors only\n\n",
		argv[0], environ);
	_exit(-1);
    }

	if(argc < 2) usage();

	while((opt = getopt(argc, argv, "p:n:e:rqvd")) != -1) {
	    switch(opt) {
		case 'p':
		    if(target_pid) {
			log_err("only one \"-n\" or \"-p\" option allowed\n");
			goto done;
		    }		
		    target_pid = atoi(optarg); 
		    if(target_pid <= 0) {
			log_err("invalid pid %d\n", target_pid);
			goto done;
		    } else {
			char c[128];
			struct stat st;
			    sprintf(c, "/proc/%d", target_pid);
			    if(stat(c, &st) != 0) {
				log_err("no such pid: %d\n", target_pid);
			        goto done;
			    }	
		    }	
		    break;
		case 'n':
		    if(target_pid) {
			log_err("only one \"-n\" or \"-p\" option allowed\n");
			goto done;
		    }		
		    target_pid = find_process(optarg);
		    if(target_pid < 0) {
			log_err("process named \"%s\" not running\n", optarg);
			goto done;
		    }	
		    break;
		case 'e':
		    len = strlen(optarg) + 1;
		    estrings = (char *) realloc(estrings, estr_len + len);
		    if(!estrings) {
			log_err("out of memory\n");
			goto done;
		    }
		    c = estrings + estr_len;	
		    memcpy(c, optarg, len);
		    estr_len += len;
		    break;

		case 'q':
		    if(verbose > 1) {
			log_err("\"-v\" cannot be used with \"-q\".\n");
			goto done;
		    }
		    quiet = 1;
		    break;
		case 'v':
		    if(quiet) {
			log_err("\"-v\" cannot be used with \"-q\".\n");
			goto done;
		    }
		    verbose++;
		    break;
		case 'r':
		    remove_default_env = 1;
		    break;
		case 'd':
		    dump_image = 1;
		    break;
		default:
		    usage();
		    goto done;		
	    }	
	}

	if(!target_pid) usage();
	if(quiet) verbose = 0;
	log_info("Prepare code for injection ...\n");

	if(!remove_default_env) {
	    estrings = realloc(estrings, estr_len + environ_len);
	    if(!estrings) {
		log_err("out of memory\n");
		goto done;
	    }
	    c = estrings + estr_len;
	    memcpy(c, environ, environ_len);
	    estr_len += environ_len;	
	}

	memset(lay, 0, sizeof(layout));
	tot_len = spawn_size;

	mem = malloc(tot_len);
	if(!mem) {
	    log_err("no memory for spawn\n");
	    goto done;	
	}

	memcpy(mem, &spawn, spawn_size);

	argv += optind;
	argc -= optind;

	aptrs = (off_t *) malloc(sizeof(off_t) * (argc+1));
	if(!aptrs) {
	    log_err("no memory for argv\n");
	    goto done;	
	}
#if 0
	catch_abnormals();
#endif
	for(k = 0; k < argc; k++) {	/* copy argv strings to layout */
	    len = (strlen(argv[k]) + 1);
	    mem = realloc(mem, tot_len + len); 
	    if(!mem) {
		log_err("no memory for argv strings\n");
		goto done;
	    }	
	    log_debug("adding argvv=%s\n", argv[k]);
	    memcpy(mem + tot_len, argv[k], len);
	    aptrs[aptrs_num++] = tot_len;	/* relative to start address */	
	    tot_len += len;
	}

	aptrs[aptrs_num++] = 0;

	/****************/	
	mem = realloc(mem, tot_len + estr_len);

	if(!mem) {
	    log_err("no memory for envp strings\n");
	    goto done;
	}

	c = estrings;
	len = 0;

	while(len < estr_len) {		/* copy envp strings to layout */
	    k = strlen(c);
	    log_debug("adding envp=%s\n", c);
	    memcpy(mem + tot_len, c, k + 1);
	    eptrs = (off_t *) realloc(eptrs, sizeof(off_t) * (eptrs_num + 1));
	    if(!eptrs) {
		log_err("no memory for envp ptr\n");
		goto done;
	    }	
	    eptrs[eptrs_num++] = tot_len;	/* relative to start address */	
	    tot_len += (k + 1);
	    c += (k + 1);
	    len += (k + 1);
	}
	
	eptrs = (off_t *) realloc(eptrs, sizeof(off_t) * (eptrs_num + 1));  /* final null ptr */
	if(!eptrs) {
	    log_err("no mem for envp\n");	
	    goto done;	
	}
	eptrs[eptrs_num++] = 0;

	if(tot_len & 7) tot_len += (8 - (tot_len & 7));

	ptrs_offs = tot_len;			/* save start address of pointer arrays */
	tot_len += (aptrs_num + eptrs_num) * sizeof(void *);			

	lay->base = alloc_process_mem(target_pid, tot_len);
	if(!lay->base) {
	    log_err("failed to allocate process memory\n");
	    goto done;		
	}
	log_info("Target process memory allocated at %p\n", lay->base); 

	/* Prepare target pointers in our memory */

	*(off_t *) (mem + spawn_argv) = (off_t) lay->base + ptrs_offs;
	*(off_t *) (mem + spawn_arge) = (off_t) lay->base + ptrs_offs + aptrs_num * sizeof(off_t);

	lay->mem = mem;
	mem = mem + ptrs_offs;			/* relocate pointers in target memory image */
	for(k = 0; k < aptrs_num - 1; k++) {
	    *((off_t *) mem) = aptrs[k] + (off_t) lay->base;	
	    mem += sizeof(off_t);
	}
	*((off_t *) mem) = 0;
	mem += sizeof(off_t); 	/* skip null ptr */
	for(k = 0; k < eptrs_num - 1; k++) {
	    *((off_t *) mem) = eptrs[k] + (off_t) lay->base;	
	    mem += sizeof(off_t);
	}
	*((off_t *) mem) = 0;

	mem = lay->mem;

	if(dump_image) {
	    lay->bss = tot_len;
	    dump(lay);
	}
	/* Copy our layout to process */
	ret = copy_to_process(target_pid, lay->base, lay->mem, tot_len);
	if(ret != 0) {
	    log_err("copy to process failed\n");
	    goto done;
	}

	/* lay->startup_offs = 0; <-- spawn code is at the start of our image */
	ret = run(target_pid, lay, 0, 0);
	if(ret == -1) {
	    log_err("error launching\n");
	    goto done;
	}
	log_info("pid = %d in process %d started\n", ret, target_pid);

	/* cleanup */
	ret = free_process_mem(target_pid, lay->base, tot_len);
	if(ret != 0) {
	    log_err("failed to free process memory!\n");
	    goto done;
	}		
	log_info("Process memory cleaned\n");

    done:
	if(mem) free(mem);
	if(aptrs) free(aptrs);
	if(eptrs) free(eptrs);
	if(estrings) free(estrings);

    return ret;		
}
#endif

