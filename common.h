#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <unistd.h>
#include <elf.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <getopt.h>
#include <dirent.h>
#include <errno.h>

#if !defined(__arm__) && !defined(__aarch64__)
#error "This code is for ARM and AARCH64 only"
#endif

#define log_err(fmt,args...) do { fprintf(stderr, fmt, ##args); fflush(stderr); } while(0);
#define log_info(fmt,args...) do { if(verbose) { printf(fmt, ##args); fflush(stdout); } } while(0)
#define log_debug(fmt,args...) do { if(verbose > 1) { printf(fmt, ##args); fflush(stdout); } } while(0)

#ifndef ELF_BITS
#error	ELF_BITS not defined.
#endif

#define __ENAME(PRE,BITS,POST) PRE ## BITS ## _ ## POST
#define _ENAME(PRE,BITS,POST) __ENAME(PRE,BITS,POST)
#define ENAME(PRE,POST) _ENAME(PRE,ELF_BITS,POST)  

#define Elf_Ehdr        ENAME(Elf,Ehdr)
#define Elf_Shdr        ENAME(Elf,Shdr) 
#define Elf_Sym         ENAME(Elf,Sym)
#define Elf_Rela        ENAME(Elf,Rela)

#define ELF_R_SYM	ENAME(ELF,R_SYM)
#define ELF_R_TYPE	ENAME(ELF,R_TYPE)
#ifndef ELF_ST_TYPE
#define ELF_ST_TYPE	ENAME(ELF,ST_TYPE)
#define ELF_ST_BIND	ENAME(ELF,ST_BIND)
#endif

typedef struct _libinfo {
    char *name;				/* full path to shared library file */
    off_t load_addr;			/* address of first segment in target process addrspace */
    void *img;				/* address of its mapping to our process addrspace */
    void *dlhandle;			/* for test case */
    size_t img_size;
    off_t dynsym_offset, dynstr_offset;	/* file offsets of ".dynsym" and ".dynstr" sections */	
    size_t dynsym_size, dynstr_size;	/* sizes of these sections */	
    struct _libinfo *next;
} lib_info;

typedef struct _layout {
    void *base;					/* start loading address in target process addrspace (2nd pass) */
    void *mem;					/* start loading address in our process addrspace */
    off_t plt, got, bss;			/* PLT/GOT/BSS offsets from start address */
    size_t plt_size, got_size, bss_size;	/* their sizes (updated during 1st pass, must be 0 on entry to setup_image()) */
    size_t max_plt, max_got;			/* size limits (set to max_*_size for 1st pass, and to calculated sizes thereafter) */
    off_t entry_offs;				/* entry point offset found in object file during 1st pass */	
    off_t startup_offs;				/* offset of startup code that creates a new thread and calls entry point */
} layout;

extern int verbose;

/* Add library ("name" = its full path) to a linked lib_info list for symbol name resolution */
extern int add_lib(pid_t pid, lib_info **libs, char *name);

/* Process sections updating layout memory */
extern int setup_image(layout *lay, lib_info *loaded_libs, char *start_name);


