#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/prctl.h>
#include <signal.h>
#include <android/dlext.h>
#include <android/log.h>

#ifndef __arm__
#error "This patch is for 32-bit ARM code only."
#endif

#define TAG_NAME  "process_patch"
#define log_info(fmt, args...)  __android_log_print(ANDROID_LOG_INFO, TAG_NAME, "[%s] " fmt, __func__, ##args)
#define log_err(fmt, args...)   __android_log_print(ANDROID_LOG_ERROR, TAG_NAME, "[%s] " fmt, __func__, ##args)

#define PDEBUG 1

#ifdef PDEBUG
#define log_debug(fmt, args...)   __android_log_print(ANDROID_LOG_DEBUG, TAG_NAME, "[%s] " fmt, __func__, ##args)
#else
#define log_debug(...)
#endif

/*  Do take care to set this (used for linker's dlfncs only)  */
#define OREO 1	

#define TERM_SIGNAL	SIGUSR2

/* 
    An example demonstrating how to intercept calls to a particular function using injector.
    Make sure to set/remove -mthumb flag in Makefile to match the arm/thumb mode of TARGET_LIB.
    (Warning: libc needs a special patch since nougat!)
    
    Run:	
    ./injector32 -n <process name> patch_func.o \
	/system/lib/libc.so /system/lib/liblog.so /system/bin/linker <TARGET_LIB>

    Stop: killall -SIGUSR2 <process_name>. 
    Then it's safe to use the cleanup command output by injector before.
    Here, the process_name is mediaserver, or audioserver in nougat or later.

    Change these three TARGET_* #defines and patch_func below as necessary. 
    You may leave TARGET_FUNC undefined; then, provide code at the very start of main() 
    to calculate func_addr. 
*/

#if 0
#define TARGET_LIB "/system/lib/libaudiopolicymanagerdefault.so"
#define TARGET_FUNC _ZN7android18AudioPolicyManager14setInputDeviceEijbPi
#define TARGET_FUNC_ARGS  (void *pthis, int a, unsigned int b, bool c, int* d)
#else
#define TARGET_LIB "/system/lib/libtinyalsa.so"
#define TARGET_FUNC pcm_open
#define TARGET_FUNC_ARGS  (int card, int device, int flags, void *config)
#endif

#ifdef TARGET_FUNC
#define __N2STR(A) #A
#define _N2STR(A) __N2STR(A)
#define TARGET_FUNC_NAME  _N2STR(TARGET_FUNC)
#else
#define TARGET_FUNC_NAME "<unknown>"
#endif

static pthread_mutex_t patch_mutex = PTHREAD_MUTEX_INITIALIZER;
static int need_run = 1;
static int running = 0;

/* virgin TARGET_FUNC taken from TARGET_LIB copy */
static int (*func_copy) TARGET_FUNC_ARGS = 0;
extern int TARGET_FUNC TARGET_FUNC_ARGS;

static int patch_func TARGET_FUNC_ARGS
{
    int ret;

    pthread_mutex_lock(&patch_mutex);	

#if 0
    if(running) ret = func_copy(pthis, a, b, c, d);
    else ret = TARGET_FUNC(pthis, a, b, c, d);
    log_info("setInputDevice(input=%d, device=0x%x, force=%s, patchHandle=%d)=%d", 
		a, b, c ? "true":"false", d ? *d : 0, ret);	
#else
    log_info("opening \"hw:%d,%d\" [flags=0x%x]", card, device, flags);	
    if(running) ret = func_copy(card, device, flags, config);
    else ret = TARGET_FUNC(card, device, flags, config);
#endif

    pthread_mutex_unlock(&patch_mutex);	
    return ret;	
}

/************* No need to change anything below if TARGET_FUNC is defined *************/

#ifndef RTLD_NOLOAD
#define RTLD_NOLOAD        0x4
#endif

#ifndef ANDROID_DLEXT_FORCE_LOAD
#define ANDROID_DLEXT_FORCE_LOAD        0x40
#endif

#ifdef OREO
#define DLOPEN __dl__Z8__dlopenPKciPKv
#define DLSYM __dl__Z7__dlsymPvPKcPKv
#define DLCLOSE __dl__Z9__dlclosePv
#define DLOPEN_EXT __dl__Z20__android_dlopen_extPKciPK17android_dlextinfoPKv
#else
#define DLOPEN __dl_dlopen
#define DLSYM __dl_dlsym
#define DLCLOSE __dl_dlclose
#define DLOPEN_EXT __dl_android_dlopen_ext
#endif

/* Caller address is actually for Oreo only */
extern void *DLOPEN(const char *filename, int flag, const void *caller);
extern void *DLSYM(void *handle, const char *symbol, const void *caller);
extern int DLCLOSE(void *handle);
extern void * DLOPEN_EXT(const char* filename, int flag, const android_dlextinfo* extinfo, const void *caller);

static uint32_t patch[3] = {
#ifdef __thumb__
    0xc004f8df,				/* ldr.w ip, jump_ptr */
    0xbf004760,				/* bx ip;  nop        */
#else
    0xe59fc000,				/* ldr  ip, jump_ptr  */
    0xe1a0f00c,				/* mov  pc, ip	      */
#endif
    (uint32_t) &patch_func		/* jump_ptr: our function */
};


/* First instructions of TARGET_FUNC to save and replace with the patch below.
   We could usually restore them from func_copy, that'd require checking for relocations...   */
static uint32_t saved_instr[sizeof(patch)/sizeof(uint32_t)]; 

/* Won't bother loading libanrdoid_runtime just to clear cache after patching. */
static void clear_cache(void *from, void *to)
{
    register void *_from asm("r0") = from;
    register void *_to asm("r1") = to;
    asm volatile(
	"push	{r2,r7}\n\t"
	"mov	r7, %2\n\t"
	"mov	r2, #0\n\t"
	"svc	#0\n\t"
	"pop	{r2,r7}\n\t" : : "r" (_from), "r"(_to), "r"(0xf0002));
}

static void terminate(int sig) {
    log_info("exiting");	
    need_run = 0;
}

/***** Entry point ****/

int main(int argc, char **argv) 
{ 
    uint32_t func_addr, patch_addr;
    uint32_t prot_addr, prot_size;
    int ret = -1;
    void *caller = 0;
    android_dlextinfo extinfo;
    void *libcopy;

#ifdef TARGET_FUNC
	func_addr = (uint32_t) &TARGET_FUNC;	/* function to patch */
#else
	void *libloaded = DLOPEN(TARGET_LIB, RTLD_NOLOAD, caller);
	uint32_t ref_addr0, ref_addr1;
	char *ref_symbol_name;	
	/* 
	   HERE: code ending with "func_addr = ..."  
	*/
	func_addr = 0x1234;
#endif

	log_debug("patching...");
	log_debug("address of " TARGET_FUNC_NAME " in process space: 0x%08x", func_addr);

	memset(&extinfo, 0, sizeof(extinfo));
	extinfo.flags = ANDROID_DLEXT_FORCE_LOAD;

	/* forcibly load a copy of TARGET_LIB */

	libcopy = DLOPEN_EXT(TARGET_LIB, RTLD_NOW, &extinfo, caller);

	if(!libcopy) {
	    log_err("failed to load copy of " TARGET_LIB);
	    return -1;	
	}

#ifdef TARGET_FUNC
	func_copy = (typeof(func_copy)) DLSYM(libcopy, TARGET_FUNC_NAME, caller);
#else
	/* libhandle difference won't work in nougat or later; need a ref symbol present in TARGET_LIB */
	ref_symbol_name = "replace_me"; /* find_good_symbol(TARGET_LIB); -- too lazy to write this. */
	ref_addr0 = (uint32_t) DLSYM(libloaded, ref_symbol_name, caller);
	ref_addr1 = (uint32_t) DLSYM(libcopy, ref_symbol_name, caller);
	if(!ref_addr0 || !ref_addr1) {
	    log_err("%s is not found in " TARGET_LIB ", please provide a valid address", ref_symbol_name);
	    return -1;	
	}
	log_debug("ref function: 0x%x in loaded lib, 0x%x in lib copy", ref_addr0, ref_addr1);
	func_copy = (typeof(func_copy)) (func_addr - (ref_addr0 - ref_addr1));
	DLCLOSE(libloaded);
#endif

	if(!func_copy) {
	    log_err("failed to find " TARGET_FUNC_NAME " in loaded copy of " TARGET_LIB);
	    goto exit;
	}

	log_debug("address of " TARGET_FUNC_NAME " in library copy: %p", func_copy);
	log_debug("address of patch for " TARGET_FUNC_NAME ": %p", patch_func);

	prctl(PR_SET_NAME, (unsigned long) "hack");	/* give a name to our thread */

	patch_addr = ((uint32_t) func_addr) & ~1; 		/* thumb address bit cleared */
	prot_addr = ((uint32_t) func_addr) & ~0xfff; 		/* page aligned */
	prot_size = 0x1000;

	/* in case that we need to patch across the page boundary */
	if(((patch_addr + sizeof(patch)) & ~0xfff) != prot_addr) prot_size += 0x1000;

	/* can't just use the library copy as there might be relocations right away */
	memcpy(&saved_instr, (void *) patch_addr, sizeof(patch));

	if(mprotect((void *) prot_addr, prot_size, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
	    log_err("cannot change memory protection at 0x08%x [%s], aborted", 
		prot_addr, strerror(errno));
	    goto exit;
	}

	log_debug("patching at address 0x%08x", patch_addr);

	/* fingers crossed... */
	memcpy((void *) patch_addr, patch, sizeof(patch));
	clear_cache((void *) patch_addr, (void *) patch_addr + sizeof(patch)); 
	running = 1;

	if(mprotect((void *) prot_addr, prot_size, PROT_READ | PROT_EXEC) != 0) 
	    log_err("error: failed to restore original memory protection, continue anyway");

	log_info("patch loaded for " TARGET_FUNC_NAME);

	signal(TERM_SIGNAL, terminate);

	/* As an alternative, this trivial loop could be replaced by server code that 
	   would run on behalf of the target process until instructed to terminate. */

	while(need_run) sleep(1);
	
	pthread_mutex_lock(&patch_mutex);
	if(mprotect((void *) prot_addr, prot_size, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) 
	    log_err("cannot change memory protection at 0x%08x [%s], exiting anyway", prot_addr, strerror(errno));
	else {
	    memcpy((void *) patch_addr, &saved_instr, sizeof(patch));
	    clear_cache((void *) patch_addr, (void *) patch_addr + sizeof(patch)); 
	    if(mprotect((void *) prot_addr, prot_size, PROT_READ | PROT_EXEC) != 0) 
		log_err("error: failed to restore original memory protection");
	    else ret = 0;	
	}
	running = 0;
	pthread_mutex_unlock(&patch_mutex);

    exit: 
	DLCLOSE(libcopy);
	log_info("patch unloaded");	

	/* It's now safe to request "injector cleanup" to restore the initial mediaserver state completely. */

    return ret;
}



