#include        "common.h"

#define R_ARM_NONE			0
/* platforms/android-21/arch-arm64/usr/include/machine/elf_machdep.h: 
   why redefine R_AARCH64_NONE=0 to 256 which is clearly marked as WITHDRAWN in specs?! */
#ifdef R_AARCH64_NONE
#undef R_AARCH64_NONE
#endif
#define R_AARCH64_NONE			0

#ifdef __arm__
#define R_ARM_ABS32			2
#define R_ARM_REL32			3
#define R_ARM_CALL			28
#define R_ARM_THM_CALL			10
#define R_ARM_JUMP24			29
#define R_ARM_THM_JUMP24		30
#define R_ARM_BASE_PREL			25
#define R_ARM_GOT_BREL			26
#define	R_ARM_GOTOFF32			24
#define	R_ARM_PREL31			42
#define R_ARM_GOT_PREL			96
#define R_ARM_THM_JUMP11		102
#define R_ARM_THM_JUMP8			103
/* On Linux board, no such relocs in Android */
#define R_ARM_MOVW_ABS_NC		43
#define R_ARM_MOVT_ABS			44
#define R_ARM_THM_MOVW_ABS_NC		47
#define R_ARM_THM_MOVT_ABS		48
#else	/* __aarch64__ */
#define R_AARCH64_ABS64			257
#define R_AARCH64_ABS32			258
#define R_AARCH64_ADR_PREL_PG_HI21	275
#define R_AARCH64_ADR_PREL_PG_HI21_NC	276
#define R_AARCH64_ADD_ABS_LO12_NC	277
#define R_AARCH64_JUMP26		282
#define	R_AARCH64_CALL26		283
#define R_AARCH64_ADR_GOT_PAGE		311
#define R_AARCH64_LD64_GOT_LO12_NC	312
#define R_AARCH64_LDST8_ABS_LO12_NC	278
#define R_AARCH64_LDST16_ABS_LO12_NC	284
#define R_AARCH64_LDST32_ABS_LO12_NC	285
#define R_AARCH64_LDST64_ABS_LO12_NC	286
#define R_AARCH64_LDST128_ABS_LO12_NC	299
#define R_AARCH64_PREL64		260
#define R_AARCH64_PREL32		261
#endif

#define RELN(A)  [A] = #A
#ifdef __arm__
static const char *rel_names[] = {
   RELN(R_ARM_NONE), RELN(R_ARM_ABS32), RELN(R_ARM_REL32), RELN(R_ARM_PREL31), RELN(R_ARM_CALL),
   RELN(R_ARM_THM_CALL), RELN(R_ARM_JUMP24), RELN(R_ARM_THM_JUMP24), RELN(R_ARM_BASE_PREL), RELN(R_ARM_GOTOFF32),
   RELN(R_ARM_GOT_BREL), RELN(R_ARM_GOT_PREL), RELN(R_ARM_MOVW_ABS_NC), RELN(R_ARM_MOVT_ABS), 
   RELN(R_ARM_THM_JUMP8), RELN(R_ARM_THM_JUMP11),	
   RELN(R_ARM_THM_MOVW_ABS_NC), RELN(R_ARM_THM_MOVT_ABS),
};
static const int align_maxlen = sizeof("R_ARM_THM_MOVW_ABS_NC") + 1;
#else
static const char *rel_names[] = {
   RELN(R_AARCH64_NONE), RELN(R_AARCH64_ABS64), RELN(R_AARCH64_ABS32),
   RELN(R_AARCH64_ADR_PREL_PG_HI21), RELN(R_AARCH64_ADR_PREL_PG_HI21_NC),
   RELN(R_AARCH64_ADD_ABS_LO12_NC), RELN(R_AARCH64_JUMP26), RELN(R_AARCH64_CALL26),
   RELN(R_AARCH64_ADR_GOT_PAGE), RELN(R_AARCH64_LD64_GOT_LO12_NC),
   RELN(R_AARCH64_LDST8_ABS_LO12_NC), RELN(R_AARCH64_LDST16_ABS_LO12_NC),	
   RELN(R_AARCH64_LDST32_ABS_LO12_NC), RELN(R_AARCH64_LDST64_ABS_LO12_NC),	
   RELN(R_AARCH64_LDST128_ABS_LO12_NC),	RELN(R_AARCH64_PREL32), RELN(R_AARCH64_PREL64),
};
static const int align_maxlen = sizeof("R_AARCH64_ADR_PREL_PG_HI21_NC") + 1;
#endif
static const int rel_nsz = (sizeof(rel_names))/sizeof(char *);

#if 0
All arm/aarch64 relocations generated in Android source tree:

find google/out/target/product/hammerhead/obj -name \*\.o | xargs readelf -r | grep R_ARM | awk '{ print $3 }' | sort | uniq
R_ARM_ABS32			+
R_ARM_BASE_PREL			+
R_ARM_CALL			+
R_ARM_GOT_BREL			+
R_ARM_GOTOFF32			+ (clang)
R_ARM_GOT_PREL			+ (clang)
R_ARM_JUMP24			+
R_ARM_NONE			+
R_ARM_PREL31			+ (clang)
R_ARM_REL32			+
R_ARM_TARGET1			- (dont care, (PRE)INIT/FINI_ARRAYS, platform-specific) (CPP forbids don-apostophe-t:))
R_ARM_TARGET2			- (dont care, platform-specific)
R_ARM_THM_CALL			+
R_ARM_THM_JUMP11		- (not tested)
R_ARM_THM_JUMP24		+
R_ARM_THM_JUMP8			- (not tested)
R_ARM_V4BX			- (dont care, armv4 compatibility relocation for BX branches)

find google/out/target/product/flounder/obj -name \*\.o | xargs aarch64-linux-android-objdump -r | grep R_AARCH64 | awk '{ print $3 }' | sort | uniq
R_AARCH64_ABS32			+
R_AARCH64_ABS64			+
R_AARCH64_ADD_ABS_LO12_NC	+
R_AARCH64_ADR_GOT_PAGE		+
R_AARCH64_ADR_PREL_PG_HI21	+
R_AARCH64_CALL26		+
R_AARCH64_CONDBR19		- (conditional branch)
R_AARCH64_JUMP26		+
R_AARCH64_LD64_GOT_LO12_NC	+
R_AARCH64_LDST128_ABS_LO12_NC	+
R_AARCH64_LDST16_ABS_LO12_NC	+
R_AARCH64_LDST32_ABS_LO12_NC	+
R_AARCH64_LDST64_ABS_LO12_NC	+
R_AARCH64_LDST8_ABS_LO12_NC	+
R_AARCH64_PREL32		- (not tested)
R_AARCH64_PREL64		- (not tested)
#endif

#define ELF_REL_ERR     -1

static inline Elf_Shdr *section_hdr(Elf_Ehdr *elf, int idx) {
    if(idx > elf->e_shnum) return 0;	
    return (Elf_Shdr *) ((void *) elf + elf->e_shoff + elf->e_shentsize * idx);
}

static inline char *section_name(Elf_Ehdr *elf, int idx) {
    if(elf->e_shstrndx == SHN_UNDEF) return 0;	
    return (char *) elf + section_hdr(elf, elf->e_shstrndx)->sh_offset + section_hdr(elf, idx)->sh_name;	
}


static off_t handle_external_symbol(uint32_t rel_type, char *name, layout *lay, lib_info *loaded_libs)
{
#ifdef __arm__
    uint32_t plt_code_arm[3] = {
	0xe59fc000,	/* ldr	ip, jump_ptr  */
	0xe1a0f00c,	/* mov	pc, ip	      */
	0		/* jump_ptr:  .word 0 */
    };
    uint32_t plt_code_thumb[3] = {
	0xc004f8df,	/* ldr.w ip, jump_ptr */
	0xbf004760,	/* bx ip; nop	      */
	0		/* jump_ptr:  .word 0 */
    };
#else
    uint64_t plt_code_aarch64[2] = {
	0xd61f020058000050, 	/* ldr x16, jump_ptr; br x16; */
	0			/* jump_ptr: .word 0,0 */
    };	
#endif

    lib_info *lib;
    Elf_Sym *sym;
    off_t addr = 0, offs;
    void *plt_code;
    int k, code_size;	
    void *dest;	
	
	/* Try finding definition of this symbol in loaded libs */

	for(lib = loaded_libs; !addr && lib; lib = lib->next) {
	    for(k = 0, sym = (Elf_Sym *) (lib->img + lib->dynsym_offset); 
			k < lib->dynsym_size; k += sizeof(Elf_Sym), sym++) 
		if(strcmp(name, lib->img + lib->dynstr_offset + sym->st_name) == 0) {
		    if(sym->st_shndx == SHN_UNDEF) continue;  /* sym referenced but not defined here */
		    addr = lib->load_addr + sym->st_value;
		    log_debug("[%s] [0x%lx]", lib->name, addr);
		    break;
		}
	}

	if(!addr) {
	    if(strcmp(name, "_GLOBAL_OFFSET_TABLE_") == 0) return lay->got;	/* we create our own GOT */
	    log_err("\nfailed to find symbol \"%s\" in loaded libs\n", name);
	    return 0;
	}

	memset(&plt_code, 0, sizeof(plt_code));

	switch(rel_type) {
#ifdef __arm__
	    /* 32-bit call/jump relocations */	
	    case R_ARM_JUMP24: 
	    case R_ARM_CALL:		
 		/* check if already added to PLT */
		for(k = 0; k < lay->plt_size; k += sizeof(plt_code_arm)) {
		    offs = lay->plt + k;
		    dest = lay->mem + offs;	
		    if(((uint32_t *)dest)[2] == (uint32_t) addr) {
			log_debug(" (reused in PLT)");	
			if(rel_type == R_ARM_ABS32) return addr;
			return offs;
		    }
		}
		/* add new PLT entry */
		code_size = sizeof(plt_code_arm);
		plt_code = plt_code_arm;
		((uint32_t *) plt_code)[2] = addr;
		break;
	    case R_ARM_THM_JUMP24: 
	    case R_ARM_THM_CALL:
		for(k = 0; k < lay->plt_size; k += sizeof(plt_code_thumb)) {
		    offs = lay->plt + k;
		    dest = lay->mem + offs;	
		    if(((uint32_t *)dest)[2] == (uint32_t) addr) {
			log_debug(" (reused in PLT)");		
			return offs;
		    }
		}
		code_size = sizeof(plt_code_thumb);
		plt_code = plt_code_thumb;
		((uint32_t *) plt_code)[2] = addr;
		break;
#else
	    /* 64-bit call/jump relocations */	
	    case R_AARCH64_JUMP26: 
	    case R_AARCH64_CALL26:
		for(k = 0; k < lay->plt_size; k += sizeof(plt_code_aarch64)) {
		    offs = lay->plt + k;
		    dest = lay->mem + offs;	
		    if(((uint64_t *)dest)[1] == (uint64_t) addr) {
			log_debug(" (reused in PLT)");		
			return offs;
		    }
 		}
		code_size = sizeof(plt_code_aarch64);
		plt_code = plt_code_aarch64;
		((int64_t *) plt_code)[1] = addr;
		break;
#endif
	    default: 
		/* Must be data relocation */
		return addr;
	}
	if(lay->plt_size + code_size > lay->max_plt) {	
	    log_err("\nmax_plt_size 0x%lx exceeded, please increase it\n", (long) lay->max_plt);
	    return 0;
	}
	offs = lay->plt + lay->plt_size;
	dest = lay->mem + offs;
	memcpy(dest, plt_code, code_size);
	log_debug(" (added to PLT)");
	lay->plt_size += code_size;

    return (long) offs;
}

static int relocate(int type, Elf_Shdr *reltab, Elf_Rela *rel, layout *lay, lib_info *loaded_libs)
{
    uint32_t sym = ELF_R_SYM(rel->r_info);	
    uint32_t rel_type = ELF_R_TYPE(rel->r_info);

    Elf_Shdr *target = section_hdr((Elf_Ehdr *)lay->mem, reltab->sh_info);
    Elf_Shdr *symtab = section_hdr((Elf_Ehdr *)lay->mem, reltab->sh_link);
    Elf_Shdr *strtab = section_hdr((Elf_Ehdr *)lay->mem, symtab->sh_link);

    Elf_Sym *symbol;
    char *name;
    long sym_addr = 0;

    long offs = target->sh_offset + rel->r_offset; 
    int32_t *rel_addr = (int32_t *) (lay->mem + offs);		/* instruction/data address to be patched */	
    long base = (long) (lay->base ? lay->base : lay->mem);	/* base for local symbols */
    void *dest;
    int  k;
    long rval;

	/* calculate sym_addr */

	if(sym == SHN_UNDEF || reltab->sh_link == SHN_UNDEF) {
	    if(rel_type != R_ARM_NONE) {
		log_err("symbol %d and/or symtab %d undefined, dunno how to apply %s\n", 
		    sym, reltab->sh_link, (rel_type < rel_nsz)? rel_names[rel_type] : 
		    "unknown reloc type");
		return ELF_REL_ERR;
	    }	
	    return 0;
	}

	if(sym > symtab->sh_size / symtab->sh_entsize) {
	    log_err("symbol %d outside symtab limits\n", sym);
	    return ELF_REL_ERR;
	}

	symbol = (Elf_Sym *) (lay->mem + symtab->sh_offset) + sym; 	
	name = (char *) lay->mem + strtab->sh_offset + symbol->st_name; 	

	log_debug("%*s at %s:%lx\tname=%s ", align_maxlen,
		(rel_type < rel_nsz && rel_names[rel_type])? rel_names[rel_type] : "UNKNOWN",
		section_name(lay->mem, reltab->sh_info), 
		(long)rel->r_offset, symbol->st_name ? name : "<unnamed>");

	if(symbol->st_shndx == SHN_UNDEF) {
	    /* External symbol, look it up in libs and set up plt entry */
	    sym_addr = handle_external_symbol(rel_type, name, lay, loaded_libs);
	    if(!sym_addr) {
		log_err("-- undefined external symbol\n");
		return ELF_REL_ERR;
	    }
	} else if(symbol->st_shndx == SHN_ABS) {
	    /* Absolute symbol */
	    sym_addr = symbol->st_value;
	    log_debug("-- absolute, addr=%lx", sym_addr);
	} else {
	    /* Symbol relative to some section */
	    Elf_Shdr *section = section_hdr((Elf_Ehdr *)lay->mem, symbol->st_shndx);
	    if(section->sh_type == SHT_NOBITS) sym_addr = lay->bss + symbol->st_value;	/* single bss section assumed! */
	    else sym_addr = section->sh_offset + symbol->st_value; /* other ones go as is */
	    log_debug("[sect=%s]", section_name(lay->mem, symbol->st_shndx));
	}

	if(type == SHT_RELA) sym_addr += rel->r_addend;		/* RELA seem to occur on aarch64 only */

	/* do actual relocation */
	switch(rel_type) {

#ifdef __arm__
	    /* 32-bit relocations */	

	    case R_ARM_NONE:
		break;	

	    case R_ARM_ABS32:
		if(symbol->st_shndx != SHN_UNDEF) sym_addr += base;
		*rel_addr += sym_addr;
		break;	

	    case R_ARM_REL32:
		*rel_addr += (sym_addr - offs);
		break;		

	    case R_ARM_PREL31:
		sym_addr -= offs;
		sym_addr = (sym_addr & 0x40000000) ? (sym_addr | 0x80000000) : (sym_addr & ~0x80000000) ;
		*rel_addr += sym_addr;
		break;		

	    case R_ARM_JUMP24:	
	    case R_ARM_CALL:		
		*rel_addr = (*rel_addr & 0xff000000) | ((sym_addr - offs - 8)/4 & 0xffffff); /* (8 = ref. pc) */
		break;

	    case R_ARM_THM_JUMP24:	
	    case R_ARM_THM_CALL:
		{
		    uint32_t t = (ELF_ST_TYPE(symbol->st_info) == STT_FUNC); 
		    uint32_t sa = ((sym_addr | t) - offs - 4)/2;			    /* (4 = ref. pc) */
		    uint16_t *r = (uint16_t *) rel_addr;
		    uint32_t s = (sa >> 24) & 1;
			r[0] = (r[0] & ~0x7ff) | ((sa >> 11) & 0x3ff) | (s << 10);
			r[1] = (r[1] & ~0x2fff) | (sa & 0x7ff) 
				| (((~((sa >> 23) ^ s)) & 1) << 13) | (((~((sa >> 22) ^ s)) & 1) << 11);
		}
		break;

	    case R_ARM_BASE_PREL:			/* B(S) + A – P */
		log_debug("GOT at %lx", sym_addr);
		*rel_addr += (sym_addr - offs);
		break;

	    case R_ARM_GOT_BREL:
	    case R_ARM_GOT_PREL:
	    case R_ARM_GOTOFF32:
		rval = (symbol->st_shndx == SHN_UNDEF) ? sym_addr : sym_addr + base;
		/* check if this address is already in GOT */
		for(k = 0; k < lay->got_size; k += 4) {
		    dest = lay->mem + lay->got + k;
		    if(*(long *) dest == rval) break;
		}
		switch(rel_type) {
		    case R_ARM_GOT_BREL:		/* GOT(S) + A – GOT_ORG */
			*rel_addr = k;
			break;
		    case R_ARM_GOT_PREL:		/* GOT(S) + A – P */
			*rel_addr += lay->got + k - offs;
			break;
		    case R_ARM_GOTOFF32:		/* ((S + A) | T) – GOT_ORG */
			*rel_addr += (sym_addr | (ELF_ST_TYPE(symbol->st_info) == STT_FUNC)) - lay->got;
			break;
		}
		if(k < lay->got_size) {
		    log_debug("(reused in GOT)");	
		    return 0;	
		}
		/* not found, add new GOT entry */
		if(lay->got_size + 4 > lay->max_got) {	
		    log_err("max_got_size 0x%x exceeded, please increase it\n", lay->max_got);
		    return ELF_REL_ERR;		
		}
		dest = lay->mem + lay->got + k; /* k == lay->got_size, store new GOT entry */
		*(long *) dest = rval;
		log_debug(" [addr=0x%lx] (added to GOT)", rval);
		lay->got_size += 4;
		break;

	    case R_ARM_THM_MOVW_ABS_NC:		
	    case R_ARM_THM_MOVT_ABS:		/* range check needed for MOVT */
		{
		    uint16_t s, *r = (uint16_t *) rel_addr;
		    uint32_t sa = sym_addr;
			if(symbol->st_shndx != SHN_UNDEF) sa += base;
			s = (rel_type == R_ARM_THM_MOVT_ABS) ? (sa >> 16) : (sa & 0xffff);
			r[0] = (r[0] & ~0x040f) | (s >> 12) /* 12-15 -> 0-3 */ | ((s >> 1) & 0x400); /* 11 -> 10 */ 
			r[1] = (r[1] & ~0x70ff) | ((s << 4) & 0x7000) /* 8-10 -> 12-14 */ | (s & 0xff);
		}
		break;

	    case R_ARM_MOVW_ABS_NC:
	    case R_ARM_MOVT_ABS:		/* range check needed for MOVT */
		{
		    uint32_t sa = sym_addr;
			if(symbol->st_shndx != SHN_UNDEF) sa += base;
			sa = (rel_type == R_ARM_MOVT_ABS) ? (sa >> 16) : (sa & 0xffff) ;
			*rel_addr = (*rel_addr & ~0xf0fff) | ((sa << 4) & ~0xffff) | (sa & 0xfff);
		}
		break;
#else
	    /* 64-bit relocations */	

	    case R_AARCH64_NONE:
		break;

	    case R_AARCH64_ABS32:
//		if(symbol->st_shndx != SHN_UNDEF) sym_addr += base;
		if(sym_addr >= 0x100000000 || sym_addr < (int64_t) 0xffffffff80000000) {
		    log_err("\n-- absolute 32-bit offset out of range: %llx\n", (long long) sym_addr);	
		    return ELF_REL_ERR;	
		}
		*((uint64_t *) rel_addr) += sym_addr;
		break;	


	    case R_AARCH64_ABS64:
		if(symbol->st_shndx != SHN_UNDEF) sym_addr += base;
		*((uint64_t *) rel_addr) += sym_addr;
		break;	

	    case R_AARCH64_PREL32:	
		sym_addr -= offs;
		if(sym_addr >= 0x100000000 || sym_addr < (int64_t) 0xffffffff80000000) {
		    log_err("\n-- absolute 32-bit offset out of range: %llx\n", (long long)sym_addr);	
		    return ELF_REL_ERR;	
		}
		*((uint64_t *) rel_addr) += sym_addr;
		break;	
			
	    case R_AARCH64_PREL64:
		*((uint64_t *) rel_addr) += (sym_addr - offs);
		break;	

	    case R_AARCH64_ADR_PREL_PG_HI21:
		if(symbol->st_shndx == SHN_UNDEF) offs += base;		/* offset must point to real page! */
	    adrp_prel:
		rval = (sym_addr >> 12) - (offs >> 12);
		if((rval << 12) >= 0x100000000 || (rval << 12) < (int64_t) 0xffffffff00000000) {
		    log_err("\n-- page offset %llx out of range\n", (long long) rval);
		    return ELF_REL_ERR;	
		}
		*rel_addr = (*rel_addr & ~0x60ffffe0) | ((rval << 29) & 0x60000000) 
				| ((rval << 3) & 0xffffe0);
		break;

	    case R_AARCH64_ADR_PREL_PG_HI21_NC:		/* same as above with no overrange check */
		if(symbol->st_shndx == SHN_UNDEF) offs += base;		/* !!! */
		rval = (sym_addr >> 12) - (offs >> 12);
		*rel_addr = (*rel_addr & ~0x60ffffe0) | ((rval << 29) & 0x60000000) 
				| ((rval << 3) & 0xffffe0);
		break;        

	    case R_AARCH64_ADD_ABS_LO12_NC:
	    add_offs12:	
		sym_addr += base;
		rval = ((sym_addr & 0xfff) << 10);
		*rel_addr = (*rel_addr & 0xffc003ff) | rval;
		break;

	    case R_AARCH64_JUMP26:
	    case R_AARCH64_CALL26:
		rval = (sym_addr - offs)/4;
		if(rval >= 0x8000000 || rval < (int64_t) 0xfffffffff8000000) {
		    log_err("\n-- branch offset %llx out of range\n", (long long) rval);
		    return ELF_REL_ERR;	
		}	
		*rel_addr = (*rel_addr & 0xfc000000) | (rval & 0x3ffffff);
		break;

	    case R_AARCH64_ADR_GOT_PAGE:
		if(symbol->st_shndx != SHN_UNDEF) sym_addr += base;
		/* check if this address is already in GOT */
		for(k = 0; k < lay->got_size; k += 8) {
		    dest = lay->mem + lay->got + k;
		    if(*(long *) dest == sym_addr) {
			log_debug(" (reused in GOT)");
			sym_addr = lay->got + k;
			goto adrp_prel;
		    }
		}
		/* not found, add new GOT entry */
		if(lay->got_size + 8 > lay->max_got) {	
		    log_err("max_got_size 0x%lx exceeded, please increase it\n", lay->max_got);
		    return ELF_REL_ERR;		
		}
		dest = lay->mem + lay->got + lay->got_size;
		*(long *) dest = sym_addr;				/* add to GOT */
		log_debug(" [addr=0x%lx] (added to GOT)", sym_addr);
		sym_addr = lay->got + lay->got_size;
		lay->got_size += 8;
		goto adrp_prel;

	    case R_AARCH64_LD64_GOT_LO12_NC:
		rval = sym_addr;
		if(symbol->st_shndx != SHN_UNDEF) rval += base;
		for(k = 0; k < lay->got_size; k += 8) {			/* obtain GOT entry address */
		    dest = lay->mem + lay->got + k;
		    if(*(long *) dest == rval) {
			sym_addr = ((lay->got + k) & 0xfff)/8;	/* offset must be in qwords for LDR */
			goto add_offs12;
		    }
		}
		log_err("\nNot found in GOT: ADR/LDR must be out of order, NEED A FIX!\n");	
		return ELF_REL_ERR;
		
	    case R_AARCH64_LDST128_ABS_LO12_NC:
		rval = ((sym_addr & 0xff0) << 6);
		*rel_addr = (*rel_addr & 0xffc003ff) | rval;
		break;	

	    case R_AARCH64_LDST64_ABS_LO12_NC:
		rval = ((sym_addr & 0xff8) << 7);
		*rel_addr = (*rel_addr & 0xffc003ff) | rval;
		break;	

	    case R_AARCH64_LDST32_ABS_LO12_NC:
		rval = ((sym_addr & 0xffc) << 8);
		*rel_addr = (*rel_addr & 0xffc003ff) | rval;
		break;	

	    case R_AARCH64_LDST16_ABS_LO12_NC:
		rval = ((sym_addr & 0xffe) << 9);
		*rel_addr = (*rel_addr & 0xffc003ff) | rval;
		break;	

	    case R_AARCH64_LDST8_ABS_LO12_NC:
		rval = ((sym_addr & 0xfff) << 10);
		*rel_addr = (*rel_addr & 0xffc003ff) | rval;
		break;	
#endif
	    default:
		log_err("\nUnsupported relocation type %d\n", rel_type);
		return ELF_REL_ERR;
	}
	log_debug("\n");
    return 0;
}


int setup_image(layout *lay, lib_info *loaded_libs, char *start_name)
{

    int i, k, bss = 0, ret = 0;
    Elf_Ehdr *elf = (Elf_Ehdr *) lay->mem;
    void *c, *cc, *names;
    Elf_Shdr *sh, *strtab;


	for(c = lay->mem + elf->e_shoff, k = 0; k < elf->e_shnum; k++, c += elf->e_shentsize) {
	    sh = (Elf_Shdr *) c;	
	    if(verbose > 2) {
		log_debug("%d: \"%s\"\n\tsh_type=%x, sh_flags=%lx, sh_addr=%lx, sh_offset=%lx, sh_size=%lx,\n" 
	   	"     \tsh_link=%d, sh_info=%d, sh_addralign=%lx, sh_entsize=%lx\n", k, section_name(elf, k), 
		sh->sh_type, (long) sh->sh_flags, (long) sh->sh_addr, (long) sh->sh_offset, (long) sh->sh_size, 
		sh->sh_link, sh->sh_info, (long) sh->sh_addralign, (long) sh->sh_entsize);
	    }
	    switch(sh->sh_type) {
		case SHT_REL:
		case SHT_RELA:
		    for(cc = lay->mem + sh->sh_offset, i = 0; i < sh->sh_size/sh->sh_entsize; i++, cc += sh->sh_entsize) {	
			Elf_Rela *rel = (Elf_Rela *) cc;
			if(relocate(sh->sh_type, sh, rel, lay, loaded_libs) != 0) {
			    ret = -1;
			    goto done;
			}	
		    }
		    break;
		case SHT_SYMTAB:
		    strtab = section_hdr(elf, sh->sh_link);
		    names = (char *) elf + strtab->sh_offset;		
		    for(cc = lay->mem + sh->sh_offset, i = 0; i < sh->sh_size/sh->sh_entsize; i++, cc += sh->sh_entsize) {
			Elf_Sym *sym = (Elf_Sym *) cc;
			if(strcmp(names + sym->st_name, start_name) == 0) {
			    lay->entry_offs = section_hdr(elf, sym->st_shndx)->sh_offset + sym->st_value;
			    log_debug("\t=> found '%s' at 0x%lx (0x%lx) in section %d\n", 
					start_name, (long)sym->st_value, lay->entry_offs, sym->st_shndx);		
			}
		    }
		    break;
	    	case SHT_NOBITS: 
		    if(bss) {
			log_err("Multiple NOBITS (a.k.a. BSS) sections not supported.\n"
				"Please merge \"%s\" and \"%s\" in object file.\n",
				section_name(elf, bss), section_name(elf, k));
			ret = -1;
			goto done;	
		    }	
		    lay->bss_size = sh->sh_size;
		    bss = k;
		    break;
	    }	
	}
    done:
	
    return ret;
}

int add_lib(pid_t target_pid, lib_info **loaded_libs, char *name)
{
    lib_info *lib;
    char tmp[512];
    FILE *maps = 0;
    int fd, k, link;
    Elf_Ehdr *e;
    Elf_Shdr *sh;
    int itr = 0;

	lib = (lib_info *) calloc(1, sizeof(lib_info));
	lib->name = strdup(name);
	lib->img = MAP_FAILED;

    retry:
	sprintf(tmp, "/proc/%d/maps", target_pid ? target_pid : getpid());
    	maps = fopen(tmp, "r");
	if(!maps) {
	    log_err("cannot open %s\n", tmp);
	    goto err_load;
	}
	while(fgets(tmp, sizeof(tmp), maps))
	    if(strstr(tmp, name)) {
		if(sscanf(tmp, "%lx", &lib->load_addr) != 1) {
		    log_err("cannot read load_addr for %s in proc\n", name);
		    fclose(maps);	
		    goto err_load;	
		}
		break;	
	    }
	fclose(maps);
	if(!lib->load_addr) {
	    if(!target_pid && !itr) {
		itr = 1;
		lib->dlhandle = dlopen(name, RTLD_NOW);
		if(lib->dlhandle) {
		    log_debug("%s wasn't loaded to our addrspace, retrying\n", name);	
		    goto retry;	
		}
	    }
	    log_err("failed to find load_addr of %s in addrspace of pid=%d\n", name, target_pid);
	    goto err_load;	
	}
	fd = open(name, O_RDONLY);
	if(fd < 0) {
	    log_err("failed to open %s\n", name);
	    goto err_load;	
	}
	lib->img_size = lseek(fd, 0, SEEK_END);
	lib->img = mmap(0, lib->img_size, PROT_READ, MAP_PRIVATE, fd, 0);
	close(fd);
	if(lib->img == MAP_FAILED) {
	    log_err("failed to map %s\n", name);
	    goto err_load;	
	}
	if(strncmp((char *)lib->img, ELFMAG, 4) != 0) {
	    log_err("%s: not an elf file\n", name);
	    goto err_load;
	}
	e = (Elf_Ehdr *) lib->img;
	if(e->e_ident[EI_NIDENT] != ET_DYN || e->e_ident[EI_NIDENT+1] != 0) {
	    log_err("%s: not a shared library\n", name);
	    goto err_load;	
	}

#ifdef __arm__
	if(e->e_ident[EI_CLASS] != ELFCLASS32 || e->e_machine != EM_ARM) 
#else
	if(e->e_ident[EI_CLASS] != ELFCLASS64 || e->e_machine != EM_AARCH64) 
#endif
	{
	    log_err("%s: 32/64 library conflict\n", name);
	    goto err_load;
	}	

	link = 0;
	for(k = 0; k < e->e_shnum; k++)  {
	    sh = (Elf_Shdr *) (lib->img + e->e_shoff + e->e_shentsize * k);
	    if(sh->sh_type == SHT_DYNSYM) {
		lib->dynsym_offset = sh->sh_offset;
		lib->dynsym_size = sh->sh_size;
		link = sh->sh_link;
		break;
	    }
	}
	if(!link) {
	    log_err("failed to find DYNSYM section in %s\n", name);
	    goto err_load;	
	}
	sh = (Elf_Shdr *) (lib->img + e->e_shoff + e->e_shentsize * link);
	if(sh->sh_type != SHT_STRTAB) {
	    log_err("DYNSYM section in %s does not point to STRTAB\n", name);
	    goto err_load;	
	}

	lib->dynstr_offset = sh->sh_offset;
	lib->dynstr_size = sh->sh_size;

	log_debug("%s added, load_addr=0x%lx\n", name, (long) lib->load_addr);

	if(!*loaded_libs) *loaded_libs = lib;
	else {
	    lib_info *ll;
	    for(ll = *loaded_libs; ll->next; ll = ll->next) ;
	    ll->next = lib;	
	}
	return 0;

    err_load:
	if(lib->name) free(lib->name);
	if(lib->img != MAP_FAILED) munmap(lib->img, lib->img_size);
	free(lib);
	return -1;		
}


