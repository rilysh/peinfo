#ifndef PEINFO_H
# define PEINFO_H

#include <stdint.h>

/* Taken from:
   https://github.com/WerWolv/ImHex-Patterns/blob/255116a58781a110720d1abf8a0d35d1e4c65b09/patterns/pe.hexpat#L66
   For function: pe_coff_get_arch_name() */
#define TYPE_UNKNOWN        (0x0000)
#define TYPE_ALPHAAXPOLD    (0x0183)
#define TYPE_ALPHAAXP       (0x0184)
#define TYPE_ALPHAAXP64BIT  (0x0284)
#define TYPE_AM33           (0x01D3)
#define TYPE_AMD64          (0x8664)
#define TYPE_ARM            (0x01C0)
#define TYPE_ARM64          (0xAA64)
#define TYPE_ARMNT          (0x01C4)
#define TYPE_CLRPUREMSIL    (0xC0EE)
#define TYPE_EBC            (0x0EBC)
#define TYPE_I386           (0x014C)
#define TYPE_I860           (0x014D)
#define TYPE_IA64           (0x0200)
#define TYPE_LOONGARCH32    (0x6232)
#define TYPE_LOONGARCH64    (0x6264)
#define TYPE_M32R           (0x9041)
#define TYPE_MIPS16         (0x0266)
#define TYPE_MIPSFPU        (0x0366)
#define TYPE_MIPSFPU16      (0x0466)
#define TYPE_MOTOROLA68000  (0x0268)
#define TYPE_POWERPC        (0x01F0)
#define TYPE_POWERPCFP      (0x01F1)
#define TYPE_POWERPC64      (0x01F2)
#define TYPE_R3000          (0x0162)
#define TYPE_R4000          (0x0166)
#define TYPE_R10000         (0x0168)
#define TYPE_RISCV32        (0x5032)
#define TYPE_RISCV64        (0x5064)
#define TYPE_RISCV128       (0x5128)
#define TYPE_SH3            (0x01A2)
#define TYPE_SH3DSP         (0x01A3)
#define TYPE_SH4            (0x01A6)
#define TYPE_SH5            (0x01A8)
#define TYPE_THUMB          (0x01C2)
#define TYPE_WCEMIPSV2      (0x0169)

/* Compiler specific macros. */
/* Assuming you're using a GCC or Clang that has this attribute. */
#if defined (__GNUC__) || defined (__clang__)
# undef PROG_UNREACHABLE
# define PROG_UNREACHABLE()    __builtin_unreachable()
# undef PROG_NORETURN
# define PROG_NORETURN         __attribute__((noreturn))
# undef PROG_PACKED
# define PROG_PACKED           __attribute__((packed))
#else
# undef PROG_UNREACHABLE
# define PROG_UNREACHABLE()
# undef PROG_NORETURN
# define PROG_NORETURN
# undef PROG_PACKED
# define PROG_PACKED
#endif

/* Structures definitions. */
struct pe_dos_header {
        uint16_t e_magic;     /* Magic number. */
	uint16_t e_cblp;      /* Bytes on last page of file. */
	uint16_t e_cp;        /* Pages in files. */
	uint16_t e_crlc;      /* Relocations. */
	uint16_t e_cparhdr;   /* Size of header in paragraphs. */
	uint16_t e_minalloc;  /* Minimum extra  paragraphs needed. */
	uint16_t e_maxalloc;  /* Maximum extra paragraphs needed. */
	uint16_t e_ss;        /* Initial (relative) SS value. */
	uint16_t e_sp;        /* Initial SP value. */
	uint16_t e_csum;      /* Checksum. */
	uint16_t e_ip;        /* Initial IP value. */
	uint16_t e_cs;        /* Initial (relative) CS value. */
	uint16_t e_lfarlc;    /* File address of relocation table. */
	uint16_t e_ovno;      /* Overlay number. */
        uint16_t e_res[4];    /* Reserved words. */
        uint16_t e_oemid;     /* OEM identifier (for e_oeminfo). */
        uint16_t e_oeminfo;   /* OEM information; e_oemid specific. */
        uint16_t e_res2[10];  /* Reserved words. */
        uint32_t e_lfanew;    /* File address of new exe header. */
};

struct PROG_PACKED pe_coff_header {
	unsigned char e_magic[4];   /* PE identity. */
	uint16_t e_arch;            /* Machine type. */
	uint16_t e_numsofsec;       /* Number of sections. */
	time_t e_tdstamp;           /* Timestamp in UNIX format. */
	uint32_t e_pt_sym;          /* COFF symbol table file offset. */
	uint32_t e_n_sym;           /* Number of entries in the symbol table. */
	uint16_t e_s_opt;           /* PE optional header size. */
};

struct pe_coff_characters {
	unsigned short e_has_image_relocs : 1;        /* Has relocation information? */
	unsigned short e_is_exec_image : 1;           /* Is this a executable file? */
	unsigned short e_are_line_n_stripped : 1;     /* Were COFF line numbers stripped from the file? */ 
	unsigned short e_are_syms_stripped : 1;       /* Were COFF symbols stripped from the file? */
	unsigned short e_has_agg_ws_trim : 1;         /* Was aggressive trim done to the working set? (obsolete) */
	unsigned short e_is_large_addr_aware : 1;     /* Can this application handle memory
							 address larger than 2GB? */
	unsigned short __e_padding : 1;               /* Padding. */
	unsigned short e_bytes_res_lo : 1;            /* Reserved bytes (obsolete). */
	unsigned short e_is_32_bit_machine : 1;       /* Does the system supports 32-bit words? */
	unsigned short e_is_debug_stripped : 1;       /* Was debugging information removed? */
	unsigned short e_rem_r_from_swap : 1;         /* If the image is on removable media,
							 copy it and run it from the swap. */
	unsigned short e_net_r_from_swap : 1;         /* If the image is on network, copy it
							 and run it from the swap. */
	unsigned short e_is_sys_file : 1;             /* Is this image a system file? */
	unsigned short e_is_dll : 1;                  /* Is this image a DLL file? */
	unsigned short e_is_unip_only : 1;            /* Should this image be run on an uniprocessor system? */
	unsigned short e_unused_last_res_bytes : 1;   /* Last reserved bytes (obsolete). */
};

struct PROG_PACKED pe_optional_header32 {
	uint16_t e_pe_magic;
	uint8_t e_major_linker;
	uint8_t e_minor_linker;
	uint32_t e_sizeof_code;
	uint32_t e_sizeof_init_data;
	uint32_t e_sizeof_uninit_data;
	uint32_t e_addrof_entry_point;
	uint32_t e_baseof_code;
	uint32_t e_baseof_data;
	uint32_t e_image_base;
	uint32_t e_virt_sect_align;
	uint32_t e_raw_sect_align;
	uint16_t e_major_os_ver;
	uint16_t e_minor_os_ver;
	uint16_t e_major_image_ver;
	uint16_t e_minor_image_ver;
	uint16_t e_major_subsys_ver;
	uint16_t e_minor_subsys_ver;
	uint32_t e_win32_ver;
	uint32_t e_sizeof_image;
	uint32_t e_sizeof_headers;
	uint32_t e_checksum;
	uint16_t e_subsystem_type;
};

struct PROG_PACKED pe_optional_header64 {
	uint16_t e_pe_magic;
	uint8_t e_major_linker;
	uint8_t e_minor_linker;
	uint32_t e_sizeof_code;
	uint32_t e_sizeof_init_data;
	uint32_t e_sizeof_uninit_data;
	uint32_t e_addrof_entry_point;
	uint32_t e_baseof_code;
        uint64_t e_image_base;
	uint32_t e_virt_sect_align;
	uint32_t e_raw_sect_align;
	uint16_t e_major_os_ver;
	uint16_t e_minor_os_ver;
	uint16_t e_major_image_ver;
	uint16_t e_minor_image_ver;
	uint16_t e_major_subsys_ver;
	uint16_t e_minor_subsys_ver;
	uint32_t e_win32_ver;
	uint32_t e_sizeof_image;
	uint32_t e_sizeof_headers;
	uint32_t e_checksum;
	uint16_t e_subsystem_type;
};

struct pe_dll_characteristics {
	/* 8-bits. */
	unsigned short e_call_when_loaded : 1;
	unsigned short e_call_when_thread_term : 1;
	unsigned short e_call_when_thread_starts : 1;
	unsigned short e_call_when_exiting : 1;
	unsigned short __e_padding : 1;          /* This skips .4 */
	unsigned short e_high_entropy_va : 1;    /* ASLR with 64-bit address space. */
	unsigned short e_dynamic_base : 1;       /* Can be relocated at load time. */
	unsigned short e_force_integrity : 1;    /* Code integrity checks are enforced. */

	/* Next 8-bits. */
	unsigned short e_nx_compat : 1;
        unsigned short e_no_isolation : 1;
	unsigned short e_no_seh : 1;
	unsigned short e_do_not_bind : 1;
	unsigned short e_app_container : 1;
	unsigned short e_is_wdm_driver : 1;
	unsigned short e_supports_control_flow_guard : 1;
	unsigned short e_term_serv_aware : 1;	
};

struct PROG_PACKED pe_sizeof_after32 {
	uint32_t e_sizeof_stack_res;
	uint32_t e_sizeof_stack_comm;
	uint32_t e_sizeof_heap_res;
	uint32_t e_sizeof_heap_comm;
};

struct PROG_PACKED pe_sizeof_after64 {
	uint64_t e_sizeof_stack_res;
	uint64_t e_sizeof_stack_comm;
	uint64_t e_sizeof_heap_res;
	uint64_t e_sizeof_heap_comm;
};

struct pe_section_table_entry {
        char e_section_name[8];
        uint32_t e_virt_size;
	uint32_t e_rv_size;
	uint32_t e_sizeof_raw_data;
	uint32_t e_sizeof_ptr_raw_data;
	uint32_t e_sizeof_ptr_relocs;
	uint32_t e_sizeof_ptr_line_n;
	uint16_t e_n_of_relocs;
        uint16_t e_n_of_line_nums;
};

/* For function: pe_optional_get_magic_value() */
#define MAGIC_ROM       (0x107)
#define MAGIC_PE32      (0x10b)
#define MAGIC_PE32Plus  (0x20b)

/* For function: pe_optional_get_subsystem_value() */
#define SUBSYSTEM_UNKNOWN                 (0x00)
#define SUBSYTEM_NATIVE                   (0x01)
#define SUBSYTEM_WINDOWSGUI               (0x02)
#define SUBSYTEM_WINDOWSCUI               (0x03)
#define SUBSYTEM_OS2CUI                   (0x05)
#define SUBSYTEM_POSIXCUI                 (0x07)
#define SUBSYSTEM_WINDOWS9XNATIVE         (0x08)
#define SUBSYSTEM_WINDOWSCEGUI            (0x09)
#define SUBSYSTEM_EFIAPPLICATION          (0x0a)
#define SUBSYSTEM_EFIBOOTSERVICEDRIVER    (0x0b)
#define SUBSYSTEM_EFIRUNTIMEDRIVER        (0x0c)
#define SUBSYSTEM_EFIROM                  (0x0d)
#define SUBSYSTEM_XBOX                    (0x0e)
#define SUBSYSTEM_WINDOWSBOOTAPPLICATION  (0x10)

/* For function: pe_print_coff_char_fields() */
#define PE_COFF_CHAR_IS_OK(x)    ((x) == ((uint16_t)1) ? "Yes" : "No")

/* Argument options. */
struct arg_options {
	int dos_header_opt : 1;
	int coff_header_opt : 1;
	int coff_char_fields_opt : 1;
	int sizeof_after_opt : 1; 
	int list_section_tables_opt : 1;
	int optional_header_opt : 1;
	int dll_character_opt : 1;
	int dos_stub_opt : 1;
	int has_valid_dansid : 1;
	int find_section_opt : 1;
	int help_opt : 1;
};

#endif /* PEINFO_H */
