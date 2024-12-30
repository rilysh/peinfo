#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <time.h>
#include <err.h>
#include <getopt.h>
#include <errno.h>

#include "peinfo.h"

/* Returns the offset of a needle by mmaping. */
static off_t get_offset(int fd, const char *pat)
{
	off_t fsz, off;
        unsigned char *d, *p;

	if ((fsz = lseek(fd, (off_t)0, SEEK_END)) == -1)
		err(EXIT_FAILURE, "lseek()");

	d = mmap(NULL, (size_t)fsz, PROT_READ, MAP_PRIVATE, fd, (off_t)0);
	if ((p = memmem(d, fsz, pat, strlen(pat))) == NULL)
		return (-1);
        off = p - d;
	munmap(d, (size_t)fsz);
	return (off);
}

/* Check whether the PE file is valid or not.
   Note that this only checks whether the PE file
   has MZ and "This program" string, and no other
   tests are being peformed. */
static int is_valid_pe(int fd)
{
	struct stat st;
        uint8_t sig[3];

	if (fstat(fd, &st) == -1)
		err(EXIT_FAILURE, "fstat()");

	if ((st.st_mode & S_IFMT) != S_IFREG)
		return (0);

	memset(sig, '\0', sizeof(sig));
	read(fd, sig, sizeof(sig));

	if (sig[0] == 'M' && sig[1] == 'Z' &&
	    get_offset(fd, "This program") != -1)
		return (1);

        return (0);
}

/* Convert the UNIX time to pretty readable format. */
static char *format_unix_timestamp(time_t time)
{
	static const char format[] = "%a %b %d, %H:%M:%S";
	struct tm t;
	static char res[50];
	time_t time2;

	/* We want UTC time and date. */
	time2 = time - 19800;
        if (localtime_r(&time2, &t) == NULL)
		err(EXIT_FAILURE, "localtime_r()");
	strftime(res, sizeof(res), format, &t);
	return (res);
}

/* Walk through the DOS header (resides at the beginning
   of a PE file). */ 
static void pe_walk_dos_header(struct pe_dos_header *dh, int fd)
{
	/* Doing a seek is _useless_, this just ensures
	   that whatever PE file we're reading is seekable. */
	if (lseek(fd, (off_t)0, SEEK_SET) == -1)
		err(EXIT_FAILURE, "lseek()");
	
        read(fd, dh, sizeof(struct pe_dos_header));
}

/* Find the DOS stub text in the PE file.
   These usually are:
   1. This program cannot be run in DOS mode.
   2. This program must be run under Win32. */
static char *pe_get_dos_stub(int fd)
{
        static char stub[40];
	char *p;
	off_t pos;

	if ((pos = get_offset(fd, "This program")) == -1)
		errx(EXIT_FAILURE,
		     "Cannot find the DOS stub. "
		     "Are you sure that you're working with a valid PE file?");

	if (lseek(fd, pos, SEEK_SET) == (off_t)-1)
		err(EXIT_FAILURE, "lseek()");

	read(fd, stub, sizeof(stub));

        /* It's not gureented that we'll get a '\0' in the stub.
	   Better to specify the size. */
	if ((p = memchr(stub, '\n', sizeof(stub))))
		stub[p - stub - 1] = '\0';  /* new_pos - old_pos - 1. */
	return (stub);
}

static inline const char *pe_coff_get_arch_name(uint16_t arch)
{
        switch (arch) {
	case TYPE_ALPHAAXPOLD:    return ("Alpha AXP (Old)");
	case TYPE_ALPHAAXP:       return ("Alpha AXP");
	case TYPE_ALPHAAXP64BIT:  return ("Alpha AXP (64-bit)");
		/* https://en.wikipedia.org/wiki/MN103 */
	case TYPE_AM33:           return ("AM33");
	case TYPE_AMD64:          return ("AMD64");
	case TYPE_ARM:            return ("ARM");
	case TYPE_ARM64:          return ("AArch64");
	case TYPE_ARMNT:          return ("ARM (NT)"); /* This one is vague. */
	case TYPE_CLRPUREMSIL:    return ("MISL (Pure)");
	case TYPE_EBC:            return ("EBC");
	case TYPE_I386:           return ("i386");
	case TYPE_I860:           return ("i860");
	case TYPE_IA64:           return ("IA-64");
	case TYPE_LOONGARCH32:    return ("LoongArch");
	case TYPE_LOONGARCH64:    return ("LoongArch64");
	case TYPE_M32R:           return ("M32R");
	case TYPE_MIPS16:         return ("MIPS16");
	case TYPE_MIPSFPU:        return ("MIPS (with FPU)");
	case TYPE_MIPSFPU16:      return ("MIPS16 (with FPU)");
	case TYPE_MOTOROLA68000:  return ("Motorola 68k");
	case TYPE_POWERPC:        return ("PowerPC");
	case TYPE_POWERPCFP:      return ("PowerPC (with FP)");
	case TYPE_POWERPC64:      return ("PowerPC (64-bit)");
	case TYPE_R3000:          return ("R3000 (MIPS)");
	case TYPE_R4000:          return ("R4000 (MIPS)");
	case TYPE_R10000:         return ("R10000 (MIPS/T5)");
	case TYPE_RISCV32:        return ("RISCV32");
	case TYPE_RISCV64:        return ("RISCV64");
	case TYPE_RISCV128:       return ("RISCV128");
	case TYPE_SH3:            return ("SuperH 3");
	case TYPE_SH3DSP:         return ("SuperH 3 DSP");
	case TYPE_SH4:            return ("SuperH 4");
	case TYPE_SH5:            return ("SuperH 5");
	case TYPE_THUMB:          return ("ARM Thumb");
		/* TODO: This needs to be addressed. */ 
	case TYPE_WCEMIPSV2:      return ("WCEMIPSV2");
	case TYPE_UNKNOWN: default: return ("Unknown");
	}

	PROG_UNREACHABLE();
}

/* TODO: Try spliting the characters structure and add
   position to lseek(), (by adding all sized bytes from
   PE to sizeOfOptional. */   
static void pe_walk_coff_header(struct pe_coff_header *pch, int fd)
{
	off_t pos;

	if ((pos = get_offset(fd, "PE\0\0")) == -1)
		errx(EXIT_FAILURE, "cannot find the 'PE' symbol.");
        if (lseek(fd, pos, SEEK_SET) == (off_t)-1)
		err(EXIT_FAILURE, "lseek()");

	read(fd, pch, sizeof(struct pe_coff_header));
}

/* b3371eb9
   f75670ea
   44616e53 (xor'd)
   We've to find the end of "Rich" (4-bytes) */
static int pe_rich_has_valid_dansid(int fd)
{
	unsigned char lbytes[5], rbytes[5];
	off_t pos;

	memset(lbytes, '\0', sizeof(lbytes));
	memset(rbytes, '\0', sizeof(rbytes));

	if ((pos = get_offset(fd, "Rich")) == -1)
		return (0);
	if (lseek(fd, pos + 4, SEEK_SET) == (off_t)-1)
		err(EXIT_FAILURE, "lseek()");
        read(fd, lbytes, sizeof(lbytes));

	if (lseek(fd, 1, SEEK_SET) == (off_t)-1)
		err(EXIT_FAILURE, "lseek()");
	if ((pos = get_offset(fd, "$")) == (off_t)-1)
		errx(EXIT_FAILURE, "No Rich entry was found.");
	if (lseek(fd, pos + 8, SEEK_SET) == (off_t)-1)
		err(EXIT_FAILURE, "lseek()");
	read(fd, rbytes, sizeof(rbytes));

        return ((lbytes[0] ^ rbytes[0]) == 'D' &&
		(lbytes[1] ^ rbytes[1]) == 'a' &&
		(lbytes[2] ^ rbytes[2]) == 'n' &&
		(lbytes[3] ^ rbytes[3]) == 'S');
}

/* Walk the character field. */
static void pe_walk_coff_char_fields(struct pe_coff_characters *pcc, int fd)
{
	off_t pos;
	
        if ((pos = get_offset(fd, "PE\0\0")) == -1)
		errx(EXIT_FAILURE, "cannot find the 'PE' symbol.");

        /* From PE\0\0 it's 22 bytes away. */
	if (lseek(fd, pos + 22, SEEK_SET) == (off_t)-1)
		err(EXIT_FAILURE, "lseek()");

	read(fd, pcc, sizeof(struct pe_coff_characters));
}

static inline const char *pe_optional_get_magic_value(uint16_t value)
{
	switch (value) {
	case MAGIC_ROM:      return ("ROM");
	case MAGIC_PE32:     return ("PE32");
	case MAGIC_PE32Plus: return ("PE32+");
	default:             return ("Unknown");
	}

	PROG_UNREACHABLE();
}

static inline const char *pe_optional_get_subsystem_value(int value)
{
	switch (value) {
	case SUBSYSTEM_UNKNOWN: default:        return ("Unknown");
	case SUBSYTEM_NATIVE:                   return ("Native");
	case SUBSYTEM_WINDOWSGUI:               return ("WindowsGUI");
	case SUBSYTEM_WINDOWSCUI:               return ("WindowsCUI");
	case SUBSYTEM_OS2CUI:                   return ("OS2CUI");
	case SUBSYTEM_POSIXCUI:                 return ("POSIXCUI");
	case SUBSYSTEM_WINDOWS9XNATIVE:         return ("Windows9xNative");
	case SUBSYSTEM_WINDOWSCEGUI:            return ("WindowsCEGUI");
	case SUBSYSTEM_EFIAPPLICATION:          return ("EFIApplication");
	case SUBSYSTEM_EFIBOOTSERVICEDRIVER:    return ("EFIBootServiceDriver");
	case SUBSYSTEM_EFIRUNTIMEDRIVER:        return ("EFIRuntimeDriver");
	case SUBSYSTEM_EFIROM:                  return ("EFIROM");
	case SUBSYSTEM_XBOX:                    return ("Xbox");
	case SUBSYSTEM_WINDOWSBOOTAPPLICATION:  return ("WindowsBootApplication");
	}

	PROG_UNREACHABLE();
}

/* Walk the optional header. */
static void pe_walk_optional_header(struct pe_optional_header32 *poh32,
				   struct pe_optional_header64 *poh64,
				   int is_32_bit, int fd)
{
	off_t pos;

	if ((pos = get_offset(fd, "PE\0\0")) == -1)
		errx(EXIT_FAILURE, "cannot find the 'PE' symbol.");
	if (lseek(fd, pos + 24, SEEK_SET) == -1)
		err(EXIT_FAILURE, "lseek()");

	if (is_32_bit)
		read(fd, poh32, sizeof(struct pe_optional_header32));
	else
		read(fd, poh64, sizeof(struct pe_optional_header64));
}

/* Walk the DLL characteristics. */
static void pe_walk_optional_dll_chars(struct pe_dll_characteristics *pdc, int fd)
{
	off_t pos;

	if ((pos = get_offset(fd, "PE\0\0")) == -1)
		errx(EXIT_FAILURE, "cannot find the 'PE' symbol.");
	if (lseek(fd, pos + 94, SEEK_SET) == -1)
		err(EXIT_FAILURE, "lseek()");

        read(fd, pdc, sizeof(struct pe_dll_characteristics));
}

/* Walk the sizeof after. */
static void pe_walk_sizeof_after(struct pe_sizeof_after32 *pwa32,
				 struct pe_sizeof_after64 *pwa64,
				 int fd, int is_32_bit)
{
	off_t pos;

	if ((pos = get_offset(fd, "PE\0\0")) == -1)
		errx(EXIT_FAILURE, "cannot find the 'PE' symbol.");
	if (lseek(fd, pos + 96, SEEK_SET) == -1)
		err(EXIT_FAILURE, "lseek()");

	if (is_32_bit)
		read(fd, pwa32, sizeof(struct pe_sizeof_after32));
	else
		read(fd, pwa64, sizeof(struct pe_sizeof_after64));
}

/* Walk the section table. */
static void pe_walk_section_table(struct pe_section_table_entry *pse,
				  int sect_level, int fd, int is_32_bit)
{
	off_t pos, skip_bytes;

	if ((pos = get_offset(fd, "PE\0\0")) == -1)
		errx(EXIT_FAILURE, "cannot find the 'PE' symbol.");

	skip_bytes = (is_32_bit ? 248 : 264);
        while (sect_level--)
		skip_bytes += 40; /* Total structure would be 40 bytes. */

	/* This reposition is needed as 64-bit PE binaries have u64 entries
	   for pe_sizeof_after* structure. */
	if (lseek(fd, pos + skip_bytes, SEEK_SET) == -1)
		err(EXIT_FAILURE, "lseek()");
	
	read(fd, pse, sizeof(struct pe_section_table_entry));
}

/* Print collected COFF header information. */
static void pe_print_coff_header(struct pe_coff_header pch)
{
	fprintf(stdout,
		"Signature: %s\n"
		"Architecture: %#x (%s)\n"
		"NumberOfSections: %u\n"
		"TimeDateStamp: %ld (%s)\n"
		"PointerToSymbolTable: %u\n"
		"NumberOfSymbols: %u\n"
		"SizeOfOptionalHeader: %u\n",
		pch.e_magic,
		pch.e_arch, pe_coff_get_arch_name(pch.e_arch),
		pch.e_numsofsec,
		pch.e_tdstamp, format_unix_timestamp(pch.e_tdstamp),
		pch.e_pt_sym,
		pch.e_n_sym,
		pch.e_s_opt);
}

/* Print collected COFF characteristics informations. */
static void pe_print_coff_char_fields(struct pe_coff_characters pcc)
{
        fprintf(stdout,
		"Is reloc info stripped?\t\t[%s]\n"
		"Is an executable? \t\t[%s]\n"
		"Are COFF line numbers stripped?\t[%s]\n"
		"Are COFF symbols stripped? \t[%s]\n"
		"Aggressive trim to WS \t\t[%s]\n"
		"Larger address than 2GB? \t[%s]\n"
		"Compiled for 32-bit? \t\t[%s]\n"
		"Is debug info stripped? \t[%s]\n"
		"Is on removable-media? \t\t[%s]\n"
		"Is on network? \t\t\t[%s]\n"
		"Is a system-file? \t\t[%s]\n"
		"Is a DLL? \t\t\t[%s]\n"
		"Is only for uni-processor? \t[%s]\n",
		PE_COFF_CHAR_IS_OK(pcc.e_has_image_relocs),
		PE_COFF_CHAR_IS_OK(pcc.e_is_exec_image),
		PE_COFF_CHAR_IS_OK(pcc.e_are_line_n_stripped),
		PE_COFF_CHAR_IS_OK(pcc.e_are_syms_stripped),
		PE_COFF_CHAR_IS_OK(pcc.e_has_agg_ws_trim),
		PE_COFF_CHAR_IS_OK(pcc.e_is_large_addr_aware),
		PE_COFF_CHAR_IS_OK(pcc.e_is_32_bit_machine),
        	PE_COFF_CHAR_IS_OK(pcc.e_is_debug_stripped),
        	PE_COFF_CHAR_IS_OK(pcc.e_rem_r_from_swap),
		PE_COFF_CHAR_IS_OK(pcc.e_net_r_from_swap),
		PE_COFF_CHAR_IS_OK(pcc.e_is_sys_file),
		PE_COFF_CHAR_IS_OK(pcc.e_is_dll),
		PE_COFF_CHAR_IS_OK(pcc.e_is_unip_only));
}

/* Print the DOS header information. */
static void pe_print_dos_header(struct pe_dos_header dh)
{
	uint16_t e_magic_last;

	e_magic_last = (dh.e_magic & ~0xff) >> 8;
	fprintf(stdout,
		"Signature: %#x (%c%c)\n"
	        "ExtraPageSize: %#x\n"
		"NumberOfPages: %#x\n"
		"Relocations: %#x\n"
		"HeaderSizeInParagraphs: %#x\n"
		"MinimumAllocatedParagraphs: %#x\n"
		"MaximumAllocatedParagraphs: %#x\n"

		"InitialRelativeSSValue: %#x\n"
		"InitialRelativeSPValue: %#x\n"
		"Checksum: %#x\n"
		"InitialRelativeIPValue: %#x\n"
		"InitialRelativeCSValue: %#x\n"

		"RelocationsTablePointer: %#x\n"
		"OverlayNumber: %#x\n"
		"ReservedWords: %#x, %#x, %#x, %#x\n"
		"OEMIdentifier (for OEM information): %#x\n"
		"OEMInformation; OEMID specific: %#x\n"
		"OtherReservedWords: %#x, %#x, %#x, %#x, %#x, %#x, %#x, %#x, %#x, %#x\n"
		"COFFHeaderPointer: %#x\n",
		dh.e_magic, dh.e_magic, e_magic_last,
		dh.e_cblp,
		dh.e_cp,
		dh.e_crlc,
		dh.e_cparhdr,
		dh.e_minalloc,
		dh.e_maxalloc,
		dh.e_ss, dh.e_sp, dh.e_csum, dh.e_ip, dh.e_cs,
		dh.e_lfarlc,
		dh.e_ovno,
		dh.e_res[0], dh.e_res[1], dh.e_res[2], dh.e_res[3],
		dh.e_oemid,
		dh.e_oeminfo,
		dh.e_res2[0], dh.e_res2[1], dh.e_res2[2], dh.e_res2[3],
		dh.e_res2[4], dh.e_res2[5], dh.e_res2[6], dh.e_res2[7],
		dh.e_res2[8], dh.e_res2[9],
		dh.e_lfanew);
}

/* Iterate through each table (via an index), and print
   relevant informations about the section. */
static void pe_print_section_table(int fd, int is_32)
{
	struct pe_section_table_entry pse;
	int i, is_first;

	for (i = 0, is_first = 0;; i++) {
		pe_walk_section_table(&pse, i, fd, is_32);
		/* Note: You can think it as a hack to check whether there's an
		   entry or not. */
		if (i == (INT32_MAX - 1) ||
		    pse.e_virt_size == 0 ||
		    pse.e_virt_size == UINT32_MAX)
			break;

		if (is_first != 0)
			fputc('\n', stdout);
		else
			is_first = 1;

		fprintf(stdout,
			"Name: %s\n"
			"VirtualSize: %u\n"
			"VirtualAddress: %u\n"
			"SizeOfRawData: %u\n"
			"PointerToRawData: %u\n"
			"PointerToRelocations: %u\n"
			"PointerToLinenumbers: %u\n"
			"NumberOfRelocations: %u\n"
			"NumberOfLinenumbers: %u\n",
			pse.e_section_name, pse.e_virt_size,
			pse.e_rv_size, pse.e_sizeof_raw_data,
			pse.e_sizeof_ptr_raw_data,
			pse.e_sizeof_ptr_relocs, pse.e_sizeof_ptr_line_n,
			(unsigned int)pse.e_n_of_relocs,
			(unsigned int)pse.e_n_of_line_nums);
	        memset(&pse, '\0', sizeof(struct pe_section_table_entry));
	}
}

/* Find a specified section table and print information about it. */
static void pe_find_section_table(int fd, int is_32, const char *section)
{
	int i, has_one;
	struct pe_section_table_entry pse;

	has_one = 0;
	for (i = 0;; i++) {
	        pe_walk_section_table(&pse, i, fd, is_32);
		if (i == (INT32_MAX - 1) ||
		    pse.e_virt_size == 0 ||
		    pse.e_virt_size == UINT32_MAX)
			break;
		if (strcmp(section, pse.e_section_name) == 0) {
			has_one = 1;
			fprintf(stdout,
				"Name: %s\n"
				"VirtualSize: %u\n"
				"VirtualAddress: %u\n"
				"SizeOfRawData: %u\n"
				"PointerToRawData: %u\n"
				"PointerToRelocations: %u\n"
				"PointerToLinenumbers: %u\n"
				"NumberOfRelocations: %u\n"
				"NumberOfLinenumbers: %u\n",
				pse.e_section_name, pse.e_virt_size,
				pse.e_rv_size, pse.e_sizeof_raw_data,
				pse.e_sizeof_ptr_raw_data, pse.e_sizeof_ptr_relocs,
				pse.e_sizeof_ptr_line_n, pse.e_n_of_relocs,
				pse.e_n_of_line_nums);
			break;
		}

		memset(&pse, '\0', sizeof(struct pe_section_table_entry));
	}

	if (!has_one)
		errx(EXIT_FAILURE, "no section found called '%s'.",
		     section);
}

/* Print usage. */
PROG_NORETURN
static void print_usage(int exit_stat)
{
	fputs("** usage **\n"
	      "-----------\n"
	      " --dos-header           -- Display DOS header structure.\n"
	      " --coff-header          -- Display COFF header structure.\n"
	      " --coff-char-fields     -- Display characteristics structure.\n"
	      " --sizeof-after         -- Display the sizeof structure.\n"
	      " --list-section-tables  -- Display all section tables.\n"
	      " --option-header        -- Display optional header structure.\n"
	      " --dll-character        -- Display DLL characteristics structure.\n"
	      " --dos-stub             -- Display the DOS stub message.\n"
	      " --valid-dansid         -- Check whether the PE file has a valid DanS ID.\n"
	      " --find-section         -- Find a section with its name.\n"
	      " --help                 -- Display this help menu.\n", stdout);
	exit(exit_stat);
}

/* Print optional header information. */
static void pe_print_optional_header(struct pe_optional_header32 poh32,
				     struct pe_optional_header64 poh64,
				     int is_32_bit)
{
	if (is_32_bit) {
		/* Note: Keep it as it's.
		   Making it a single fprintf(...) function
		   will make this look way worse than it's
		   right now. */
		fprintf(stdout, "Magic: %s\n",
			pe_optional_get_magic_value(poh32.e_pe_magic));
		fprintf(stdout, "MajorLinkerVersion: %u\n", poh32.e_major_linker);
		fprintf(stdout, "MinorLinkerVersion: %u\n", poh32.e_minor_linker);
		fprintf(stdout, "SizeOfCode: %u\n", poh32.e_sizeof_code);
		fprintf(stdout, "SizeOfInitializedData: %u\n",
			poh32.e_sizeof_init_data);
		fprintf(stdout, "SizeOfUninitializedData: %u\n",
			poh32.e_sizeof_uninit_data);
		fprintf(stdout, "AddressOfEntryPoint: %u\n",
			poh32.e_addrof_entry_point);
		fprintf(stdout, "BaseOfCode: %u\n", poh32.e_baseof_code);
		fprintf(stdout, "BaseOfData: %u\n", poh32.e_baseof_data);
		fprintf(stdout, "ImageBase: %u\n", poh32.e_image_base);
		fprintf(stdout, "SectionAlignment: %u\n", poh32.e_virt_sect_align);
		fprintf(stdout, "FileAlignment: %u\n", poh32.e_raw_sect_align);
		fprintf(stdout, "MajorOperatingSystemVersion: %u\n", poh32.e_major_os_ver);
		fprintf(stdout, "MinorOperatingSystemVersion: %u\n", poh32.e_minor_os_ver);
		fprintf(stdout, "MajorImageVersion: %u\n", poh32.e_major_image_ver);
		fprintf(stdout, "MinorImageVersion: %u\n", poh32.e_minor_image_ver);
		fprintf(stdout, "MajorSubsystemVersion: %u\n", poh32.e_major_subsys_ver);
		fprintf(stdout, "MinorSubsystemVersion: %u\n", poh32.e_minor_subsys_ver);
		fprintf(stdout, "Win32VersionValue (Reserved): %u\n", poh32.e_win32_ver);
		fprintf(stdout, "SizeOfImage: %u\n", poh32.e_sizeof_image);
		fprintf(stdout, "SizeOfHeaders: %u\n", poh32.e_sizeof_headers);
		fprintf(stdout, "CheckSum: %u\n", poh32.e_checksum);
		fprintf(stdout, "SubsystemType: %u (%s)\n", poh32.e_subsystem_type,
			pe_optional_get_subsystem_value(poh32.e_subsystem_type));
	} else {
		fprintf(stdout, "Magic: %s\n", pe_optional_get_magic_value(poh64.e_pe_magic));
		fprintf(stdout, "MajorLinkerVersion: %u\n", poh64.e_major_linker);
		fprintf(stdout, "MinorLinkerVersion: %u\n", poh64.e_minor_linker);
		fprintf(stdout, "SizeOfCode: %u\n", poh64.e_sizeof_code);
		fprintf(stdout, "SizeOfInitializedData: %u\n", poh64.e_sizeof_init_data);
		fprintf(stdout, "SizeOfUninitializedData: %u\n", poh64.e_sizeof_uninit_data);
		fprintf(stdout, "AddressOfEntryPoint: %u\n", poh64.e_addrof_entry_point);
		fprintf(stdout, "BaseOfCode: %u\n", poh64.e_baseof_code);
	        fprintf(stdout, "ImageBase: %lu\n", poh64.e_image_base);
		fprintf(stdout, "SectionAlignment: %u\n", poh64.e_virt_sect_align);
		fprintf(stdout, "FileAlignment: %u\n", poh64.e_raw_sect_align);
		fprintf(stdout, "MajorOperatingSystemVersion: %u\n", poh64.e_major_os_ver);
		fprintf(stdout, "MinorOperatingSystemVersion: %u\n", poh64.e_minor_os_ver);
		fprintf(stdout, "MajorImageVersion: %u\n", poh64.e_major_image_ver);
		fprintf(stdout, "MinorImageVersion: %u\n", poh64.e_minor_image_ver);
		fprintf(stdout, "MajorSubsystemVersion: %u\n", poh64.e_major_subsys_ver);
		fprintf(stdout, "MinorSubsystemVersion: %u\n", poh64.e_minor_subsys_ver);
		fprintf(stdout, "Win32VersionValue (Reserved): %u\n", poh64.e_win32_ver);
		fprintf(stdout, "SizeOfImage: %u\n", poh64.e_sizeof_image);
		fprintf(stdout, "SizeOfHeaders: %u\n", poh64.e_sizeof_headers);
		fprintf(stdout, "CheckSum: %u\n", poh64.e_checksum);
		fprintf(stdout, "SubsystemType: %u (%s)\n", poh64.e_subsystem_type,
			pe_optional_get_subsystem_value(poh64.e_subsystem_type));		
	}

	/* TODO: Apparently BaseOfData doesn't exists in PE32+. */
	/* That means we need a separate optional header structure for PE32+. */
	/* https://learn.microsoft.com/en-us/windows/win32/debug/pe-format */
}

#define PE_OP_DLL_CHAR_IS_OK(x)    (((x) == (uint16_t)1) ? "Yes" : "No")

/* Print optional DLL characteristics informations. */
static void pe_print_optional_dll_characteristics(struct pe_dll_characteristics pdc)
{
	fprintf(stdout,
		"CallWhenLoaded: %s (%u)\n"
		"CallWhenThreadStarts: %s (%u)\n"
	        "CallWhenThreadTerminates: %s (%u)\n"
		"CallWhenExiting: %s (%u)\n"
	        "HighEntropyVA: %s (%u)\n"
		"DynamicBase: %s (%u)\n"
		"ForceIntegrity: %s (%u)\n"
		"NXCompatible: %s (%u)\n"
		"NoIsolation: %s (%u)\n"
		"NoSEH: %s (%u)\n"
		"DoNotBind: %s (%u)\n"
		"AppContainer: %s (%u)\n"
		"IsWDMDriver: %s (%u)\n"
		"SupportsControlFlowGuard: %s (%u)\n"
		"TerminalServerAware: %s (%u)\n",
		PE_OP_DLL_CHAR_IS_OK(pdc.e_call_when_loaded),
		pdc.e_call_when_loaded,

		PE_OP_DLL_CHAR_IS_OK(pdc.e_call_when_thread_starts),
		pdc.e_call_when_thread_starts,

		PE_OP_DLL_CHAR_IS_OK(pdc.e_call_when_thread_term),
		pdc.e_call_when_thread_term,

		PE_OP_DLL_CHAR_IS_OK(pdc.e_call_when_exiting),
		pdc.e_call_when_exiting,

		PE_OP_DLL_CHAR_IS_OK(pdc.e_high_entropy_va),
		pdc.e_high_entropy_va,

	        PE_OP_DLL_CHAR_IS_OK(pdc.e_dynamic_base),
		pdc.e_dynamic_base,

	        PE_OP_DLL_CHAR_IS_OK(pdc.e_force_integrity),
		pdc.e_force_integrity,

	        PE_OP_DLL_CHAR_IS_OK(pdc.e_nx_compat),
		pdc.e_nx_compat,

		PE_OP_DLL_CHAR_IS_OK(pdc.e_no_isolation),
		pdc.e_no_isolation,

		PE_OP_DLL_CHAR_IS_OK(pdc.e_no_seh),
		pdc.e_no_seh,

		PE_OP_DLL_CHAR_IS_OK(pdc.e_do_not_bind),
		pdc.e_do_not_bind,

		PE_OP_DLL_CHAR_IS_OK(pdc.e_app_container),
		pdc.e_app_container,

		PE_OP_DLL_CHAR_IS_OK(pdc.e_is_wdm_driver),
		pdc.e_is_wdm_driver,

		PE_OP_DLL_CHAR_IS_OK(pdc.e_supports_control_flow_guard),
		pdc.e_supports_control_flow_guard,

		PE_OP_DLL_CHAR_IS_OK(pdc.e_term_serv_aware),
		pdc.e_term_serv_aware);
}

/* Print sizeof after information. */
static void pe_print_sizeof_after(struct pe_sizeof_after32 psa32,
				  struct pe_sizeof_after64 psa64,
				  int is_32_bit)
{
	if (is_32_bit)
		fprintf(stdout,
			"Heap Comm: %u bytes\nHeap Res: %u bytes\n"
			"Stack Comm: %u bytes\nStack Res: %u bytes\n",
			psa32.e_sizeof_heap_comm, psa32.e_sizeof_heap_res,
			psa32.e_sizeof_stack_comm, psa32.e_sizeof_stack_res);
	else
		fprintf(stdout,
			"Heap Comm: %lu bytes\nHeap Res: %lu bytes\n"
			"Stack Comm: %lu bytes\nStack Res: %lu bytes\n",
			psa64.e_sizeof_heap_comm, psa64.e_sizeof_heap_res,
			psa64.e_sizeof_stack_comm, psa64.e_sizeof_stack_res);
}

/* TODO: https://xor.pw/# */
/* TODO: Optional header information. */
/* https://ghidra.re/ghidra_docs/api/ghidra/app/util/bin/format/pe/OptionalHeader.html */
int main(int argc, char **argv)
{
	int fd, opt;
	int has_dansid;
        struct pe_dos_header dh;
	struct pe_coff_header pch;
	struct pe_coff_characters pcc;
	struct pe_dll_characteristics pdc;
	struct pe_sizeof_after32 psa32;
	struct pe_sizeof_after64 psa64;
	struct pe_optional_header32 poh32;
	struct pe_optional_header64 poh64;
	struct arg_options aopt;

	if (argc < 2)
	        print_usage(EXIT_FAILURE);

	fd = 0;
	memset(&aopt, '\0', sizeof(struct arg_options));

	static const struct option lopts[] = {
		{ "dos-header",           no_argument, 0, 1 },
		{ "coff-header",          no_argument, 0, 2 },
		{ "coff-char-fields",     no_argument, 0, 3 },
		{ "sizeof-after",         no_argument, 0, 4 },
		{ "list-section-tables",  no_argument, 0, 5 },
		{ "optional-header",      no_argument, 0, 6 },
		{ "dll-character",        no_argument, 0, 7 },
		{ "dos-stub",             no_argument, 0, 8 },
		{ "valid-dans",           no_argument, 0, 9 },
		{ "find-section",         no_argument, 0, 10 },
		{ "help",                 no_argument, 0, 'h' },
		{ NULL,                   0,           0, 0 }
	};

	while ((opt = getopt_long(argc, argv, "h", lopts, NULL)) != -1) {
		switch (opt) {
		case 1:  aopt.dos_header_opt = -1; break;
		case 2:  aopt.coff_header_opt = -1; break;
		case 3:  aopt.coff_char_fields_opt = -1; break;
		case 4:  aopt.sizeof_after_opt = -1; break;
		case 5:  aopt.list_section_tables_opt = -1; break;
		case 6:  aopt.optional_header_opt = -1; break;
		case 7:  aopt.dll_character_opt = -1; break;
		case 8:  aopt.dos_stub_opt = -1; break;
		case 9:  aopt.has_valid_dansid = -1; break;
		case 10: aopt.find_section_opt = -1; break;
		case 'h': aopt.help_opt = -1; break;
		default: break;
		}
	}

	if (aopt.dos_header_opt || aopt.coff_header_opt ||
	    aopt.coff_char_fields_opt || aopt.sizeof_after_opt ||
	    aopt.list_section_tables_opt || aopt.optional_header_opt ||
	    aopt.dll_character_opt || aopt.dos_stub_opt ||
	    aopt.has_valid_dansid || aopt.find_section_opt) {
		if (argc < 3)
			errx(EXIT_FAILURE, "file path is required but found nothing.");
		if ((fd = open(argv[2], O_RDONLY)) == -1) {
		        if (errno == ENOENT)
				errx(EXIT_FAILURE,
				     "error: '%s' file path does not exists.", argv[2]);
		        err(EXIT_FAILURE, "open()");
		}

		if (!is_valid_pe(fd))
			errx(EXIT_FAILURE, "error: '%s' is not a Windows PE file.", argv[2]);

		/* Check if section name was provided. */
		if (aopt.find_section_opt) {
			if (argc < 4)
				errx(EXIT_FAILURE, "section name was not provided.");
		}
	}

	if (aopt.dos_header_opt) {
		pe_walk_dos_header(&dh, fd);
		pe_print_dos_header(dh);
		goto exit_program;
	}

	if (aopt.coff_header_opt) {
		pe_walk_coff_header(&pch, fd);
	        pe_print_coff_header(pch);
	        goto exit_program;
	}

	if (aopt.coff_char_fields_opt) {
		/* To find PE machine type. */
		pe_walk_coff_char_fields(&pcc, fd);
		pe_print_coff_char_fields(pcc);
	        goto exit_program;
	}

	if (aopt.sizeof_after_opt) {
		/* To find PE machine type. */
		pe_walk_coff_char_fields(&pcc, fd);
		pe_walk_sizeof_after(&psa32, &psa64, fd, pcc.e_is_32_bit_machine);
		pe_print_sizeof_after(psa32, psa64, pcc.e_is_32_bit_machine);
		goto exit_program;
	}

	if (aopt.list_section_tables_opt) {
		/* To find PE machine type. */
		pe_walk_coff_char_fields(&pcc, fd);
		pe_print_section_table(fd, pcc.e_is_32_bit_machine);
		goto exit_program;
	}

	if (aopt.optional_header_opt) {
		/* To find PE machine type. */
		pe_walk_coff_char_fields(&pcc, fd);
		pe_walk_optional_header(&poh32, &poh64, pcc.e_is_32_bit_machine, fd);
		pe_print_optional_header(poh32, poh64, pcc.e_is_32_bit_machine);
		goto exit_program;
	}

	if (aopt.dll_character_opt) {
		pe_walk_optional_dll_chars(&pdc, fd);
		pe_print_optional_dll_characteristics(pdc);
		goto exit_program;
	}

	if (aopt.dos_stub_opt) {
		fprintf(stdout, "DOS Stub: %s\n", pe_get_dos_stub(fd));
		goto exit_program;
	}

	if (aopt.has_valid_dansid) {
		has_dansid = pe_rich_has_valid_dansid(fd);
		fprintf(stdout, "ValidDansID: %d (%s)\n", has_dansid,
			has_dansid ? "Yes" : "No");
		goto exit_program;
	}

	if (aopt.find_section_opt) {
		/* To find PE machine type. */
		pe_walk_coff_char_fields(&pcc, fd);
		pe_find_section_table(fd, pcc.e_is_32_bit_machine, argv[3]);
		goto exit_program;
	}

	if (aopt.help_opt)
		print_usage(EXIT_SUCCESS);

exit_program:
	close(fd);
	exit(EXIT_SUCCESS);
}
