#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-1198.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(118220);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/30");

  script_cve_id(
    "CVE-2014-9939",
    "CVE-2017-15938",
    "CVE-2017-15939",
    "CVE-2017-15996",
    "CVE-2017-16826",
    "CVE-2017-16827",
    "CVE-2017-16828",
    "CVE-2017-16829",
    "CVE-2017-16830",
    "CVE-2017-16831",
    "CVE-2017-16832",
    "CVE-2017-6965",
    "CVE-2017-6966",
    "CVE-2017-6969",
    "CVE-2017-7209",
    "CVE-2017-7210",
    "CVE-2017-7223",
    "CVE-2017-7224",
    "CVE-2017-7225",
    "CVE-2017-7226",
    "CVE-2017-7299",
    "CVE-2017-7300",
    "CVE-2017-7301",
    "CVE-2017-7302",
    "CVE-2017-7303",
    "CVE-2017-7304",
    "CVE-2017-8392",
    "CVE-2017-8393",
    "CVE-2017-8394",
    "CVE-2017-8396",
    "CVE-2017-8421",
    "CVE-2017-9746",
    "CVE-2017-9747",
    "CVE-2017-9748",
    "CVE-2017-9750",
    "CVE-2017-9755",
    "CVE-2017-9756",
    "CVE-2018-10372",
    "CVE-2018-10373",
    "CVE-2018-10534",
    "CVE-2018-10535",
    "CVE-2018-6323",
    "CVE-2018-6543",
    "CVE-2018-6759",
    "CVE-2018-6872",
    "CVE-2018-7208",
    "CVE-2018-7568",
    "CVE-2018-7569",
    "CVE-2018-7570",
    "CVE-2018-7642",
    "CVE-2018-7643",
    "CVE-2018-8945"
  );

  script_name(english:"openSUSE Security Update : binutils (openSUSE-2018-1198)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"This update for binutils to 2.31 fixes the following issues :

These security issues were fixed :

  - CVE-2017-15996: readelf allowed remote attackers to
    cause a denial of service (excessive memory allocation)
    or possibly have unspecified other impact via a crafted
    ELF file that triggered a buffer overflow on fuzzed
    archive header (bsc#1065643).

  - CVE-2017-15939: Binary File Descriptor (BFD) library
    (aka libbfd) mishandled NULL files in a .debug_line file
    table, which allowed remote attackers to cause a denial
    of service (NULL pointer dereference and application
    crash) via a crafted ELF file, related to
    concat_filename (bsc#1065689).

  - CVE-2017-15938: the Binary File Descriptor (BFD) library
    (aka libbfd) miscalculated DW_FORM_ref_addr die refs in
    the case of a relocatable object file, which allowed
    remote attackers to cause a denial of service
    (find_abstract_instance_name invalid memory read,
    segmentation fault, and application crash)
    (bsc#1065693).

  - CVE-2017-16826: The coff_slurp_line_table function the
    Binary File Descriptor (BFD) library (aka libbfd)
    allowed remote attackers to cause a denial of service
    (invalid memory access and application crash) or
    possibly have unspecified other impact via a crafted PE
    file (bsc#1068640).

  - CVE-2017-16832: The pe_bfd_read_buildid function in the
    Binary File Descriptor (BFD) library (aka libbfd) did
    not validate size and offset values in the data
    dictionary, which allowed remote attackers to cause a
    denial of service (segmentation violation and
    application crash) or possibly have unspecified other
    impact via a crafted PE file (bsc#1068643).

  - CVE-2017-16831: Binary File Descriptor (BFD) library
    (aka libbfd) did not validate the symbol count, which
    allowed remote attackers to cause a denial of service
    (integer overflow and application crash, or excessive
    memory allocation) or possibly have unspecified other
    impact via a crafted PE file (bsc#1068887).

  - CVE-2017-16830: The print_gnu_property_note function did
    not have integer-overflow protection on 32-bit
    platforms, which allowed remote attackers to cause a
    denial of service (segmentation violation and
    application crash) or possibly have unspecified other
    impact via a crafted ELF file (bsc#1068888).

  - CVE-2017-16829: The _bfd_elf_parse_gnu_properties
    function in the Binary File Descriptor (BFD) library
    (aka libbfd) did not prevent negative pointers, which
    allowed remote attackers to cause a denial of service
    (out-of-bounds read and application crash) or possibly
    have unspecified other impact via a crafted ELF file
    (bsc#1068950).

  - CVE-2017-16828: The display_debug_frames function
    allowed remote attackers to cause a denial of service
    (integer overflow and heap-based buffer over-read, and
    application crash) or possibly have unspecified other
    impact via a crafted ELF file (bsc#1069176).

  - CVE-2017-16827: The aout_get_external_symbols function
    in the Binary File Descriptor (BFD) library (aka libbfd)
    allowed remote attackers to cause a denial of service
    (slurp_symtab invalid free and application crash) or
    possibly have unspecified other impact via a crafted ELF
    file (bsc#1069202).

  - CVE-2018-6323: The elf_object_p function in the Binary
    File Descriptor (BFD) library (aka libbfd) had an
    unsigned integer overflow because bfd_size_type
    multiplication is not used. A crafted ELF file allowed
    remote attackers to cause a denial of service
    (application crash) or possibly have unspecified other
    impact (bsc#1077745).

  - CVE-2018-6543: Prevent integer overflow in the function
    load_specific_debug_section() which resulted in
    `malloc()` with 0 size. A crafted ELF file allowed
    remote attackers to cause a denial of service
    (application crash) or possibly have unspecified other
    impact (bsc#1079103).

  - CVE-2018-6759: The bfd_get_debug_link_info_1 function in
    the Binary File Descriptor (BFD) library (aka libbfd)
    had an unchecked strnlen operation. Remote attackers
    could have leveraged this vulnerability to cause a
    denial of service (segmentation fault) via a crafted ELF
    file (bsc#1079741).

  - CVE-2018-6872: The elf_parse_notes function in the
    Binary File Descriptor (BFD) library (aka libbfd)
    allowed remote attackers to cause a denial of service
    (out-of-bounds read and segmentation violation) via a
    note with a large alignment (bsc#1080556).

  - CVE-2018-7208: In the coff_pointerize_aux function in
    the Binary File Descriptor (BFD) library (aka libbfd) an
    index was not validated, which allowed remote attackers
    to cause a denial of service (segmentation fault) or
    possibly have unspecified other impact via a crafted
    file, as demonstrated by objcopy of a COFF object
    (bsc#1081527).

  - CVE-2018-7570: The
    assign_file_positions_for_non_load_sections function in
    the Binary File Descriptor (BFD) library (aka libbfd)
    allowed remote attackers to cause a denial of service
    (NULL pointer dereference and application crash) via an
    ELF file with a RELRO segment that lacks a matching LOAD
    segment, as demonstrated by objcopy (bsc#1083528).

  - CVE-2018-7569: The Binary File Descriptor (BFD) library
    (aka libbfd) allowed remote attackers to cause a denial
    of service (integer underflow or overflow, and
    application crash) via an ELF file with a corrupt DWARF
    FORM block, as demonstrated by nm (bsc#1083532).

  - CVE-2018-8945: The bfd_section_from_shdr function in the
    Binary File Descriptor (BFD) library (aka libbfd)
    allowed remote attackers to cause a denial of service
    (segmentation fault) via a large attribute section
    (bsc#1086608).

  - CVE-2018-7643: The display_debug_ranges function allowed
    remote attackers to cause a denial of service (integer
    overflow and application crash) or possibly have
    unspecified other impact via a crafted ELF file, as
    demonstrated by objdump (bsc#1086784).

  - CVE-2018-7642: The swap_std_reloc_in function in the
    Binary File Descriptor (BFD) library (aka libbfd)
    allowed remote attackers to cause a denial of service
    (aout_32_swap_std_reloc_out NULL pointer dereference and
    application crash) via a crafted ELF file, as
    demonstrated by objcopy (bsc#1086786).

  - CVE-2018-7568: The parse_die function in the Binary File
    Descriptor (BFD) library (aka libbfd) allowed remote
    attackers to cause a denial of service (integer overflow
    and application crash) via an ELF file with corrupt
    dwarf1 debug information, as demonstrated by nm
    (bsc#1086788).

  - CVE-2018-10373: concat_filename in the Binary File
    Descriptor (BFD) library (aka libbfd) allowed remote
    attackers to cause a denial of service (NULL pointer
    dereference and application crash) via a crafted binary
    file, as demonstrated by nm-new (bsc#1090997).

  - CVE-2018-10372: process_cu_tu_index allowed remote
    attackers to cause a denial of service (heap-based
    buffer over-read and application crash) via a crafted
    binary file, as demonstrated by readelf (bsc#1091015).

  - CVE-2018-10535: The ignore_section_sym function in the
    Binary File Descriptor (BFD) library (aka libbfd) did
    not validate the output_section pointer in the case of a
    symtab entry with a 'SECTION' type that has a '0' value,
    which allowed remote attackers to cause a denial of
    service (NULL pointer dereference and application crash)
    via a crafted file, as demonstrated by objcopy
    (bsc#1091365).

  - CVE-2018-10534: The
    _bfd_XX_bfd_copy_private_bfd_data_common function in the
    Binary File Descriptor (BFD) library (aka libbfd)
    processesed a negative Data Directory size with an
    unbounded loop that increased the value of
    (external_IMAGE_DEBUG_DIRECTORY) *edd so that the
    address exceeded its own memory region, resulting in an
    out-of-bounds memory write, as demonstrated by objcopy
    copying private info with
    _bfd_pex64_bfd_copy_private_bfd_data_common in
    pex64igen.c (bsc#1091368).

These non-security issues were fixed :

  - The AArch64 port now supports showing disassembly notes
    which are emitted when inconsistencies are found with
    the instruction that may result in the instruction being
    invalid. These can be turned on with the option -M notes
    to objdump.

  - The AArch64 port now emits warnings when a combination
    of an instruction and a named register could be invalid.

  - Added O modifier to ar to display member offsets inside
    an archive

  - The ADR and ADRL pseudo-instructions supported by the
    ARM assembler now only set the bottom bit of the address
    of thumb function symbols if the -mthumb-interwork
    command line option is active.

  - Add --generate-missing-build-notes=[yes|no] option to
    create (or not) GNU Build Attribute notes if none are
    present in the input sources. Add a

    --enable-generate-build-notes=[yes|no] configure time
    option to set the default behaviour. Set the default if
    the configure option is not used to 'no'.

  - Remove -mold-gcc command-line option for x86 targets.

  - Add -O[2|s] command-line options to x86 assembler to
    enable alternate shorter instruction encoding.

  - Add support for .nops directive. It is currently
    supported only for x86 targets.

  - Speed up direct linking with DLLs for Cygwin and Mingw
    targets.

  - Add a configure option --enable-separate-code to decide
    whether

    -z separate-code should be enabled in ELF linker by
    default. Default to yes for Linux/x86 targets. Note that
    -z separate-code can increase disk and memory size.

  - RISC-V: Fix symbol address problem with versioned
    symbols 

  - Restore riscv64-elf cross prefix via symlinks

  - RISC-V: Don't enable relaxation in relocatable link

  - Prevent linking faiures on i386 with assertion
    (bsc#1085784)

  - Fix symbol size bug when relaxation deletes bytes

  - Add --debug-dump=links option to readelf and
    --dwarf=links option to objdump which displays the
    contents of any .gnu_debuglink or .gnu_debugaltlink
    sections. Add a --debug-dump=follow-links option to
    readelf and a --dwarf=follow-links option to objdump
    which causes indirect links into separate debug info
    files to be followed when dumping other DWARF sections.

  - Add support for loaction views in DWARF debug line
    information.

  - Add -z separate-code to generate separate code PT_LOAD
    segment.

  - Add '-z undefs' command line option as the inverse of
    the '-z defs' option.

  - Add -z globalaudit command line option to force audit
    libraries to be run for every dynamic object loaded by
    an executable - provided that the loader supports this
    functionality.

  - Tighten linker script grammar around file name
    specifiers to prevent the use of SORT_BY_ALIGNMENT and
    SORT_BY_INIT_PRIORITY on filenames. These would
    previously be accepted but had no effect.

  - The EXCLUDE_FILE directive can now be placed within any
    SORT_* directive within input section lists.

  - Fix linker relaxation with --wrap

  - Add arm-none-eabi symlinks (bsc#1074741)

Former updates of binutils also fixed the following security issues,
for which there was not CVE assigned at the time the update was
released or no mapping between code change and CVE existed :

  - CVE-2014-9939: Prevent stack-based buffer overflow when
    printing bad bytes in Intel Hex objects (bsc#1030296).

  - CVE-2017-7225: The find_nearest_line function in
    addr2line did not handle the case where the main file
    name and the directory name are both empty, triggering a
    NULL pointer dereference and an invalid write, and
    leading to a program crash (bsc#1030585).

  - CVE-2017-7224: The find_nearest_line function in objdump
    was vulnerable to an invalid write (of size 1) while
    disassembling a corrupt binary that contains an empty
    function name, leading to a program crash (bsc#1030588).

  - CVE-2017-7223: GNU assembler in was vulnerable to a
    global buffer overflow (of size 1) while attempting to
    unget an EOF character from the input stream,
    potentially leading to a program crash (bsc#1030589).

  - CVE-2017-7226: The pe_ILF_object_p function in the
    Binary File Descriptor (BFD) library (aka libbfd) was
    vulnerable to a heap-based buffer over-read of size 4049
    because it used the strlen function instead of strnlen,
    leading to program crashes in several utilities such as
    addr2line, size, and strings. It could lead to
    information disclosure as well (bsc#1030584).

  - CVE-2017-7299: The Binary File Descriptor (BFD) library
    (aka libbfd) had an invalid read (of size 8) because the
    code to emit relocs (bfd_elf_final_link function in
    bfd/elflink.c) did not check the format of the input
    file trying to read the ELF reloc section header. The
    vulnerability leads to a GNU linker (ld) program crash
    (bsc#1031644).

  - CVE-2017-7300: The Binary File Descriptor (BFD) library
    (aka libbfd) had an aout_link_add_symbols function in
    bfd/aoutx.h that is vulnerable to a heap-based buffer
    over-read (off-by-one) because of an incomplete check
    for invalid string offsets while loading symbols,
    leading to a GNU linker (ld) program crash
    (bsc#1031656).

  - CVE-2017-7302: The Binary File Descriptor (BFD) library
    (aka libbfd) had a swap_std_reloc_out function in
    bfd/aoutx.h that is vulnerable to an invalid read (of
    size 4) because of missing checks for relocs that could
    not be recognised. This vulnerability caused Binutils
    utilities like strip to crash (bsc#1031595).

  - CVE-2017-7303: The Binary File Descriptor (BFD) library
    (aka libbfd) was vulnerable to an invalid read (of size
    4) because of missing a check (in the find_link
    function) for null headers attempting to match them.
    This vulnerability caused Binutils utilities like strip
    to crash (bsc#1031593).

  - CVE-2017-7301: The Binary File Descriptor (BFD) library
    (aka libbfd) had an aout_link_add_symbols function in
    bfd/aoutx.h that has an off-by-one vulnerability because
    it did not carefully check the string offset. The
    vulnerability could lead to a GNU linker (ld) program
    crash (bsc#1031638).

  - CVE-2017-7304: The Binary File Descriptor (BFD) library
    (aka libbfd) was vulnerable to an invalid read (of size
    8) because of missing a check (in the
    copy_special_section_fields function) for an invalid
    sh_link field attempting to follow it. This
    vulnerability caused Binutils utilities like strip to
    crash (bsc#1031590).

  - CVE-2017-8392: The Binary File Descriptor (BFD) library
    (aka libbfd) was vulnerable to an invalid read of size 8
    because of missing a check to determine whether symbols
    are NULL in the _bfd_dwarf2_find_nearest_line function.
    This vulnerability caused programs that conduct an
    analysis of binary programs using the libbfd library,
    such as objdump, to crash (bsc#1037052).

  - CVE-2017-8393: The Binary File Descriptor (BFD) library
    (aka libbfd) was vulnerable to a global buffer over-read
    error because of an assumption made by code that runs
    for objcopy and strip, that SHT_REL/SHR_RELA sections
    are always named starting with a .rel/.rela prefix. This
    vulnerability caused programs that conduct an analysis
    of binary programs using the libbfd library, such as
    objcopy and strip, to crash (bsc#1037057).

  - CVE-2017-8394: The Binary File Descriptor (BFD) library
    (aka libbfd) was vulnerable to an invalid read of size 4
    due to NULL pointer dereferencing of
    _bfd_elf_large_com_section. This vulnerability caused
    programs that conduct an analysis of binary programs
    using the libbfd library, such as objcopy, to crash
    (bsc#1037061).

  - CVE-2017-8396: The Binary File Descriptor (BFD) library
    (aka libbfd) was vulnerable to an invalid read of size 1
    because the existing reloc offset range tests didn't
    catch small negative offsets less than the size of the
    reloc field. This vulnerability caused programs that
    conduct an analysis of binary programs using the libbfd
    library, such as objdump, to crash (bsc#1037066).

  - CVE-2017-8421: The function coff_set_alignment_hook in
    Binary File Descriptor (BFD) library (aka libbfd) had a
    memory leak vulnerability which can cause memory
    exhaustion in objdump via a crafted PE file
    (bsc#1037273).

  - CVE-2017-9746: The disassemble_bytes function in
    objdump.c allowed remote attackers to cause a denial of
    service (buffer overflow and application crash) or
    possibly have unspecified other impact via a crafted
    binary file, as demonstrated by mishandling of rae insns
    printing for this file during 'objdump

    -D' execution (bsc#1044891).

  - CVE-2017-9747: The ieee_archive_p function in the Binary
    File Descriptor (BFD) library (aka libbfd) might have
    allowed remote attackers to cause a denial of service
    (buffer overflow and application crash) or possibly have
    unspecified other impact via a crafted binary file, as
    demonstrated by mishandling of this file during 'objdump
    -D' execution (bsc#1044897).

  - CVE-2017-9748: The ieee_object_p function in the Binary
    File Descriptor (BFD) library (aka libbfd) might have
    allowed remote attackers to cause a denial of service
    (buffer overflow and application crash) or possibly have
    unspecified other impact via a crafted binary file, as
    demonstrated by mishandling of this file during 'objdump
    -D' execution (bsc#1044901).

  - CVE-2017-9750: opcodes/rx-decode.opc lacked bounds
    checks for certain scale arrays, which allowed remote
    attackers to cause a denial of service (buffer overflow
    and application crash) or possibly have unspecified
    other impact via a crafted binary file, as demonstrated
    by mishandling of this file during 'objdump -D'
    execution (bsc#1044909).

  - CVE-2017-9755: Not considering the the number of
    registers for bnd mode allowed remote attackers to cause
    a denial of service (buffer overflow and application
    crash) or possibly have unspecified other impact via a
    crafted binary file, as demonstrated by mishandling of
    this file during 'objdump -D' execution (bsc#1044925).

  - CVE-2017-9756: The aarch64_ext_ldst_reglist function
    allowed remote attackers to cause a denial of service
    (buffer overflow and application crash) or possibly have
    unspecified other impact via a crafted binary file, as
    demonstrated by mishandling of this file during 'objdump
    -D' execution (bsc#1044927).

  - CVE-2017-7209: The dump_section_as_bytes function in
    readelf accessed a NULL pointer while reading section
    contents in a corrupt binary, leading to a program crash
    (bsc#1030298).

  - CVE-2017-6965: readelf wrote to illegal addresses while
    processing corrupt input files containing
    symbol-difference relocations, leading to a heap-based
    buffer overflow (bsc#1029909).

  - CVE-2017-6966: readelf had a use-after-free
    (specifically read-after-free) error while processing
    multiple, relocated sections in an MSP430 binary. This
    is caused by mishandling of an invalid symbol index, and
    mishandling of state across invocations (bsc#1029908).

  - CVE-2017-6969: readelf was vulnerable to a heap-based
    buffer over-read while processing corrupt RL78 binaries.
    The vulnerability can trigger program crashes. It may
    lead to an information leak as well (bsc#1029907).

  - CVE-2017-7210: objdump was vulnerable to multiple
    heap-based buffer over-reads (of size 1 and size 8)
    while handling corrupt STABS enum type strings in a
    crafted object file, leading to program crash
    (bsc#1030297). This update was imported from the
    SUSE:SLE-12:Update update project.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1029907");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1029908");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1029909");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1030296");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1030297");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1030298");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1030584");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1030585");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1030588");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1030589");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1031590");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1031593");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1031595");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1031638");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1031644");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1031656");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1037052");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1037057");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1037061");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1037066");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1037273");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1044891");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1044897");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1044901");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1044909");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1044925");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1044927");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1065643");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1065689");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1065693");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1068640");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1068643");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1068887");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1068888");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1068950");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1069176");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1069202");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1074741");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1077745");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1079103");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1079741");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1080556");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1081527");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1083528");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1083532");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1085784");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1086608");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1086784");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1086786");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1086788");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1090997");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1091015");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1091365");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1091368");
  script_set_attribute(attribute:"solution", value:
"Update the affected binutils packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-9939");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/10/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:binutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:binutils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:binutils-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:binutils-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:binutils-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:binutils-gold");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:binutils-gold-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cross-aarch64-binutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cross-aarch64-binutils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cross-aarch64-binutils-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cross-arm-binutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cross-arm-binutils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cross-arm-binutils-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cross-avr-binutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cross-avr-binutils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cross-avr-binutils-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cross-hppa-binutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cross-hppa-binutils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cross-hppa-binutils-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cross-hppa64-binutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cross-hppa64-binutils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cross-hppa64-binutils-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cross-i386-binutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cross-i386-binutils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cross-i386-binutils-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cross-ia64-binutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cross-ia64-binutils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cross-ia64-binutils-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cross-m68k-binutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cross-m68k-binutils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cross-m68k-binutils-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cross-mips-binutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cross-mips-binutils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cross-mips-binutils-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cross-ppc-binutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cross-ppc-binutils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cross-ppc-binutils-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cross-ppc64-binutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cross-ppc64-binutils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cross-ppc64-binutils-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cross-ppc64le-binutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cross-ppc64le-binutils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cross-ppc64le-binutils-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cross-s390-binutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cross-s390-binutils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cross-s390-binutils-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cross-s390x-binutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cross-s390x-binutils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cross-s390x-binutils-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cross-sparc-binutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cross-sparc-binutils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cross-sparc-binutils-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cross-sparc64-binutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cross-sparc64-binutils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cross-sparc64-binutils-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cross-spu-binutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cross-spu-binutils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cross-spu-binutils-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cross-x86_64-binutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cross-x86_64-binutils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cross-x86_64-binutils-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "openSUSE");
if (release !~ "^(SUSE42\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.3", reference:"binutils-2.31-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"binutils-debuginfo-2.31-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"binutils-debugsource-2.31-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"binutils-devel-2.31-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"binutils-gold-2.31-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"binutils-gold-debuginfo-2.31-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"cross-aarch64-binutils-2.31-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"cross-aarch64-binutils-debuginfo-2.31-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"cross-aarch64-binutils-debugsource-2.31-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"cross-arm-binutils-2.31-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"cross-arm-binutils-debuginfo-2.31-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"cross-arm-binutils-debugsource-2.31-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"cross-avr-binutils-2.31-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"cross-avr-binutils-debuginfo-2.31-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"cross-avr-binutils-debugsource-2.31-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"cross-hppa-binutils-2.31-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"cross-hppa-binutils-debuginfo-2.31-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"cross-hppa-binutils-debugsource-2.31-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"cross-hppa64-binutils-2.31-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"cross-hppa64-binutils-debuginfo-2.31-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"cross-hppa64-binutils-debugsource-2.31-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"cross-ia64-binutils-2.31-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"cross-ia64-binutils-debuginfo-2.31-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"cross-ia64-binutils-debugsource-2.31-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"cross-m68k-binutils-2.31-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"cross-m68k-binutils-debuginfo-2.31-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"cross-m68k-binutils-debugsource-2.31-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"cross-mips-binutils-2.31-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"cross-mips-binutils-debuginfo-2.31-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"cross-mips-binutils-debugsource-2.31-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"cross-ppc-binutils-2.31-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"cross-ppc-binutils-debuginfo-2.31-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"cross-ppc-binutils-debugsource-2.31-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"cross-ppc64-binutils-2.31-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"cross-ppc64-binutils-debuginfo-2.31-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"cross-ppc64-binutils-debugsource-2.31-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"cross-ppc64le-binutils-2.31-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"cross-ppc64le-binutils-debuginfo-2.31-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"cross-ppc64le-binutils-debugsource-2.31-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"cross-s390-binutils-2.31-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"cross-s390-binutils-debuginfo-2.31-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"cross-s390-binutils-debugsource-2.31-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"cross-s390x-binutils-2.31-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"cross-s390x-binutils-debuginfo-2.31-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"cross-s390x-binutils-debugsource-2.31-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"cross-sparc-binutils-2.31-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"cross-sparc-binutils-debuginfo-2.31-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"cross-sparc-binutils-debugsource-2.31-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"cross-sparc64-binutils-2.31-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"cross-sparc64-binutils-debuginfo-2.31-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"cross-sparc64-binutils-debugsource-2.31-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"cross-spu-binutils-2.31-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"cross-spu-binutils-debuginfo-2.31-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"cross-spu-binutils-debugsource-2.31-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"cross-x86_64-binutils-2.31-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"cross-x86_64-binutils-debuginfo-2.31-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"cross-x86_64-binutils-debugsource-2.31-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"binutils-devel-32bit-2.31-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"cross-i386-binutils-2.31-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"cross-i386-binutils-debuginfo-2.31-19.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"cross-i386-binutils-debugsource-2.31-19.1") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "binutils / binutils-debuginfo / binutils-debugsource / etc");
}
