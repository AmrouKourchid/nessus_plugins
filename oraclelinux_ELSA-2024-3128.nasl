#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2024-3128.
##

include('compat.inc');

if (description)
{
  script_id(198025);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/02");

  script_cve_id("CVE-2023-47038");

  script_name(english:"Oracle Linux 8 : perl:5.32 (ELSA-2024-3128)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 8 host has packages installed that are affected by a vulnerability as referenced in the
ELSA-2024-3128 advisory.

    - Fix CVE-2023-47038

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2024-3128.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-47038");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/11/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/05/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/05/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:linux:8:10:appstream_base");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:linux:8::appstream");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Algorithm-Diff");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Archive-Tar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Archive-Zip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Attribute-Handlers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-AutoLoader");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-AutoSplit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-B");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Benchmark");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-CPAN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-CPAN-DistnameInfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-CPAN-Meta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-CPAN-Meta-Requirements");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-CPAN-Meta-YAML");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Carp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Class-Struct");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Compress-Bzip2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Compress-Raw-Bzip2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Compress-Raw-Lzma");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Compress-Raw-Zlib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Config-Extensions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Config-Perl-V");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-DBM_Filter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-DB_File");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Data-Dumper");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Data-OptList");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Data-Section");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Devel-PPPort");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Devel-Peek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Devel-SelfStubber");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Devel-Size");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Digest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Digest-MD5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Digest-SHA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-DirHandle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Dumpvalue");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-DynaLoader");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Encode");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Encode-Locale");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Encode-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-English");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Env");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Errno");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Exporter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-ExtUtils-CBuilder");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-ExtUtils-Command");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-ExtUtils-Constant");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-ExtUtils-Embed");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-ExtUtils-Install");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-ExtUtils-MM-Utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-ExtUtils-MakeMaker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-ExtUtils-Manifest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-ExtUtils-Miniperl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-ExtUtils-ParseXS");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Fcntl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Fedora-VSP");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-File-Basename");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-File-Compare");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-File-Copy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-File-DosGlob");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-File-Fetch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-File-Find");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-File-HomeDir");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-File-Path");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-File-Temp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-File-Which");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-File-stat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-FileCache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-FileHandle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Filter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Filter-Simple");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-FindBin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-GDBM_File");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Getopt-Long");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Getopt-Std");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-HTTP-Tiny");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Hash-Util");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Hash-Util-FieldHash");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-I18N-Collate");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-I18N-LangTags");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-I18N-Langinfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-IO");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-IO-Compress");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-IO-Compress-Lzma");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-IO-Socket-IP");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-IO-Zlib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-IPC-Cmd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-IPC-Open3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-IPC-SysV");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-IPC-System-Simple");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Importer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-JSON-PP");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Locale-Maketext");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Locale-Maketext-Simple");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-MIME-Base64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-MRO-Compat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Math-BigInt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Math-BigInt-FastCalc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Math-BigRat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Math-Complex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Memoize");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Module-Build");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Module-CoreList");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Module-CoreList-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Module-Load");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Module-Load-Conditional");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Module-Loaded");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Module-Metadata");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-NDBM_File");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-NEXT");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Net");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Net-Ping");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-ODBM_File");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Object-HashBase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Object-HashBase-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Opcode");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-POSIX");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Package-Generator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Params-Check");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Params-Util");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-PathTools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Perl-OSType");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-PerlIO-via-QuotedPrint");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Pod-Checker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Pod-Escapes");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Pod-Functions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Pod-Html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Pod-Parser");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Pod-Perldoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Pod-Simple");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Pod-Usage");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Safe");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Scalar-List-Utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Search-Dict");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-SelectSaver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-SelfLoader");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Socket");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Software-License");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Storable");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Sub-Exporter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Sub-Install");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Symbol");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Sys-Hostname");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Sys-Syslog");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Term-ANSIColor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Term-Cap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Term-Complete");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Term-ReadLine");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Term-Table");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Test-Harness");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Test-Simple");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Text-Abbrev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Text-Balanced");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Text-Diff");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Text-Glob");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Text-ParseWords");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Text-Tabs+Wrap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Text-Template");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Thread");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Thread-Queue");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Thread-Semaphore");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Tie");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Tie-File");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Tie-Memoize");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Tie-RefHash");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Time");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Time-HiRes");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Time-Local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Time-Piece");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-URI");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Unicode-Collate");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Unicode-Normalize");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Unicode-UCD");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-User-pwent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-autodie");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-autouse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-bignum");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-blib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-constant");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-debugger");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-deprecate");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-diagnostics");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-encoding");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-encoding-warnings");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-experimental");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-fields");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-filetest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-generators");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-homedir");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-if");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-inc-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-interpreter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-less");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-libnet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-libnetcfg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-local-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-locale");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-macros");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-meta-notation");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-mro");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-open");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-overload");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-overloading");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-parent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-perlfaq");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-ph");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-podlators");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-sigtrap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-sort");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-subs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-threads");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-threads-shared");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-vars");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-version");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-vmsish");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/local_checks_enabled");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item('Host/OracleLinux')) audit(AUDIT_OS_NOT, 'Oracle Linux');
var os_release = get_kb_item("Host/RedHat/release");
if (isnull(os_release) || !pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:os_release)) audit(AUDIT_OS_NOT, 'Oracle Linux');
var os_ver = pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Oracle Linux');
os_ver = os_ver[1];
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 8', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);

var module_ver = get_kb_item('Host/RedHat/appstream/perl');
if (isnull(module_ver)) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module perl:5.32');
if ('5.32' >!< module_ver) audit(AUDIT_PACKAGE_NOT_AFFECTED, 'Module perl:' + module_ver);

var appstreams = {
    'perl:5.32': [
      {'reference':'perl-5.32.1-473.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
      {'reference':'perl-Algorithm-Diff-1.1903-10.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Archive-Tar-2.38-3.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Archive-Zip-1.68-3.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Attribute-Handlers-1.01-473.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-AutoLoader-5.74-473.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-AutoSplit-5.74-473.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-B-1.80-473.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Benchmark-1.23-473.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-CPAN-2.28-5.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-CPAN-DistnameInfo-0.12-13.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-CPAN-Meta-2.150010-397.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-CPAN-Meta-Requirements-2.140-397.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-CPAN-Meta-YAML-0.018-1001.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Carp-1.50-439.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Class-Struct-0.66-473.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Compress-Bzip2-2.28-2.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Compress-Raw-Bzip2-2.096-1.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Compress-Raw-Lzma-2.096-1.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Compress-Raw-Zlib-2.096-2.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Config-Extensions-0.03-473.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Config-Perl-V-0.32-441.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-DBM_Filter-0.06-473.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-DB_File-1.855-1.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Data-Dumper-2.174-440.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Data-OptList-0.110-7.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Data-Section-0.200007-8.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Devel-PPPort-3.62-1.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Devel-Peek-1.28-473.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Devel-SelfStubber-1.06-473.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Devel-Size-0.83-3.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Digest-1.20-1.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Digest-MD5-2.58-1.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Digest-SHA-6.02-2.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'perl-DirHandle-1.05-473.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Dumpvalue-2.27-473.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-DynaLoader-1.47-473.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Encode-3.08-461.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
      {'reference':'perl-Encode-Locale-1.05-10.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Encode-devel-3.08-461.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
      {'reference':'perl-English-1.11-473.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Env-1.04-396.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Errno-1.30-473.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Exporter-5.74-458.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-ExtUtils-CBuilder-0.280236-1.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'perl-ExtUtils-Command-7.46-3.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'perl-ExtUtils-Constant-0.25-473.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-ExtUtils-Embed-1.35-473.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-ExtUtils-Install-2.20-1.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-ExtUtils-MM-Utils-7.46-3.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'perl-ExtUtils-MakeMaker-7.46-3.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'perl-ExtUtils-Manifest-1.73-1.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'perl-ExtUtils-Miniperl-1.09-473.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-ExtUtils-ParseXS-3.40-439.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'perl-Fcntl-1.13-473.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Fedora-VSP-0.001-10.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-File-Basename-2.85-473.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-File-Compare-1.100.600-473.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-File-Copy-2.34-473.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-File-DosGlob-1.12-473.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-File-Fetch-1.00-1.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-File-Find-1.37-473.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-File-HomeDir-1.004-6.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-File-Path-2.16-439.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-File-Temp-0.231.100-1.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'perl-File-Which-1.23-4.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-File-stat-1.09-473.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-FileCache-1.10-473.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-FileHandle-2.03-473.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Filter-1.60-1.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'perl-Filter-Simple-0.96-457.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-FindBin-1.51-473.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-GDBM_File-1.18-473.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Getopt-Long-2.52-1.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'perl-Getopt-Std-1.12-473.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-HTTP-Tiny-0.078-1.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Hash-Util-0.23-473.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Hash-Util-FieldHash-1.20-473.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-I18N-Collate-1.02-473.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-I18N-LangTags-0.44-473.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-I18N-Langinfo-0.19-473.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-IO-1.43-473.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-IO-Compress-2.096-1.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-IO-Compress-Lzma-2.096-1.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-IO-Socket-IP-0.41-2.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-IO-Zlib-1.10-473.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'perl-IPC-Cmd-1.04-2.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'perl-IPC-Open3-1.21-473.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-IPC-SysV-2.09-1.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-IPC-System-Simple-1.30-3.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Importer-0.025-6.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-JSON-PP-4.04-2.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'perl-Locale-Maketext-1.29-440.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Locale-Maketext-Simple-0.21-473.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'perl-MIME-Base64-3.15-1001.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-MRO-Compat-0.13-5.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Math-BigInt-1.9998.18-1.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'perl-Math-BigInt-FastCalc-0.500.900-1.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Math-BigRat-0.2614-2.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Math-Complex-1.59-473.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Memoize-1.03-473.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Module-Build-0.42.31-5.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'perl-Module-CoreList-5.20211020-1.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'perl-Module-CoreList-tools-5.20211020-1.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'perl-Module-Load-0.36-1.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'perl-Module-Load-Conditional-0.74-1.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Module-Loaded-0.08-473.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'perl-Module-Metadata-1.000037-1.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-NDBM_File-1.15-473.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-NEXT-0.67-473.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Net-1.02-473.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Net-Ping-2.72-473.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-ODBM_File-1.16-473.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Object-HashBase-0.009-4.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Object-HashBase-tools-0.009-4.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Opcode-1.48-473.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-POSIX-1.94-473.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Package-Generator-1.106-12.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Params-Check-0.38-396.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'perl-Params-Util-1.102-2.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-PathTools-3.78-439.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Perl-OSType-1.010-397.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-PerlIO-via-QuotedPrint-0.09-1.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Pod-Checker-1.74-1.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
      {'reference':'perl-Pod-Escapes-1.07-396.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'perl-Pod-Functions-1.13-473.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Pod-Html-1.25-473.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Pod-Parser-1.63-1001.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Pod-Perldoc-3.28.01-443.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Pod-Simple-3.42-1.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'perl-Pod-Usage-2.01-1.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
      {'reference':'perl-Safe-2.41-473.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Scalar-List-Utils-1.55-457.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
      {'reference':'perl-Search-Dict-1.07-473.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-SelectSaver-1.02-473.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-SelfLoader-1.26-473.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Socket-2.031-1.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
      {'reference':'perl-Software-License-0.103014-5.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Storable-3.21-457.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'perl-Sub-Exporter-0.987-17.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Sub-Install-0.928-15.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Symbol-1.08-473.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Sys-Hostname-1.23-473.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Sys-Syslog-0.36-1.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Term-ANSIColor-5.01-458.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Term-Cap-1.17-396.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Term-Complete-1.403-473.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Term-ReadLine-1.17-473.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Term-Table-0.015-2.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Test-1.31-473.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Test-Harness-3.42-2.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'perl-Test-Simple-1.302181-2.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'perl-Text-Abbrev-1.02-473.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Text-Balanced-2.04-1.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Text-Diff-1.45-7.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Text-Glob-0.11-5.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Text-ParseWords-3.30-396.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Text-Tabs+Wrap-2013.0523-396.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Text-Template-1.58-1.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Thread-3.05-473.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Thread-Queue-3.14-457.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Thread-Semaphore-2.13-473.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Tie-4.6-473.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Tie-File-1.06-473.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Tie-Memoize-1.1-473.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Tie-RefHash-1.39-473.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Time-1.03-473.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Time-HiRes-1.9764-459.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
      {'reference':'perl-Time-Local-1.300-4.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'perl-Time-Piece-1.3401-473.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-URI-1.76-5.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Unicode-Collate-1.29-1.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Unicode-Normalize-1.27-458.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Unicode-UCD-0.75-473.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-User-pwent-1.03-473.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-autodie-2.34-1.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-autouse-1.11-473.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-base-2.27-473.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-bignum-0.51-439.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-blib-1.07-473.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-constant-1.33-1001.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-debugger-1.56-473.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-deprecate-0.04-473.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-devel-5.32.1-473.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
      {'reference':'perl-diagnostics-1.37-473.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-doc-5.32.1-473.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-encoding-3.00-461.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
      {'reference':'perl-encoding-warnings-0.13-473.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-experimental-0.025-1.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-fields-2.27-473.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-filetest-1.03-473.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-generators-1.13-1.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-homedir-2.000024-7.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-if-0.60.800-473.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-inc-latest-0.500-10.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'perl-interpreter-5.32.1-473.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
      {'reference':'perl-less-0.03-473.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-lib-0.65-473.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-libnet-3.13-1.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-libnetcfg-5.32.1-473.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
      {'reference':'perl-libs-5.32.1-473.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
      {'reference':'perl-local-lib-2.000024-7.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-locale-1.09-473.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-macros-5.32.1-473.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
      {'reference':'perl-meta-notation-5.32.1-473.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-mro-1.23-473.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-open-1.12-473.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-overload-1.31-473.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-overloading-0.02-473.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-parent-0.238-457.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'perl-perlfaq-5.20210520-1.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-ph-5.32.1-473.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-podlators-4.14-457.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'perl-sigtrap-1.09-473.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-sort-2.04-473.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-subs-1.03-473.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-threads-2.25-457.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'perl-threads-shared-1.61-457.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-utils-5.32.1-473.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-vars-1.05-473.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-version-0.99.29-1.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
      {'reference':'perl-vmsish-1.04-473.module+el8.10.0+90267+7012ad3b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-5.32.1-473.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
      {'reference':'perl-Algorithm-Diff-1.1903-10.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Archive-Tar-2.38-3.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Archive-Zip-1.68-3.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Attribute-Handlers-1.01-473.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-AutoLoader-5.74-473.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-AutoSplit-5.74-473.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-B-1.80-473.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Benchmark-1.23-473.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-CPAN-2.28-5.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-CPAN-DistnameInfo-0.12-13.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-CPAN-Meta-2.150010-397.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-CPAN-Meta-Requirements-2.140-397.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-CPAN-Meta-YAML-0.018-1001.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Carp-1.50-439.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Class-Struct-0.66-473.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Compress-Bzip2-2.28-2.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Compress-Raw-Bzip2-2.096-1.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Compress-Raw-Lzma-2.096-1.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Compress-Raw-Zlib-2.096-2.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Config-Extensions-0.03-473.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Config-Perl-V-0.32-441.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-DBM_Filter-0.06-473.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-DB_File-1.855-1.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Data-Dumper-2.174-440.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Data-OptList-0.110-7.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Data-Section-0.200007-8.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Devel-PPPort-3.62-1.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Devel-Peek-1.28-473.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Devel-SelfStubber-1.06-473.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Devel-Size-0.83-3.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Digest-1.20-1.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Digest-MD5-2.58-1.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Digest-SHA-6.02-2.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'perl-DirHandle-1.05-473.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Dumpvalue-2.27-473.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-DynaLoader-1.47-473.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Encode-3.08-461.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
      {'reference':'perl-Encode-Locale-1.05-10.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Encode-devel-3.08-461.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
      {'reference':'perl-English-1.11-473.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Env-1.04-396.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Errno-1.30-473.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Exporter-5.74-458.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-ExtUtils-CBuilder-0.280236-1.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'perl-ExtUtils-Command-7.46-3.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'perl-ExtUtils-Constant-0.25-473.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-ExtUtils-Embed-1.35-473.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-ExtUtils-Install-2.20-1.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-ExtUtils-MM-Utils-7.46-3.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'perl-ExtUtils-MakeMaker-7.46-3.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'perl-ExtUtils-Manifest-1.73-1.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'perl-ExtUtils-Miniperl-1.09-473.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-ExtUtils-ParseXS-3.40-439.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'perl-Fcntl-1.13-473.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Fedora-VSP-0.001-10.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-File-Basename-2.85-473.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-File-Compare-1.100.600-473.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-File-Copy-2.34-473.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-File-DosGlob-1.12-473.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-File-Fetch-1.00-1.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-File-Find-1.37-473.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-File-HomeDir-1.004-6.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-File-Path-2.16-439.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-File-Temp-0.231.100-1.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'perl-File-Which-1.23-4.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-File-stat-1.09-473.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-FileCache-1.10-473.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-FileHandle-2.03-473.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Filter-1.60-1.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'perl-Filter-Simple-0.96-457.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-FindBin-1.51-473.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-GDBM_File-1.18-473.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Getopt-Long-2.52-1.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'perl-Getopt-Std-1.12-473.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-HTTP-Tiny-0.078-1.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Hash-Util-0.23-473.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Hash-Util-FieldHash-1.20-473.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-I18N-Collate-1.02-473.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-I18N-LangTags-0.44-473.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-I18N-Langinfo-0.19-473.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-IO-1.43-473.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-IO-Compress-2.096-1.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-IO-Compress-Lzma-2.096-1.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-IO-Socket-IP-0.41-2.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-IO-Zlib-1.10-473.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'perl-IPC-Cmd-1.04-2.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'perl-IPC-Open3-1.21-473.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-IPC-SysV-2.09-1.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-IPC-System-Simple-1.30-3.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Importer-0.025-6.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-JSON-PP-4.04-2.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'perl-Locale-Maketext-1.29-440.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Locale-Maketext-Simple-0.21-473.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'perl-MIME-Base64-3.15-1001.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-MRO-Compat-0.13-5.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Math-BigInt-1.9998.18-1.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'perl-Math-BigInt-FastCalc-0.500.900-1.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Math-BigRat-0.2614-2.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Math-Complex-1.59-473.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Memoize-1.03-473.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Module-Build-0.42.31-5.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'perl-Module-CoreList-5.20211020-1.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'perl-Module-CoreList-tools-5.20211020-1.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'perl-Module-Load-0.36-1.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'perl-Module-Load-Conditional-0.74-1.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Module-Loaded-0.08-473.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'perl-Module-Metadata-1.000037-1.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-NDBM_File-1.15-473.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-NEXT-0.67-473.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Net-1.02-473.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Net-Ping-2.72-473.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-ODBM_File-1.16-473.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Object-HashBase-0.009-4.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Object-HashBase-tools-0.009-4.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Opcode-1.48-473.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-POSIX-1.94-473.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Package-Generator-1.106-12.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Params-Check-0.38-396.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'perl-Params-Util-1.102-2.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-PathTools-3.78-439.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Perl-OSType-1.010-397.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-PerlIO-via-QuotedPrint-0.09-1.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Pod-Checker-1.74-1.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
      {'reference':'perl-Pod-Escapes-1.07-396.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'perl-Pod-Functions-1.13-473.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Pod-Html-1.25-473.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Pod-Parser-1.63-1001.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Pod-Perldoc-3.28.01-443.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Pod-Simple-3.42-1.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'perl-Pod-Usage-2.01-1.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
      {'reference':'perl-Safe-2.41-473.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Scalar-List-Utils-1.55-457.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
      {'reference':'perl-Search-Dict-1.07-473.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-SelectSaver-1.02-473.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-SelfLoader-1.26-473.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Socket-2.031-1.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
      {'reference':'perl-Software-License-0.103014-5.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Storable-3.21-457.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'perl-Sub-Exporter-0.987-17.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Sub-Install-0.928-15.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Symbol-1.08-473.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Sys-Hostname-1.23-473.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Sys-Syslog-0.36-1.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Term-ANSIColor-5.01-458.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Term-Cap-1.17-396.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Term-Complete-1.403-473.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Term-ReadLine-1.17-473.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Term-Table-0.015-2.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Test-1.31-473.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Test-Harness-3.42-2.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'perl-Test-Simple-1.302181-2.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'perl-Text-Abbrev-1.02-473.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Text-Balanced-2.04-1.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Text-Diff-1.45-7.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Text-Glob-0.11-5.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Text-ParseWords-3.30-396.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Text-Tabs+Wrap-2013.0523-396.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Text-Template-1.58-1.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Thread-3.05-473.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Thread-Queue-3.14-457.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Thread-Semaphore-2.13-473.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Tie-4.6-473.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Tie-File-1.06-473.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Tie-Memoize-1.1-473.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Tie-RefHash-1.39-473.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Time-1.03-473.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Time-HiRes-1.9764-459.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
      {'reference':'perl-Time-Local-1.300-4.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'perl-Time-Piece-1.3401-473.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-URI-1.76-5.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Unicode-Collate-1.29-1.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Unicode-Normalize-1.27-458.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Unicode-UCD-0.75-473.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-User-pwent-1.03-473.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-autodie-2.34-1.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-autouse-1.11-473.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-base-2.27-473.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-bignum-0.51-439.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-blib-1.07-473.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-constant-1.33-1001.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-debugger-1.56-473.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-deprecate-0.04-473.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-devel-5.32.1-473.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
      {'reference':'perl-diagnostics-1.37-473.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-doc-5.32.1-473.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-encoding-3.00-461.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
      {'reference':'perl-encoding-warnings-0.13-473.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-experimental-0.025-1.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-fields-2.27-473.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-filetest-1.03-473.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-generators-1.13-1.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-homedir-2.000024-7.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-if-0.60.800-473.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-inc-latest-0.500-10.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'perl-interpreter-5.32.1-473.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
      {'reference':'perl-less-0.03-473.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-lib-0.65-473.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-libnet-3.13-1.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-libnetcfg-5.32.1-473.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
      {'reference':'perl-libs-5.32.1-473.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
      {'reference':'perl-local-lib-2.000024-7.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-locale-1.09-473.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-macros-5.32.1-473.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
      {'reference':'perl-meta-notation-5.32.1-473.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-mro-1.23-473.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-open-1.12-473.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-overload-1.31-473.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-overloading-0.02-473.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-parent-0.238-457.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'perl-perlfaq-5.20210520-1.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-ph-5.32.1-473.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-podlators-4.14-457.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'perl-sigtrap-1.09-473.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-sort-2.04-473.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-subs-1.03-473.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-threads-2.25-457.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'perl-threads-shared-1.61-457.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-utils-5.32.1-473.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-vars-1.05-473.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-version-0.99.29-1.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
      {'reference':'perl-vmsish-1.04-473.module+el8.10.0+90267+7012ad3b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
    ]
};

var flag = 0;
var appstreams_found = 0;
foreach var module (keys(appstreams)) {
  var appstream = NULL;
  var appstream_name = NULL;
  var appstream_version = NULL;
  var appstream_split = split(module, sep:':', keep:FALSE);
  if (!empty_or_null(appstream_split)) {
    appstream_name = appstream_split[0];
    appstream_version = appstream_split[1];
    if (!empty_or_null(appstream_name)) appstream = get_one_kb_item('Host/RedHat/appstream/' + appstream_name);
  }
  if (!empty_or_null(appstream) && appstream_version == appstream || appstream_name == 'all') {
    appstreams_found++;
    foreach var package_array ( appstreams[module] ) {
      var reference = NULL;
      var _release = NULL;
      var sp = NULL;
      var _cpu = NULL;
      var el_string = NULL;
      var rpm_spec_vers_cmp = NULL;
      var epoch = NULL;
      var allowmaj = NULL;
      if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
      if (!empty_or_null(package_array['release'])) _release = 'EL' + package_array['release'];
      if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
      if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
      if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
      if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
      if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
      if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
      if (reference && _release) {
        if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
      }
    }
  }
}

if (!appstreams_found) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module perl:5.32');

if (flag)
{
  security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'perl / perl-Algorithm-Diff / perl-Archive-Tar / etc');
}
