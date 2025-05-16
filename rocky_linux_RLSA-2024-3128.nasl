#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# Rocky Linux Security Advisory RLSA-2024:3128.
##

include('compat.inc');

if (description)
{
  script_id(235551);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/07");

  script_cve_id("CVE-2023-47038");
  script_xref(name:"RLSA", value:"2024:3128");

  script_name(english:"RockyLinux 8 : perl:5.32 (RLSA-2024:3128)");

  script_set_attribute(attribute:"synopsis", value:
"The remote RockyLinux host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote RockyLinux 8 host has packages installed that are affected by a vulnerability as referenced in the
RLSA-2024:3128 advisory.

    * perl: Write past buffer end via illegal user-defined Unicode property (CVE-2023-47038)

Tenable has extracted the preceding description block directly from the RockyLinux security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.rockylinux.org/RLSA-2024:3128");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2249523");
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
  script_set_attribute(attribute:"patch_publication_date", value:"2025/05/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/05/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Algorithm-Diff");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Archive-Tar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Archive-Zip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Attribute-Handlers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-AutoLoader");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-AutoSplit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-B");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-B-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Benchmark");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-CPAN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-CPAN-DistnameInfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-CPAN-Meta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-CPAN-Meta-Requirements");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-CPAN-Meta-YAML");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Carp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Class-Struct");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Compress-Bzip2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Compress-Bzip2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Compress-Bzip2-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Compress-Raw-Bzip2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Compress-Raw-Bzip2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Compress-Raw-Bzip2-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Compress-Raw-Lzma");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Compress-Raw-Lzma-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Compress-Raw-Lzma-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Compress-Raw-Zlib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Compress-Raw-Zlib-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Compress-Raw-Zlib-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Config-Extensions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Config-Perl-V");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-DBM_Filter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-DB_File");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-DB_File-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-DB_File-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Data-Dumper");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Data-Dumper-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Data-Dumper-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Data-OptList");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Data-Section");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Devel-PPPort");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Devel-PPPort-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Devel-PPPort-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Devel-Peek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Devel-Peek-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Devel-SelfStubber");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Devel-Size");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Devel-Size-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Devel-Size-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Digest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Digest-MD5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Digest-MD5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Digest-MD5-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Digest-SHA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Digest-SHA-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Digest-SHA-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-DirHandle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Dumpvalue");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-DynaLoader");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-DynaLoader-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Encode");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Encode-Locale");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Encode-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Encode-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Encode-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-English");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Env");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Errno");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Exporter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-ExtUtils-CBuilder");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-ExtUtils-Command");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-ExtUtils-Constant");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-ExtUtils-Embed");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-ExtUtils-Install");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-ExtUtils-MM-Utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-ExtUtils-MakeMaker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-ExtUtils-Manifest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-ExtUtils-Miniperl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-ExtUtils-ParseXS");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Fcntl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Fcntl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Fedora-VSP");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-File-Basename");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-File-Compare");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-File-Copy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-File-DosGlob");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-File-DosGlob-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-File-Fetch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-File-Find");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-File-HomeDir");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-File-Path");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-File-Temp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-File-Which");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-File-stat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-FileCache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-FileHandle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Filter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Filter-Simple");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Filter-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Filter-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-FindBin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-GDBM_File");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-GDBM_File-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Getopt-Long");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Getopt-Std");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-HTTP-Tiny");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Hash-Util");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Hash-Util-FieldHash");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Hash-Util-FieldHash-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Hash-Util-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-I18N-Collate");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-I18N-LangTags");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-I18N-Langinfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-I18N-Langinfo-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-IO");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-IO-Compress");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-IO-Compress-Lzma");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-IO-Socket-IP");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-IO-Zlib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-IO-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-IPC-Cmd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-IPC-Open3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-IPC-SysV");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-IPC-SysV-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-IPC-SysV-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-IPC-System-Simple");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Importer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-JSON-PP");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Locale-Maketext");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Locale-Maketext-Simple");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-MIME-Base64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-MIME-Base64-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-MIME-Base64-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-MRO-Compat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Math-BigInt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Math-BigInt-FastCalc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Math-BigInt-FastCalc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Math-BigInt-FastCalc-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Math-BigRat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Math-Complex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Memoize");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Module-Build");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Module-CoreList");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Module-CoreList-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Module-Load");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Module-Load-Conditional");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Module-Loaded");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Module-Metadata");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-NDBM_File");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-NDBM_File-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-NEXT");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Net");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Net-Ping");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-ODBM_File");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-ODBM_File-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Object-HashBase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Object-HashBase-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Opcode");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Opcode-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-POSIX");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-POSIX-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Package-Generator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Params-Check");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Params-Util");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Params-Util-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Params-Util-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-PathTools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-PathTools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-PathTools-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Perl-OSType");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-PerlIO-via-QuotedPrint");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Pod-Checker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Pod-Escapes");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Pod-Functions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Pod-Html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Pod-Parser");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Pod-Perldoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Pod-Simple");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Pod-Usage");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Safe");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Scalar-List-Utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Scalar-List-Utils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Scalar-List-Utils-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Search-Dict");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-SelectSaver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-SelfLoader");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Socket");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Socket-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Socket-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Software-License");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Storable");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Storable-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Storable-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Sub-Exporter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Sub-Install");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Symbol");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Sys-Hostname");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Sys-Hostname-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Sys-Syslog");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Sys-Syslog-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Sys-Syslog-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Term-ANSIColor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Term-Cap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Term-Complete");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Term-ReadLine");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Term-Table");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Test-Harness");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Test-Simple");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Text-Abbrev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Text-Balanced");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Text-Diff");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Text-Glob");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Text-ParseWords");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Text-Tabs+Wrap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Text-Template");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Thread");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Thread-Queue");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Thread-Semaphore");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Tie");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Tie-File");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Tie-Memoize");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Tie-RefHash");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Time");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Time-HiRes");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Time-HiRes-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Time-HiRes-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Time-Local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Time-Piece");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Time-Piece-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-URI");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Unicode-Collate");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Unicode-Collate-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Unicode-Collate-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Unicode-Normalize");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Unicode-Normalize-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Unicode-Normalize-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Unicode-UCD");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-User-pwent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-autodie");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-autouse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-bignum");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-blib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-constant");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-debugger");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-deprecate");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-diagnostics");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-encoding");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-encoding-warnings");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-experimental");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-fields");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-filetest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-generators");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-homedir");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-if");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-inc-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-interpreter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-interpreter-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-less");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-libnet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-libnetcfg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-libs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-local-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-locale");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-macros");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-meta-notation");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-mro");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-mro-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-open");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-overload");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-overloading");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-parent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-perlfaq");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-ph");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-podlators");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-sigtrap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-sort");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-subs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-threads");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-threads-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-threads-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-threads-shared");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-threads-shared-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-threads-shared-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-vars");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-version");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-version-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-version-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-vmsish");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:rocky:linux:8");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Rocky Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RockyLinux/release", "Host/RockyLinux/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/RockyLinux/release');
if (isnull(os_release) || 'Rocky Linux' >!< os_release) audit(AUDIT_OS_NOT, 'Rocky Linux');
var os_ver = pregmatch(pattern: "Rocky(?: Linux)? release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Rocky Linux');
os_ver = os_ver[1];
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'RockyLinux 8.x', 'Rocky Linux ' + os_ver);

if (!get_kb_item('Host/RockyLinux/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('aarch64' >!< cpu && 'ppc' >!< cpu && 's390' >!< cpu && 'x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Rocky Linux', cpu);

var module_ver = get_kb_item('Host/RockyLinux/appstream/perl');
if (isnull(module_ver)) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module perl:5.32');
if ('5.32' >!< module_ver) audit(AUDIT_PACKAGE_NOT_AFFECTED, 'Module perl:' + module_ver);

var appstreams = {
    'perl:5.32': [
      {'reference':'perl-5.32.1-473.module+el8.10.0+1616+0d20cc68', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
      {'reference':'perl-5.32.1-473.module+el8.10.0+1616+0d20cc68', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
      {'reference':'perl-Algorithm-Diff-1.1903-10.module+el8.10.0+1616+0d20cc68', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Algorithm-Diff-1.1903-10.module+el8.6.0+878+f93dfff7', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Algorithm-Diff-1.1903-10.module+el8.6.0+882+2fa1e48f', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Archive-Tar-2.38-3.module+el8.10.0+1616+0d20cc68', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Archive-Zip-1.68-3.module+el8.10.0+1616+0d20cc68', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Attribute-Handlers-1.01-473.module+el8.10.0+1616+0d20cc68', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-autodie-2.34-1.module+el8.10.0+1616+0d20cc68', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-AutoLoader-5.74-473.module+el8.10.0+1616+0d20cc68', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-AutoSplit-5.74-473.module+el8.10.0+1616+0d20cc68', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-autouse-1.11-473.module+el8.10.0+1616+0d20cc68', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-B-1.80-473.module+el8.10.0+1616+0d20cc68', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-B-1.80-473.module+el8.10.0+1616+0d20cc68', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-B-debuginfo-1.80-473.module+el8.10.0+1616+0d20cc68', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-B-debuginfo-1.80-473.module+el8.10.0+1616+0d20cc68', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-base-2.27-473.module+el8.10.0+1616+0d20cc68', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Benchmark-1.23-473.module+el8.10.0+1616+0d20cc68', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-bignum-0.51-439.module+el8.10.0+1616+0d20cc68', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-bignum-0.51-439.module+el8.6.0+878+f93dfff7', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-blib-1.07-473.module+el8.10.0+1616+0d20cc68', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Carp-1.50-439.module+el8.10.0+1616+0d20cc68', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Carp-1.50-439.module+el8.6.0+878+f93dfff7', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Class-Struct-0.66-473.module+el8.10.0+1616+0d20cc68', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Compress-Bzip2-2.28-2.module+el8.10.0+1616+0d20cc68', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Compress-Bzip2-2.28-2.module+el8.10.0+1616+0d20cc68', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Compress-Bzip2-debuginfo-2.28-2.module+el8.10.0+1616+0d20cc68', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Compress-Bzip2-debuginfo-2.28-2.module+el8.10.0+1616+0d20cc68', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Compress-Bzip2-debugsource-2.28-2.module+el8.10.0+1616+0d20cc68', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Compress-Bzip2-debugsource-2.28-2.module+el8.10.0+1616+0d20cc68', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Compress-Raw-Bzip2-2.096-1.module+el8.10.0+1616+0d20cc68', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Compress-Raw-Bzip2-2.096-1.module+el8.10.0+1616+0d20cc68', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Compress-Raw-Bzip2-debuginfo-2.096-1.module+el8.10.0+1616+0d20cc68', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Compress-Raw-Bzip2-debuginfo-2.096-1.module+el8.10.0+1616+0d20cc68', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Compress-Raw-Bzip2-debugsource-2.096-1.module+el8.10.0+1616+0d20cc68', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Compress-Raw-Bzip2-debugsource-2.096-1.module+el8.10.0+1616+0d20cc68', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Compress-Raw-Lzma-2.096-1.module+el8.10.0+1616+0d20cc68', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Compress-Raw-Lzma-2.096-1.module+el8.10.0+1616+0d20cc68', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Compress-Raw-Lzma-debuginfo-2.096-1.module+el8.10.0+1616+0d20cc68', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Compress-Raw-Lzma-debuginfo-2.096-1.module+el8.10.0+1616+0d20cc68', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Compress-Raw-Lzma-debugsource-2.096-1.module+el8.10.0+1616+0d20cc68', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Compress-Raw-Lzma-debugsource-2.096-1.module+el8.10.0+1616+0d20cc68', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Compress-Raw-Zlib-2.096-2.module+el8.10.0+1753+8441f55f', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Compress-Raw-Zlib-2.096-2.module+el8.10.0+1753+8441f55f', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Compress-Raw-Zlib-debuginfo-2.096-2.module+el8.10.0+1753+8441f55f', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Compress-Raw-Zlib-debuginfo-2.096-2.module+el8.10.0+1753+8441f55f', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Compress-Raw-Zlib-debugsource-2.096-2.module+el8.10.0+1753+8441f55f', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Compress-Raw-Zlib-debugsource-2.096-2.module+el8.10.0+1753+8441f55f', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Config-Extensions-0.03-473.module+el8.10.0+1616+0d20cc68', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Config-Perl-V-0.32-441.module+el8.10.0+1616+0d20cc68', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Config-Perl-V-0.32-441.module+el8.6.0+878+f93dfff7', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-constant-1.33-1001.module+el8.10.0+1616+0d20cc68', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-constant-1.33-1001.module+el8.6.0+878+f93dfff7', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-constant-1.33-1001.module+el8.6.0+882+2fa1e48f', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-CPAN-2.28-5.module+el8.10.0+1616+0d20cc68', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-CPAN-DistnameInfo-0.12-13.module+el8.10.0+1616+0d20cc68', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-CPAN-DistnameInfo-0.12-13.module+el8.10.0+1890+1072d5cf', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-CPAN-DistnameInfo-0.12-13.module+el8.10.0+1890+281b551b', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-CPAN-DistnameInfo-0.12-13.module+el8.10.0+1890+318cbfb5', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-CPAN-DistnameInfo-0.12-13.module+el8.6.0+878+f93dfff7', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-CPAN-DistnameInfo-0.12-13.module+el8.9.0+1491+219f8fe7', 'release':'8', 'el_string':'el8.9.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-CPAN-DistnameInfo-0.12-13.module+el8.9.0+1491+3507a112', 'release':'8', 'el_string':'el8.9.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-CPAN-DistnameInfo-0.12-13.module+el8.9.0+1491+a1bcd037', 'release':'8', 'el_string':'el8.9.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-CPAN-Meta-2.150010-397.module+el8.10.0+1616+0d20cc68', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-CPAN-Meta-2.150010-397.module+el8.6.0+878+f93dfff7', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-CPAN-Meta-2.150010-397.module+el8.6.0+882+2fa1e48f', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-CPAN-Meta-Requirements-2.140-397.module+el8.10.0+1616+0d20cc68', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-CPAN-Meta-Requirements-2.140-397.module+el8.6.0+878+f93dfff7', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-CPAN-Meta-Requirements-2.140-397.module+el8.6.0+882+2fa1e48f', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-CPAN-Meta-YAML-0.018-1001.module+el8.10.0+1616+0d20cc68', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-CPAN-Meta-YAML-0.018-1001.module+el8.6.0+878+f93dfff7', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-CPAN-Meta-YAML-0.018-1001.module+el8.6.0+882+2fa1e48f', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Data-Dumper-2.174-440.module+el8.10.0+1616+0d20cc68', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Data-Dumper-2.174-440.module+el8.10.0+1616+0d20cc68', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Data-Dumper-2.174-440.module+el8.6.0+878+f93dfff7', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Data-Dumper-2.174-440.module+el8.6.0+878+f93dfff7', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Data-Dumper-debuginfo-2.174-440.module+el8.10.0+1616+0d20cc68', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Data-Dumper-debuginfo-2.174-440.module+el8.10.0+1616+0d20cc68', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Data-Dumper-debuginfo-2.174-440.module+el8.6.0+878+f93dfff7', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Data-Dumper-debuginfo-2.174-440.module+el8.6.0+878+f93dfff7', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Data-Dumper-debugsource-2.174-440.module+el8.10.0+1616+0d20cc68', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Data-Dumper-debugsource-2.174-440.module+el8.10.0+1616+0d20cc68', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Data-Dumper-debugsource-2.174-440.module+el8.6.0+878+f93dfff7', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Data-Dumper-debugsource-2.174-440.module+el8.6.0+878+f93dfff7', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Data-OptList-0.110-7.module+el8.10.0+1616+0d20cc68', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Data-OptList-0.110-7.module+el8.6.0+878+f93dfff7', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Data-OptList-0.110-7.module+el8.6.0+882+2fa1e48f', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Data-Section-0.200007-8.module+el8.10.0+1616+0d20cc68', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Data-Section-0.200007-8.module+el8.6.0+878+f93dfff7', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-DB_File-1.855-1.module+el8.10.0+1616+0d20cc68', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-DB_File-1.855-1.module+el8.10.0+1616+0d20cc68', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-DB_File-debuginfo-1.855-1.module+el8.10.0+1616+0d20cc68', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-DB_File-debuginfo-1.855-1.module+el8.10.0+1616+0d20cc68', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-DB_File-debugsource-1.855-1.module+el8.10.0+1616+0d20cc68', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-DB_File-debugsource-1.855-1.module+el8.10.0+1616+0d20cc68', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-DBM_Filter-0.06-473.module+el8.10.0+1616+0d20cc68', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-debugger-1.56-473.module+el8.10.0+1616+0d20cc68', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-debuginfo-5.32.1-473.module+el8.10.0+1616+0d20cc68', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
      {'reference':'perl-debuginfo-5.32.1-473.module+el8.10.0+1616+0d20cc68', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
      {'reference':'perl-debugsource-5.32.1-473.module+el8.10.0+1616+0d20cc68', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
      {'reference':'perl-debugsource-5.32.1-473.module+el8.10.0+1616+0d20cc68', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
      {'reference':'perl-deprecate-0.04-473.module+el8.10.0+1616+0d20cc68', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-devel-5.32.1-473.module+el8.10.0+1616+0d20cc68', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
      {'reference':'perl-devel-5.32.1-473.module+el8.10.0+1616+0d20cc68', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
      {'reference':'perl-Devel-Peek-1.28-473.module+el8.10.0+1616+0d20cc68', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Devel-Peek-1.28-473.module+el8.10.0+1616+0d20cc68', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Devel-Peek-debuginfo-1.28-473.module+el8.10.0+1616+0d20cc68', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Devel-Peek-debuginfo-1.28-473.module+el8.10.0+1616+0d20cc68', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Devel-PPPort-3.62-1.module+el8.10.0+1616+0d20cc68', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Devel-PPPort-3.62-1.module+el8.10.0+1616+0d20cc68', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Devel-PPPort-debuginfo-3.62-1.module+el8.10.0+1616+0d20cc68', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Devel-PPPort-debuginfo-3.62-1.module+el8.10.0+1616+0d20cc68', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Devel-PPPort-debugsource-3.62-1.module+el8.10.0+1616+0d20cc68', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Devel-PPPort-debugsource-3.62-1.module+el8.10.0+1616+0d20cc68', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Devel-SelfStubber-1.06-473.module+el8.10.0+1616+0d20cc68', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Devel-Size-0.83-3.module+el8.10.0+1616+0d20cc68', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Devel-Size-0.83-3.module+el8.10.0+1616+0d20cc68', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Devel-Size-0.83-3.module+el8.6.0+878+f93dfff7', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Devel-Size-0.83-3.module+el8.6.0+878+f93dfff7', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Devel-Size-debuginfo-0.83-3.module+el8.10.0+1616+0d20cc68', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Devel-Size-debuginfo-0.83-3.module+el8.10.0+1616+0d20cc68', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Devel-Size-debuginfo-0.83-3.module+el8.6.0+878+f93dfff7', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Devel-Size-debuginfo-0.83-3.module+el8.6.0+878+f93dfff7', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Devel-Size-debugsource-0.83-3.module+el8.10.0+1616+0d20cc68', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Devel-Size-debugsource-0.83-3.module+el8.10.0+1616+0d20cc68', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Devel-Size-debugsource-0.83-3.module+el8.6.0+878+f93dfff7', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Devel-Size-debugsource-0.83-3.module+el8.6.0+878+f93dfff7', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-diagnostics-1.37-473.module+el8.10.0+1616+0d20cc68', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Digest-1.20-1.module+el8.10.0+1616+0d20cc68', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Digest-MD5-2.58-1.module+el8.10.0+1616+0d20cc68', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Digest-MD5-2.58-1.module+el8.10.0+1616+0d20cc68', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Digest-MD5-debuginfo-2.58-1.module+el8.10.0+1616+0d20cc68', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Digest-MD5-debuginfo-2.58-1.module+el8.10.0+1616+0d20cc68', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Digest-MD5-debugsource-2.58-1.module+el8.10.0+1616+0d20cc68', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Digest-MD5-debugsource-2.58-1.module+el8.10.0+1616+0d20cc68', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Digest-SHA-6.02-2.module+el8.10.0+1616+0d20cc68', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'perl-Digest-SHA-6.02-2.module+el8.10.0+1616+0d20cc68', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'perl-Digest-SHA-6.02-2.module+el8.6.0+878+f93dfff7', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'perl-Digest-SHA-6.02-2.module+el8.6.0+878+f93dfff7', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'perl-Digest-SHA-6.02-2.module+el8.6.0+882+2fa1e48f', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'perl-Digest-SHA-6.02-2.module+el8.6.0+882+2fa1e48f', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'perl-Digest-SHA-debuginfo-6.02-2.module+el8.10.0+1616+0d20cc68', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'perl-Digest-SHA-debuginfo-6.02-2.module+el8.10.0+1616+0d20cc68', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'perl-Digest-SHA-debuginfo-6.02-2.module+el8.6.0+878+f93dfff7', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'perl-Digest-SHA-debuginfo-6.02-2.module+el8.6.0+878+f93dfff7', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'perl-Digest-SHA-debuginfo-6.02-2.module+el8.6.0+882+2fa1e48f', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'perl-Digest-SHA-debuginfo-6.02-2.module+el8.6.0+882+2fa1e48f', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'perl-Digest-SHA-debugsource-6.02-2.module+el8.10.0+1616+0d20cc68', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'perl-Digest-SHA-debugsource-6.02-2.module+el8.10.0+1616+0d20cc68', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'perl-Digest-SHA-debugsource-6.02-2.module+el8.6.0+878+f93dfff7', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'perl-Digest-SHA-debugsource-6.02-2.module+el8.6.0+878+f93dfff7', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'perl-Digest-SHA-debugsource-6.02-2.module+el8.6.0+882+2fa1e48f', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'perl-Digest-SHA-debugsource-6.02-2.module+el8.6.0+882+2fa1e48f', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'perl-DirHandle-1.05-473.module+el8.10.0+1616+0d20cc68', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-doc-5.32.1-473.module+el8.10.0+1616+0d20cc68', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Dumpvalue-2.27-473.module+el8.10.0+1616+0d20cc68', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-DynaLoader-1.47-473.module+el8.10.0+1616+0d20cc68', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-DynaLoader-1.47-473.module+el8.10.0+1616+0d20cc68', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-DynaLoader-debuginfo-1.47-473.module+el8.10.0+1616+0d20cc68', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-DynaLoader-debuginfo-1.47-473.module+el8.10.0+1616+0d20cc68', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Encode-3.08-461.module+el8.10.0+1616+0d20cc68', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
      {'reference':'perl-Encode-3.08-461.module+el8.10.0+1616+0d20cc68', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
      {'reference':'perl-Encode-debuginfo-3.08-461.module+el8.10.0+1616+0d20cc68', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
      {'reference':'perl-Encode-debuginfo-3.08-461.module+el8.10.0+1616+0d20cc68', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
      {'reference':'perl-Encode-debugsource-3.08-461.module+el8.10.0+1616+0d20cc68', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
      {'reference':'perl-Encode-debugsource-3.08-461.module+el8.10.0+1616+0d20cc68', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
      {'reference':'perl-Encode-devel-3.08-461.module+el8.10.0+1616+0d20cc68', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
      {'reference':'perl-Encode-devel-3.08-461.module+el8.10.0+1616+0d20cc68', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
      {'reference':'perl-Encode-Locale-1.05-10.module+el8.10.0+1616+0d20cc68', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Encode-Locale-1.05-10.module+el8.9.0+1521+0101edce', 'release':'8', 'el_string':'el8.9.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Encode-Locale-1.05-10.module+el8.9.0+1521+b0a37ee7', 'release':'8', 'el_string':'el8.9.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Encode-Locale-1.05-10.module+el8.9.0+1521+ec157587', 'release':'8', 'el_string':'el8.9.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Encode-Locale-1.05-10.module+el8.9.0+1521+faf8d1d6', 'release':'8', 'el_string':'el8.9.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-encoding-3.00-461.module+el8.10.0+1616+0d20cc68', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
      {'reference':'perl-encoding-3.00-461.module+el8.10.0+1616+0d20cc68', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
      {'reference':'perl-encoding-warnings-0.13-473.module+el8.10.0+1616+0d20cc68', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-English-1.11-473.module+el8.10.0+1616+0d20cc68', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Env-1.04-396.module+el8.10.0+1616+0d20cc68', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Env-1.04-396.module+el8.6.0+878+f93dfff7', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Env-1.04-396.module+el8.6.0+882+2fa1e48f', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Errno-1.30-473.module+el8.10.0+1616+0d20cc68', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Errno-1.30-473.module+el8.10.0+1616+0d20cc68', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-experimental-0.025-1.module+el8.10.0+1616+0d20cc68', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Exporter-5.74-458.module+el8.10.0+1616+0d20cc68', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-ExtUtils-CBuilder-0.280236-1.module+el8.10.0+1616+0d20cc68', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'perl-ExtUtils-Command-7.46-3.module+el8.10.0+1616+0d20cc68', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'perl-ExtUtils-Constant-0.25-473.module+el8.10.0+1616+0d20cc68', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-ExtUtils-Embed-1.35-473.module+el8.10.0+1616+0d20cc68', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-ExtUtils-Install-2.20-1.module+el8.10.0+1616+0d20cc68', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-ExtUtils-MakeMaker-7.46-3.module+el8.10.0+1616+0d20cc68', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'perl-ExtUtils-Manifest-1.73-1.module+el8.10.0+1616+0d20cc68', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'perl-ExtUtils-Miniperl-1.09-473.module+el8.10.0+1616+0d20cc68', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-ExtUtils-MM-Utils-7.46-3.module+el8.10.0+1616+0d20cc68', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'perl-ExtUtils-ParseXS-3.40-439.module+el8.10.0+1616+0d20cc68', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'perl-ExtUtils-ParseXS-3.40-439.module+el8.6.0+878+f93dfff7', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'perl-Fcntl-1.13-473.module+el8.10.0+1616+0d20cc68', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Fcntl-1.13-473.module+el8.10.0+1616+0d20cc68', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Fcntl-debuginfo-1.13-473.module+el8.10.0+1616+0d20cc68', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Fcntl-debuginfo-1.13-473.module+el8.10.0+1616+0d20cc68', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Fedora-VSP-0.001-10.module+el8.10.0+1616+0d20cc68', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Fedora-VSP-0.001-10.module+el8.6.0+878+f93dfff7', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Fedora-VSP-0.001-10.module+el8.6.0+882+2fa1e48f', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-fields-2.27-473.module+el8.10.0+1616+0d20cc68', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-File-Basename-2.85-473.module+el8.10.0+1616+0d20cc68', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-File-Compare-1.100.600-473.module+el8.10.0+1616+0d20cc68', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-File-Copy-2.34-473.module+el8.10.0+1616+0d20cc68', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-File-DosGlob-1.12-473.module+el8.10.0+1616+0d20cc68', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-File-DosGlob-1.12-473.module+el8.10.0+1616+0d20cc68', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-File-DosGlob-debuginfo-1.12-473.module+el8.10.0+1616+0d20cc68', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-File-DosGlob-debuginfo-1.12-473.module+el8.10.0+1616+0d20cc68', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-File-Fetch-1.00-1.module+el8.10.0+1616+0d20cc68', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-File-Find-1.37-473.module+el8.10.0+1616+0d20cc68', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-File-HomeDir-1.004-6.module+el8.10.0+1616+0d20cc68', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-File-HomeDir-1.004-6.module+el8.6.0+878+f93dfff7', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-File-Path-2.16-439.module+el8.10.0+1616+0d20cc68', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-File-Path-2.16-439.module+el8.6.0+878+f93dfff7', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-File-stat-1.09-473.module+el8.10.0+1616+0d20cc68', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-File-Temp-0.231.100-1.module+el8.10.0+1616+0d20cc68', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'perl-File-Which-1.23-4.module+el8.10.0+1616+0d20cc68', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-File-Which-1.23-4.module+el8.6.0+878+f93dfff7', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-FileCache-1.10-473.module+el8.10.0+1616+0d20cc68', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-FileHandle-2.03-473.module+el8.10.0+1616+0d20cc68', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-filetest-1.03-473.module+el8.10.0+1616+0d20cc68', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Filter-1.60-1.module+el8.10.0+1616+0d20cc68', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'perl-Filter-1.60-1.module+el8.10.0+1616+0d20cc68', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'perl-Filter-debuginfo-1.60-1.module+el8.10.0+1616+0d20cc68', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'perl-Filter-debuginfo-1.60-1.module+el8.10.0+1616+0d20cc68', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'perl-Filter-debugsource-1.60-1.module+el8.10.0+1616+0d20cc68', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'perl-Filter-debugsource-1.60-1.module+el8.10.0+1616+0d20cc68', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'perl-Filter-Simple-0.96-457.module+el8.10.0+1616+0d20cc68', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-FindBin-1.51-473.module+el8.10.0+1616+0d20cc68', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-GDBM_File-1.18-473.module+el8.10.0+1616+0d20cc68', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-GDBM_File-1.18-473.module+el8.10.0+1616+0d20cc68', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-GDBM_File-debuginfo-1.18-473.module+el8.10.0+1616+0d20cc68', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-GDBM_File-debuginfo-1.18-473.module+el8.10.0+1616+0d20cc68', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-generators-1.13-1.module+el8.10.0+1616+0d20cc68', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Getopt-Long-2.52-1.module+el8.10.0+1616+0d20cc68', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'perl-Getopt-Std-1.12-473.module+el8.10.0+1616+0d20cc68', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Hash-Util-0.23-473.module+el8.10.0+1616+0d20cc68', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Hash-Util-0.23-473.module+el8.10.0+1616+0d20cc68', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Hash-Util-debuginfo-0.23-473.module+el8.10.0+1616+0d20cc68', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Hash-Util-debuginfo-0.23-473.module+el8.10.0+1616+0d20cc68', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Hash-Util-FieldHash-1.20-473.module+el8.10.0+1616+0d20cc68', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Hash-Util-FieldHash-1.20-473.module+el8.10.0+1616+0d20cc68', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Hash-Util-FieldHash-debuginfo-1.20-473.module+el8.10.0+1616+0d20cc68', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Hash-Util-FieldHash-debuginfo-1.20-473.module+el8.10.0+1616+0d20cc68', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-homedir-2.000024-7.module+el8.10.0+1616+0d20cc68', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-homedir-2.000024-7.module+el8.6.0+878+f93dfff7', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-HTTP-Tiny-0.078-1.module+el8.10.0+1616+0d20cc68', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-I18N-Collate-1.02-473.module+el8.10.0+1616+0d20cc68', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-I18N-Langinfo-0.19-473.module+el8.10.0+1616+0d20cc68', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-I18N-Langinfo-0.19-473.module+el8.10.0+1616+0d20cc68', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-I18N-Langinfo-debuginfo-0.19-473.module+el8.10.0+1616+0d20cc68', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-I18N-Langinfo-debuginfo-0.19-473.module+el8.10.0+1616+0d20cc68', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-I18N-LangTags-0.44-473.module+el8.10.0+1616+0d20cc68', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-if-0.60.800-473.module+el8.10.0+1616+0d20cc68', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Importer-0.025-6.module+el8.10.0+1616+0d20cc68', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Importer-0.025-6.module+el8.6.0+878+f93dfff7', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-inc-latest-0.500-10.module+el8.10.0+1616+0d20cc68', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'perl-inc-latest-0.500-10.module+el8.6.0+878+f93dfff7', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'perl-inc-latest-0.500-10.module+el8.6.0+882+2fa1e48f', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'perl-interpreter-5.32.1-473.module+el8.10.0+1616+0d20cc68', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
      {'reference':'perl-interpreter-5.32.1-473.module+el8.10.0+1616+0d20cc68', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
      {'reference':'perl-interpreter-debuginfo-5.32.1-473.module+el8.10.0+1616+0d20cc68', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
      {'reference':'perl-interpreter-debuginfo-5.32.1-473.module+el8.10.0+1616+0d20cc68', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
      {'reference':'perl-IO-1.43-473.module+el8.10.0+1616+0d20cc68', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-IO-1.43-473.module+el8.10.0+1616+0d20cc68', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-IO-Compress-2.096-1.module+el8.10.0+1616+0d20cc68', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-IO-Compress-Lzma-2.096-1.module+el8.10.0+1616+0d20cc68', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-IO-debuginfo-1.43-473.module+el8.10.0+1616+0d20cc68', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-IO-debuginfo-1.43-473.module+el8.10.0+1616+0d20cc68', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-IO-Socket-IP-0.41-2.module+el8.10.0+1616+0d20cc68', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-IO-Zlib-1.10-473.module+el8.10.0+1616+0d20cc68', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'perl-IPC-Cmd-1.04-2.module+el8.10.0+1616+0d20cc68', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'perl-IPC-Cmd-1.04-2.module+el8.6.0+878+f93dfff7', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'perl-IPC-Open3-1.21-473.module+el8.10.0+1616+0d20cc68', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-IPC-System-Simple-1.30-3.module+el8.10.0+1616+0d20cc68', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-IPC-SysV-2.09-1.module+el8.10.0+1616+0d20cc68', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-IPC-SysV-2.09-1.module+el8.10.0+1616+0d20cc68', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-IPC-SysV-debuginfo-2.09-1.module+el8.10.0+1616+0d20cc68', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-IPC-SysV-debuginfo-2.09-1.module+el8.10.0+1616+0d20cc68', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-IPC-SysV-debugsource-2.09-1.module+el8.10.0+1616+0d20cc68', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-IPC-SysV-debugsource-2.09-1.module+el8.10.0+1616+0d20cc68', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-JSON-PP-4.04-2.module+el8.10.0+1616+0d20cc68', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'perl-JSON-PP-4.04-2.module+el8.6.0+878+f93dfff7', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'perl-less-0.03-473.module+el8.10.0+1616+0d20cc68', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-lib-0.65-473.module+el8.10.0+1616+0d20cc68', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-lib-0.65-473.module+el8.10.0+1616+0d20cc68', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-libnet-3.13-1.module+el8.10.0+1616+0d20cc68', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-libnetcfg-5.32.1-473.module+el8.10.0+1616+0d20cc68', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
      {'reference':'perl-libs-5.32.1-473.module+el8.10.0+1616+0d20cc68', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
      {'reference':'perl-libs-5.32.1-473.module+el8.10.0+1616+0d20cc68', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
      {'reference':'perl-libs-debuginfo-5.32.1-473.module+el8.10.0+1616+0d20cc68', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
      {'reference':'perl-libs-debuginfo-5.32.1-473.module+el8.10.0+1616+0d20cc68', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
      {'reference':'perl-local-lib-2.000024-7.module+el8.10.0+1616+0d20cc68', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-local-lib-2.000024-7.module+el8.6.0+878+f93dfff7', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-locale-1.09-473.module+el8.10.0+1616+0d20cc68', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Locale-Maketext-1.29-440.module+el8.10.0+1616+0d20cc68', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Locale-Maketext-1.29-440.module+el8.6.0+878+f93dfff7', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Locale-Maketext-Simple-0.21-473.module+el8.10.0+1616+0d20cc68', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'perl-macros-5.32.1-473.module+el8.10.0+1616+0d20cc68', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
      {'reference':'perl-Math-BigInt-1.9998.18-1.module+el8.10.0+1616+0d20cc68', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'perl-Math-BigInt-1.9998.18-1.module+el8.6.0+878+f93dfff7', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'perl-Math-BigInt-FastCalc-0.500.900-1.module+el8.10.0+1616+0d20cc68', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Math-BigInt-FastCalc-0.500.900-1.module+el8.10.0+1616+0d20cc68', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Math-BigInt-FastCalc-0.500.900-1.module+el8.6.0+878+f93dfff7', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Math-BigInt-FastCalc-0.500.900-1.module+el8.6.0+878+f93dfff7', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Math-BigInt-FastCalc-debuginfo-0.500.900-1.module+el8.10.0+1616+0d20cc68', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Math-BigInt-FastCalc-debuginfo-0.500.900-1.module+el8.10.0+1616+0d20cc68', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Math-BigInt-FastCalc-debuginfo-0.500.900-1.module+el8.6.0+878+f93dfff7', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Math-BigInt-FastCalc-debuginfo-0.500.900-1.module+el8.6.0+878+f93dfff7', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Math-BigInt-FastCalc-debugsource-0.500.900-1.module+el8.10.0+1616+0d20cc68', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Math-BigInt-FastCalc-debugsource-0.500.900-1.module+el8.10.0+1616+0d20cc68', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Math-BigInt-FastCalc-debugsource-0.500.900-1.module+el8.6.0+878+f93dfff7', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Math-BigInt-FastCalc-debugsource-0.500.900-1.module+el8.6.0+878+f93dfff7', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Math-BigRat-0.2614-2.module+el8.10.0+1616+0d20cc68', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Math-BigRat-0.2614-2.module+el8.6.0+878+f93dfff7', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Math-BigRat-0.2614-2.module+el8.6.0+882+2fa1e48f', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Math-Complex-1.59-473.module+el8.10.0+1616+0d20cc68', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Memoize-1.03-473.module+el8.10.0+1616+0d20cc68', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-meta-notation-5.32.1-473.module+el8.10.0+1616+0d20cc68', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-MIME-Base64-3.15-1001.module+el8.10.0+1616+0d20cc68', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-MIME-Base64-3.15-1001.module+el8.10.0+1616+0d20cc68', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-MIME-Base64-3.15-1001.module+el8.6.0+878+f93dfff7', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-MIME-Base64-3.15-1001.module+el8.6.0+878+f93dfff7', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-MIME-Base64-3.15-1001.module+el8.6.0+882+2fa1e48f', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-MIME-Base64-3.15-1001.module+el8.6.0+882+2fa1e48f', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-MIME-Base64-debuginfo-3.15-1001.module+el8.10.0+1616+0d20cc68', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-MIME-Base64-debuginfo-3.15-1001.module+el8.10.0+1616+0d20cc68', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-MIME-Base64-debuginfo-3.15-1001.module+el8.6.0+878+f93dfff7', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-MIME-Base64-debuginfo-3.15-1001.module+el8.6.0+878+f93dfff7', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-MIME-Base64-debuginfo-3.15-1001.module+el8.6.0+882+2fa1e48f', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-MIME-Base64-debuginfo-3.15-1001.module+el8.6.0+882+2fa1e48f', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-MIME-Base64-debugsource-3.15-1001.module+el8.10.0+1616+0d20cc68', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-MIME-Base64-debugsource-3.15-1001.module+el8.10.0+1616+0d20cc68', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-MIME-Base64-debugsource-3.15-1001.module+el8.6.0+878+f93dfff7', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-MIME-Base64-debugsource-3.15-1001.module+el8.6.0+878+f93dfff7', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-MIME-Base64-debugsource-3.15-1001.module+el8.6.0+882+2fa1e48f', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-MIME-Base64-debugsource-3.15-1001.module+el8.6.0+882+2fa1e48f', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Module-Build-0.42.31-5.module+el8.10.0+1616+0d20cc68', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'perl-Module-CoreList-5.20211020-1.module+el8.10.0+1616+0d20cc68', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'perl-Module-CoreList-tools-5.20211020-1.module+el8.10.0+1616+0d20cc68', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'perl-Module-Load-0.36-1.module+el8.10.0+1616+0d20cc68', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'perl-Module-Load-Conditional-0.74-1.module+el8.10.0+1616+0d20cc68', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Module-Loaded-0.08-473.module+el8.10.0+1616+0d20cc68', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'perl-Module-Metadata-1.000037-1.module+el8.10.0+1616+0d20cc68', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Module-Metadata-1.000037-1.module+el8.6.0+878+f93dfff7', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-mro-1.23-473.module+el8.10.0+1616+0d20cc68', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-mro-1.23-473.module+el8.10.0+1616+0d20cc68', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-MRO-Compat-0.13-5.module+el8.10.0+1616+0d20cc68', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-MRO-Compat-0.13-5.module+el8.6.0+878+f93dfff7', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-MRO-Compat-0.13-5.module+el8.6.0+882+2fa1e48f', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-mro-debuginfo-1.23-473.module+el8.10.0+1616+0d20cc68', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-mro-debuginfo-1.23-473.module+el8.10.0+1616+0d20cc68', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-NDBM_File-1.15-473.module+el8.10.0+1616+0d20cc68', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-NDBM_File-1.15-473.module+el8.10.0+1616+0d20cc68', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-NDBM_File-debuginfo-1.15-473.module+el8.10.0+1616+0d20cc68', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-NDBM_File-debuginfo-1.15-473.module+el8.10.0+1616+0d20cc68', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Net-1.02-473.module+el8.10.0+1616+0d20cc68', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Net-Ping-2.72-473.module+el8.10.0+1616+0d20cc68', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-NEXT-0.67-473.module+el8.10.0+1616+0d20cc68', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Object-HashBase-0.009-4.module+el8.10.0+1616+0d20cc68', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Object-HashBase-tools-0.009-4.module+el8.10.0+1616+0d20cc68', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-ODBM_File-1.16-473.module+el8.10.0+1616+0d20cc68', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-ODBM_File-1.16-473.module+el8.10.0+1616+0d20cc68', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-ODBM_File-debuginfo-1.16-473.module+el8.10.0+1616+0d20cc68', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-ODBM_File-debuginfo-1.16-473.module+el8.10.0+1616+0d20cc68', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Opcode-1.48-473.module+el8.10.0+1616+0d20cc68', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Opcode-1.48-473.module+el8.10.0+1616+0d20cc68', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Opcode-debuginfo-1.48-473.module+el8.10.0+1616+0d20cc68', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Opcode-debuginfo-1.48-473.module+el8.10.0+1616+0d20cc68', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-open-1.12-473.module+el8.10.0+1616+0d20cc68', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-overload-1.31-473.module+el8.10.0+1616+0d20cc68', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-overloading-0.02-473.module+el8.10.0+1616+0d20cc68', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Package-Generator-1.106-12.module+el8.10.0+1616+0d20cc68', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Package-Generator-1.106-12.module+el8.6.0+878+f93dfff7', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Package-Generator-1.106-12.module+el8.6.0+882+2fa1e48f', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Params-Check-0.38-396.module+el8.10.0+1616+0d20cc68', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'perl-Params-Check-0.38-396.module+el8.6.0+878+f93dfff7', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'perl-Params-Check-0.38-396.module+el8.6.0+882+2fa1e48f', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'perl-Params-Util-1.102-2.module+el8.10.0+1616+0d20cc68', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Params-Util-1.102-2.module+el8.10.0+1616+0d20cc68', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Params-Util-debuginfo-1.102-2.module+el8.10.0+1616+0d20cc68', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Params-Util-debuginfo-1.102-2.module+el8.10.0+1616+0d20cc68', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Params-Util-debugsource-1.102-2.module+el8.10.0+1616+0d20cc68', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Params-Util-debugsource-1.102-2.module+el8.10.0+1616+0d20cc68', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-parent-0.238-457.module+el8.10.0+1616+0d20cc68', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'perl-PathTools-3.78-439.module+el8.10.0+1616+0d20cc68', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-PathTools-3.78-439.module+el8.10.0+1616+0d20cc68', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-PathTools-3.78-439.module+el8.6.0+878+f93dfff7', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-PathTools-3.78-439.module+el8.6.0+878+f93dfff7', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-PathTools-debuginfo-3.78-439.module+el8.10.0+1616+0d20cc68', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-PathTools-debuginfo-3.78-439.module+el8.10.0+1616+0d20cc68', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-PathTools-debuginfo-3.78-439.module+el8.6.0+878+f93dfff7', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-PathTools-debuginfo-3.78-439.module+el8.6.0+878+f93dfff7', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-PathTools-debugsource-3.78-439.module+el8.10.0+1616+0d20cc68', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-PathTools-debugsource-3.78-439.module+el8.10.0+1616+0d20cc68', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-PathTools-debugsource-3.78-439.module+el8.6.0+878+f93dfff7', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-PathTools-debugsource-3.78-439.module+el8.6.0+878+f93dfff7', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Perl-OSType-1.010-397.module+el8.10.0+1616+0d20cc68', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Perl-OSType-1.010-397.module+el8.6.0+878+f93dfff7', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Perl-OSType-1.010-397.module+el8.6.0+882+2fa1e48f', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-perlfaq-5.20210520-1.module+el8.10.0+1616+0d20cc68', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-PerlIO-via-QuotedPrint-0.09-1.module+el8.10.0+1616+0d20cc68', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-ph-5.32.1-473.module+el8.10.0+1616+0d20cc68', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-ph-5.32.1-473.module+el8.10.0+1616+0d20cc68', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Pod-Checker-1.74-1.module+el8.10.0+1616+0d20cc68', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
      {'reference':'perl-Pod-Escapes-1.07-396.module+el8.10.0+1616+0d20cc68', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'perl-Pod-Escapes-1.07-396.module+el8.6.0+878+f93dfff7', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'perl-Pod-Escapes-1.07-396.module+el8.6.0+882+2fa1e48f', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'perl-Pod-Functions-1.13-473.module+el8.10.0+1616+0d20cc68', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Pod-Html-1.25-473.module+el8.10.0+1616+0d20cc68', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Pod-Parser-1.63-1001.module+el8.10.0+1616+0d20cc68', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Pod-Parser-1.63-1001.module+el8.6.0+878+f93dfff7', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Pod-Parser-1.63-1001.module+el8.6.0+882+2fa1e48f', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Pod-Perldoc-3.28.01-443.module+el8.10.0+1616+0d20cc68', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Pod-Simple-3.42-1.module+el8.10.0+1616+0d20cc68', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'perl-Pod-Usage-2.01-1.module+el8.10.0+1616+0d20cc68', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
      {'reference':'perl-podlators-4.14-457.module+el8.10.0+1616+0d20cc68', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'perl-POSIX-1.94-473.module+el8.10.0+1616+0d20cc68', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-POSIX-1.94-473.module+el8.10.0+1616+0d20cc68', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-POSIX-debuginfo-1.94-473.module+el8.10.0+1616+0d20cc68', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-POSIX-debuginfo-1.94-473.module+el8.10.0+1616+0d20cc68', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Safe-2.41-473.module+el8.10.0+1616+0d20cc68', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Scalar-List-Utils-1.55-457.module+el8.10.0+1616+0d20cc68', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
      {'reference':'perl-Scalar-List-Utils-1.55-457.module+el8.10.0+1616+0d20cc68', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
      {'reference':'perl-Scalar-List-Utils-debuginfo-1.55-457.module+el8.10.0+1616+0d20cc68', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
      {'reference':'perl-Scalar-List-Utils-debuginfo-1.55-457.module+el8.10.0+1616+0d20cc68', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
      {'reference':'perl-Scalar-List-Utils-debugsource-1.55-457.module+el8.10.0+1616+0d20cc68', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
      {'reference':'perl-Scalar-List-Utils-debugsource-1.55-457.module+el8.10.0+1616+0d20cc68', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
      {'reference':'perl-Search-Dict-1.07-473.module+el8.10.0+1616+0d20cc68', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-SelectSaver-1.02-473.module+el8.10.0+1616+0d20cc68', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-SelfLoader-1.26-473.module+el8.10.0+1616+0d20cc68', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-sigtrap-1.09-473.module+el8.10.0+1616+0d20cc68', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Socket-2.031-1.module+el8.10.0+1616+0d20cc68', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
      {'reference':'perl-Socket-2.031-1.module+el8.10.0+1616+0d20cc68', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
      {'reference':'perl-Socket-debuginfo-2.031-1.module+el8.10.0+1616+0d20cc68', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
      {'reference':'perl-Socket-debuginfo-2.031-1.module+el8.10.0+1616+0d20cc68', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
      {'reference':'perl-Socket-debugsource-2.031-1.module+el8.10.0+1616+0d20cc68', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
      {'reference':'perl-Socket-debugsource-2.031-1.module+el8.10.0+1616+0d20cc68', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
      {'reference':'perl-Software-License-0.103014-5.module+el8.10.0+1616+0d20cc68', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Software-License-0.103014-5.module+el8.6.0+878+f93dfff7', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-sort-2.04-473.module+el8.10.0+1616+0d20cc68', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Storable-3.21-457.module+el8.10.0+1616+0d20cc68', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'perl-Storable-3.21-457.module+el8.10.0+1616+0d20cc68', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'perl-Storable-debuginfo-3.21-457.module+el8.10.0+1616+0d20cc68', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'perl-Storable-debuginfo-3.21-457.module+el8.10.0+1616+0d20cc68', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'perl-Storable-debugsource-3.21-457.module+el8.10.0+1616+0d20cc68', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'perl-Storable-debugsource-3.21-457.module+el8.10.0+1616+0d20cc68', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'perl-Sub-Exporter-0.987-17.module+el8.10.0+1616+0d20cc68', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Sub-Install-0.928-15.module+el8.10.0+1616+0d20cc68', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Sub-Install-0.928-15.module+el8.6.0+878+f93dfff7', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Sub-Install-0.928-15.module+el8.6.0+882+2fa1e48f', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-subs-1.03-473.module+el8.10.0+1616+0d20cc68', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Symbol-1.08-473.module+el8.10.0+1616+0d20cc68', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Sys-Hostname-1.23-473.module+el8.10.0+1616+0d20cc68', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Sys-Hostname-1.23-473.module+el8.10.0+1616+0d20cc68', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Sys-Hostname-debuginfo-1.23-473.module+el8.10.0+1616+0d20cc68', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Sys-Hostname-debuginfo-1.23-473.module+el8.10.0+1616+0d20cc68', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Sys-Syslog-0.36-1.module+el8.10.0+1616+0d20cc68', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Sys-Syslog-0.36-1.module+el8.10.0+1616+0d20cc68', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Sys-Syslog-0.36-1.module+el8.6.0+878+f93dfff7', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Sys-Syslog-0.36-1.module+el8.6.0+878+f93dfff7', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Sys-Syslog-debuginfo-0.36-1.module+el8.10.0+1616+0d20cc68', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Sys-Syslog-debuginfo-0.36-1.module+el8.10.0+1616+0d20cc68', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Sys-Syslog-debuginfo-0.36-1.module+el8.6.0+878+f93dfff7', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Sys-Syslog-debuginfo-0.36-1.module+el8.6.0+878+f93dfff7', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Sys-Syslog-debugsource-0.36-1.module+el8.10.0+1616+0d20cc68', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Sys-Syslog-debugsource-0.36-1.module+el8.10.0+1616+0d20cc68', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Sys-Syslog-debugsource-0.36-1.module+el8.6.0+878+f93dfff7', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Sys-Syslog-debugsource-0.36-1.module+el8.6.0+878+f93dfff7', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Term-ANSIColor-5.01-458.module+el8.10.0+1616+0d20cc68', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Term-Cap-1.17-396.module+el8.10.0+1616+0d20cc68', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Term-Cap-1.17-396.module+el8.6.0+878+f93dfff7', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Term-Cap-1.17-396.module+el8.6.0+882+2fa1e48f', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Term-Complete-1.403-473.module+el8.10.0+1616+0d20cc68', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Term-ReadLine-1.17-473.module+el8.10.0+1616+0d20cc68', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Term-Table-0.015-2.module+el8.10.0+1616+0d20cc68', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Term-Table-0.015-2.module+el8.6.0+878+f93dfff7', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Test-1.31-473.module+el8.10.0+1616+0d20cc68', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Test-Harness-3.42-2.module+el8.10.0+1616+0d20cc68', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'perl-Test-Harness-3.42-2.module+el8.6.0+878+f93dfff7', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'perl-Test-Harness-3.42-2.module+el8.6.0+882+2fa1e48f', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'perl-Test-Simple-1.302181-2.module+el8.10.0+1616+0d20cc68', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3'},
      {'reference':'perl-Text-Abbrev-1.02-473.module+el8.10.0+1616+0d20cc68', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Text-Balanced-2.04-1.module+el8.10.0+1616+0d20cc68', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Text-Diff-1.45-7.module+el8.10.0+1616+0d20cc68', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Text-Diff-1.45-7.module+el8.6.0+878+f93dfff7', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Text-Glob-0.11-5.module+el8.10.0+1616+0d20cc68', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Text-Glob-0.11-5.module+el8.6.0+878+f93dfff7', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Text-Glob-0.11-5.module+el8.6.0+882+2fa1e48f', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Text-ParseWords-3.30-396.module+el8.10.0+1616+0d20cc68', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Text-ParseWords-3.30-396.module+el8.6.0+878+f93dfff7', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Text-ParseWords-3.30-396.module+el8.6.0+882+2fa1e48f', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Text-Tabs+Wrap-2013.0523-396.module+el8.10.0+1616+0d20cc68', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Text-Tabs+Wrap-2013.0523-396.module+el8.6.0+878+f93dfff7', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Text-Tabs+Wrap-2013.0523-396.module+el8.6.0+882+2fa1e48f', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Text-Template-1.58-1.module+el8.10.0+1616+0d20cc68', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Text-Template-1.58-1.module+el8.6.0+878+f93dfff7', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Thread-3.05-473.module+el8.10.0+1616+0d20cc68', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Thread-Queue-3.14-457.module+el8.10.0+1616+0d20cc68', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Thread-Semaphore-2.13-473.module+el8.10.0+1616+0d20cc68', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-threads-2.25-457.module+el8.10.0+1616+0d20cc68', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'perl-threads-2.25-457.module+el8.10.0+1616+0d20cc68', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'perl-threads-debuginfo-2.25-457.module+el8.10.0+1616+0d20cc68', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'perl-threads-debuginfo-2.25-457.module+el8.10.0+1616+0d20cc68', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'perl-threads-debugsource-2.25-457.module+el8.10.0+1616+0d20cc68', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'perl-threads-debugsource-2.25-457.module+el8.10.0+1616+0d20cc68', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'perl-threads-shared-1.61-457.module+el8.10.0+1616+0d20cc68', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-threads-shared-1.61-457.module+el8.10.0+1616+0d20cc68', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-threads-shared-debuginfo-1.61-457.module+el8.10.0+1616+0d20cc68', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-threads-shared-debuginfo-1.61-457.module+el8.10.0+1616+0d20cc68', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-threads-shared-debugsource-1.61-457.module+el8.10.0+1616+0d20cc68', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-threads-shared-debugsource-1.61-457.module+el8.10.0+1616+0d20cc68', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Tie-4.6-473.module+el8.10.0+1616+0d20cc68', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Tie-File-1.06-473.module+el8.10.0+1616+0d20cc68', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Tie-Memoize-1.1-473.module+el8.10.0+1616+0d20cc68', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Tie-RefHash-1.39-473.module+el8.10.0+1616+0d20cc68', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Time-1.03-473.module+el8.10.0+1616+0d20cc68', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Time-HiRes-1.9764-459.module+el8.10.0+1616+0d20cc68', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
      {'reference':'perl-Time-HiRes-1.9764-459.module+el8.10.0+1616+0d20cc68', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
      {'reference':'perl-Time-HiRes-debuginfo-1.9764-459.module+el8.10.0+1616+0d20cc68', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
      {'reference':'perl-Time-HiRes-debuginfo-1.9764-459.module+el8.10.0+1616+0d20cc68', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
      {'reference':'perl-Time-HiRes-debugsource-1.9764-459.module+el8.10.0+1616+0d20cc68', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
      {'reference':'perl-Time-HiRes-debugsource-1.9764-459.module+el8.10.0+1616+0d20cc68', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
      {'reference':'perl-Time-Local-1.300-4.module+el8.10.0+1616+0d20cc68', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'perl-Time-Piece-1.3401-473.module+el8.10.0+1616+0d20cc68', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Time-Piece-1.3401-473.module+el8.10.0+1616+0d20cc68', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Time-Piece-debuginfo-1.3401-473.module+el8.10.0+1616+0d20cc68', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Time-Piece-debuginfo-1.3401-473.module+el8.10.0+1616+0d20cc68', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Unicode-Collate-1.29-1.module+el8.10.0+1616+0d20cc68', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Unicode-Collate-1.29-1.module+el8.10.0+1616+0d20cc68', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Unicode-Collate-debuginfo-1.29-1.module+el8.10.0+1616+0d20cc68', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Unicode-Collate-debuginfo-1.29-1.module+el8.10.0+1616+0d20cc68', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Unicode-Collate-debugsource-1.29-1.module+el8.10.0+1616+0d20cc68', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Unicode-Collate-debugsource-1.29-1.module+el8.10.0+1616+0d20cc68', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Unicode-Normalize-1.27-458.module+el8.10.0+1616+0d20cc68', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Unicode-Normalize-1.27-458.module+el8.10.0+1616+0d20cc68', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Unicode-Normalize-debuginfo-1.27-458.module+el8.10.0+1616+0d20cc68', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Unicode-Normalize-debuginfo-1.27-458.module+el8.10.0+1616+0d20cc68', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Unicode-Normalize-debugsource-1.27-458.module+el8.10.0+1616+0d20cc68', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Unicode-Normalize-debugsource-1.27-458.module+el8.10.0+1616+0d20cc68', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-Unicode-UCD-0.75-473.module+el8.10.0+1616+0d20cc68', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-URI-1.76-5.module+el8.10.0+1616+0d20cc68', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-URI-1.76-5.module+el8.6.0+878+f93dfff7', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-User-pwent-1.03-473.module+el8.10.0+1616+0d20cc68', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-utils-5.32.1-473.module+el8.10.0+1616+0d20cc68', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-vars-1.05-473.module+el8.10.0+1616+0d20cc68', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'perl-version-0.99.29-1.module+el8.10.0+1616+0d20cc68', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
      {'reference':'perl-version-0.99.29-1.module+el8.10.0+1616+0d20cc68', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
      {'reference':'perl-version-debuginfo-0.99.29-1.module+el8.10.0+1616+0d20cc68', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
      {'reference':'perl-version-debuginfo-0.99.29-1.module+el8.10.0+1616+0d20cc68', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
      {'reference':'perl-version-debugsource-0.99.29-1.module+el8.10.0+1616+0d20cc68', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
      {'reference':'perl-version-debugsource-0.99.29-1.module+el8.10.0+1616+0d20cc68', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
      {'reference':'perl-vmsish-1.04-473.module+el8.10.0+1616+0d20cc68', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'}
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
    if (!empty_or_null(appstream_name)) appstream = get_one_kb_item('Host/RockyLinux/appstream/' + appstream_name);
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
      var exists_check = NULL;
      var cves = NULL;
      if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
      if (!empty_or_null(package_array['release'])) _release = 'Rocky-' + package_array['release'];
      if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
      if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
      if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
      if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
      if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
      if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
      if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
      if (!empty_or_null(package_array['cves'])) cves = package_array['cves'];
      if (reference && _release && (!exists_check || rpm_exists(release:_release, rpm:exists_check))) {
        if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj, cves:cves)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'perl / perl-Algorithm-Diff / perl-Archive-Tar / perl-Archive-Zip / etc');
}
