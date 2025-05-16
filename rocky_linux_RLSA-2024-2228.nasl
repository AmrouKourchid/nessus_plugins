#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# Rocky Linux Security Advisory RLSA-2024:2228.
##

include('compat.inc');

if (description)
{
  script_id(235507);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/07");

  script_cve_id("CVE-2023-47038");
  script_xref(name:"RLSA", value:"2024:2228");

  script_name(english:"RockyLinux 9 : perl (RLSA-2024:2228)");

  script_set_attribute(attribute:"synopsis", value:
"The remote RockyLinux host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote RockyLinux 9 host has packages installed that are affected by a vulnerability as referenced in the
RLSA-2024:2228 advisory.

    * perl: Write past buffer end via illegal user-defined Unicode property (CVE-2023-47038)

Tenable has extracted the preceding description block directly from the RockyLinux security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.rockylinux.org/RLSA-2024:2228");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Attribute-Handlers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-AutoLoader");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-AutoSplit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-B");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-B-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Benchmark");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Class-Struct");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Config-Extensions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-DBM_Filter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Devel-Peek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Devel-Peek-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Devel-SelfStubber");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-DirHandle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Dumpvalue");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-DynaLoader");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-English");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Errno");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-ExtUtils-Constant");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-ExtUtils-Embed");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-ExtUtils-Miniperl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Fcntl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Fcntl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-File-Basename");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-File-Compare");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-File-Copy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-File-DosGlob");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-File-DosGlob-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-File-Find");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-File-stat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-FileCache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-FileHandle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-FindBin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-GDBM_File");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-GDBM_File-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Getopt-Std");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Hash-Util");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Hash-Util-FieldHash");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Hash-Util-FieldHash-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Hash-Util-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-I18N-Collate");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-I18N-LangTags");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-I18N-Langinfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-I18N-Langinfo-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-IO");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-IO-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-IPC-Open3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Locale-Maketext-Simple");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Math-Complex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Memoize");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Module-Loaded");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-NDBM_File");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-NDBM_File-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-NEXT");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Net");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-ODBM_File");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-ODBM_File-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Opcode");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Opcode-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-POSIX");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-POSIX-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Pod-Functions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Pod-Html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Safe");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Search-Dict");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-SelectSaver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-SelfLoader");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Symbol");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Sys-Hostname");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Sys-Hostname-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Term-Complete");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Term-ReadLine");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Text-Abbrev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Thread");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Thread-Semaphore");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Tie");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Tie-File");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Tie-Memoize");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Time");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Time-Piece");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Time-Piece-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Unicode-UCD");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-User-pwent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-autouse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-blib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-debugger");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-deprecate");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-diagnostics");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-encoding-warnings");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-fields");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-filetest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-if");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-interpreter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-interpreter-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-less");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-libnetcfg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-libs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-locale");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-macros");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-meta-notation");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-mro");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-mro-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-open");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-overload");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-overloading");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-ph");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-sigtrap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-sort");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-subs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-vars");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-vmsish");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:rocky:linux:9");
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
if (! preg(pattern:"^9([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'RockyLinux 9.x', 'Rocky Linux ' + os_ver);

if (!get_kb_item('Host/RockyLinux/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('aarch64' >!< cpu && 'ppc' >!< cpu && 's390' >!< cpu && 'x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Rocky Linux', cpu);

var pkgs = [
    {'reference':'perl-5.32.1-481.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
    {'reference':'perl-5.32.1-481.el9', 'cpu':'ppc64le', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
    {'reference':'perl-5.32.1-481.el9', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
    {'reference':'perl-5.32.1-481.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
    {'reference':'perl-Attribute-Handlers-1.01-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-AutoLoader-5.74-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-AutoSplit-5.74-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-autouse-1.11-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-B-1.80-481.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-B-1.80-481.el9', 'cpu':'ppc64le', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-B-1.80-481.el9', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-B-1.80-481.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-B-debuginfo-1.80-481.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-B-debuginfo-1.80-481.el9', 'cpu':'ppc64le', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-B-debuginfo-1.80-481.el9', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-B-debuginfo-1.80-481.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-base-2.27-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-Benchmark-1.23-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-blib-1.07-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-Class-Struct-0.66-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-Config-Extensions-0.03-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-DBM_Filter-0.06-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-debugger-1.56-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-debuginfo-5.32.1-481.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
    {'reference':'perl-debuginfo-5.32.1-481.el9', 'cpu':'ppc64le', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
    {'reference':'perl-debuginfo-5.32.1-481.el9', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
    {'reference':'perl-debuginfo-5.32.1-481.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
    {'reference':'perl-debugsource-5.32.1-481.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
    {'reference':'perl-debugsource-5.32.1-481.el9', 'cpu':'ppc64le', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
    {'reference':'perl-debugsource-5.32.1-481.el9', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
    {'reference':'perl-debugsource-5.32.1-481.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
    {'reference':'perl-deprecate-0.04-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-devel-5.32.1-481.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
    {'reference':'perl-devel-5.32.1-481.el9', 'cpu':'i686', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
    {'reference':'perl-devel-5.32.1-481.el9', 'cpu':'ppc64le', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
    {'reference':'perl-devel-5.32.1-481.el9', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
    {'reference':'perl-devel-5.32.1-481.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
    {'reference':'perl-Devel-Peek-1.28-481.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-Devel-Peek-1.28-481.el9', 'cpu':'ppc64le', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-Devel-Peek-1.28-481.el9', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-Devel-Peek-1.28-481.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-Devel-Peek-debuginfo-1.28-481.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-Devel-Peek-debuginfo-1.28-481.el9', 'cpu':'ppc64le', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-Devel-Peek-debuginfo-1.28-481.el9', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-Devel-Peek-debuginfo-1.28-481.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-Devel-SelfStubber-1.06-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-diagnostics-1.37-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-DirHandle-1.05-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-doc-5.32.1-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-Dumpvalue-2.27-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-DynaLoader-1.47-481.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-DynaLoader-1.47-481.el9', 'cpu':'ppc64le', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-DynaLoader-1.47-481.el9', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-DynaLoader-1.47-481.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-encoding-warnings-0.13-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-English-1.11-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-Errno-1.30-481.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-Errno-1.30-481.el9', 'cpu':'ppc64le', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-Errno-1.30-481.el9', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-Errno-1.30-481.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-ExtUtils-Constant-0.25-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-ExtUtils-Embed-1.35-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-ExtUtils-Miniperl-1.09-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-Fcntl-1.13-481.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-Fcntl-1.13-481.el9', 'cpu':'ppc64le', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-Fcntl-1.13-481.el9', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-Fcntl-1.13-481.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-Fcntl-debuginfo-1.13-481.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-Fcntl-debuginfo-1.13-481.el9', 'cpu':'ppc64le', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-Fcntl-debuginfo-1.13-481.el9', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-Fcntl-debuginfo-1.13-481.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-fields-2.27-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-File-Basename-2.85-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-File-Compare-1.100.600-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-File-Copy-2.34-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-File-DosGlob-1.12-481.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-File-DosGlob-1.12-481.el9', 'cpu':'ppc64le', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-File-DosGlob-1.12-481.el9', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-File-DosGlob-1.12-481.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-File-DosGlob-debuginfo-1.12-481.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-File-DosGlob-debuginfo-1.12-481.el9', 'cpu':'ppc64le', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-File-DosGlob-debuginfo-1.12-481.el9', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-File-DosGlob-debuginfo-1.12-481.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-File-Find-1.37-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-File-stat-1.09-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-FileCache-1.10-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-FileHandle-2.03-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-filetest-1.03-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-FindBin-1.51-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-GDBM_File-1.18-481.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-GDBM_File-1.18-481.el9', 'cpu':'ppc64le', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-GDBM_File-1.18-481.el9', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-GDBM_File-1.18-481.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-GDBM_File-debuginfo-1.18-481.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-GDBM_File-debuginfo-1.18-481.el9', 'cpu':'ppc64le', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-GDBM_File-debuginfo-1.18-481.el9', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-GDBM_File-debuginfo-1.18-481.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-Getopt-Std-1.12-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-Hash-Util-0.23-481.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-Hash-Util-0.23-481.el9', 'cpu':'ppc64le', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-Hash-Util-0.23-481.el9', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-Hash-Util-0.23-481.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-Hash-Util-debuginfo-0.23-481.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-Hash-Util-debuginfo-0.23-481.el9', 'cpu':'ppc64le', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-Hash-Util-debuginfo-0.23-481.el9', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-Hash-Util-debuginfo-0.23-481.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-Hash-Util-FieldHash-1.20-481.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-Hash-Util-FieldHash-1.20-481.el9', 'cpu':'ppc64le', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-Hash-Util-FieldHash-1.20-481.el9', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-Hash-Util-FieldHash-1.20-481.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-Hash-Util-FieldHash-debuginfo-1.20-481.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-Hash-Util-FieldHash-debuginfo-1.20-481.el9', 'cpu':'ppc64le', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-Hash-Util-FieldHash-debuginfo-1.20-481.el9', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-Hash-Util-FieldHash-debuginfo-1.20-481.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-I18N-Collate-1.02-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-I18N-Langinfo-0.19-481.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-I18N-Langinfo-0.19-481.el9', 'cpu':'ppc64le', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-I18N-Langinfo-0.19-481.el9', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-I18N-Langinfo-0.19-481.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-I18N-Langinfo-debuginfo-0.19-481.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-I18N-Langinfo-debuginfo-0.19-481.el9', 'cpu':'ppc64le', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-I18N-Langinfo-debuginfo-0.19-481.el9', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-I18N-Langinfo-debuginfo-0.19-481.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-I18N-LangTags-0.44-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-if-0.60.800-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-interpreter-5.32.1-481.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
    {'reference':'perl-interpreter-5.32.1-481.el9', 'cpu':'ppc64le', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
    {'reference':'perl-interpreter-5.32.1-481.el9', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
    {'reference':'perl-interpreter-5.32.1-481.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
    {'reference':'perl-interpreter-debuginfo-5.32.1-481.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
    {'reference':'perl-interpreter-debuginfo-5.32.1-481.el9', 'cpu':'ppc64le', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
    {'reference':'perl-interpreter-debuginfo-5.32.1-481.el9', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
    {'reference':'perl-interpreter-debuginfo-5.32.1-481.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
    {'reference':'perl-IO-1.43-481.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-IO-1.43-481.el9', 'cpu':'ppc64le', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-IO-1.43-481.el9', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-IO-1.43-481.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-IO-debuginfo-1.43-481.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-IO-debuginfo-1.43-481.el9', 'cpu':'ppc64le', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-IO-debuginfo-1.43-481.el9', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-IO-debuginfo-1.43-481.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-IPC-Open3-1.21-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-less-0.03-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-lib-0.65-481.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-lib-0.65-481.el9', 'cpu':'ppc64le', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-lib-0.65-481.el9', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-lib-0.65-481.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-libnetcfg-5.32.1-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
    {'reference':'perl-libs-5.32.1-481.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
    {'reference':'perl-libs-5.32.1-481.el9', 'cpu':'i686', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
    {'reference':'perl-libs-5.32.1-481.el9', 'cpu':'ppc64le', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
    {'reference':'perl-libs-5.32.1-481.el9', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
    {'reference':'perl-libs-5.32.1-481.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
    {'reference':'perl-libs-debuginfo-5.32.1-481.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
    {'reference':'perl-libs-debuginfo-5.32.1-481.el9', 'cpu':'ppc64le', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
    {'reference':'perl-libs-debuginfo-5.32.1-481.el9', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
    {'reference':'perl-libs-debuginfo-5.32.1-481.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
    {'reference':'perl-locale-1.09-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-Locale-Maketext-Simple-0.21-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'perl-macros-5.32.1-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
    {'reference':'perl-Math-Complex-1.59-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-Memoize-1.03-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-meta-notation-5.32.1-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-Module-Loaded-0.08-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'perl-mro-1.23-481.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-mro-1.23-481.el9', 'cpu':'ppc64le', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-mro-1.23-481.el9', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-mro-1.23-481.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-mro-debuginfo-1.23-481.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-mro-debuginfo-1.23-481.el9', 'cpu':'ppc64le', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-mro-debuginfo-1.23-481.el9', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-mro-debuginfo-1.23-481.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-NDBM_File-1.15-481.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-NDBM_File-1.15-481.el9', 'cpu':'ppc64le', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-NDBM_File-1.15-481.el9', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-NDBM_File-1.15-481.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-NDBM_File-debuginfo-1.15-481.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-NDBM_File-debuginfo-1.15-481.el9', 'cpu':'ppc64le', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-NDBM_File-debuginfo-1.15-481.el9', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-NDBM_File-debuginfo-1.15-481.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-Net-1.02-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-NEXT-0.67-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-ODBM_File-1.16-481.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-ODBM_File-1.16-481.el9', 'cpu':'ppc64le', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-ODBM_File-1.16-481.el9', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-ODBM_File-1.16-481.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-ODBM_File-debuginfo-1.16-481.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-ODBM_File-debuginfo-1.16-481.el9', 'cpu':'ppc64le', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-ODBM_File-debuginfo-1.16-481.el9', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-ODBM_File-debuginfo-1.16-481.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-Opcode-1.48-481.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-Opcode-1.48-481.el9', 'cpu':'ppc64le', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-Opcode-1.48-481.el9', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-Opcode-1.48-481.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-Opcode-debuginfo-1.48-481.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-Opcode-debuginfo-1.48-481.el9', 'cpu':'ppc64le', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-Opcode-debuginfo-1.48-481.el9', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-Opcode-debuginfo-1.48-481.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-open-1.12-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-overload-1.31-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-overloading-0.02-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-ph-5.32.1-481.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-ph-5.32.1-481.el9', 'cpu':'ppc64le', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-ph-5.32.1-481.el9', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-ph-5.32.1-481.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-Pod-Functions-1.13-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-Pod-Html-1.25-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-POSIX-1.94-481.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-POSIX-1.94-481.el9', 'cpu':'ppc64le', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-POSIX-1.94-481.el9', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-POSIX-1.94-481.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-POSIX-debuginfo-1.94-481.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-POSIX-debuginfo-1.94-481.el9', 'cpu':'ppc64le', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-POSIX-debuginfo-1.94-481.el9', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-POSIX-debuginfo-1.94-481.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-Safe-2.41-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-Search-Dict-1.07-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-SelectSaver-1.02-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-SelfLoader-1.26-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-sigtrap-1.09-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-sort-2.04-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-subs-1.03-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-Symbol-1.08-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-Sys-Hostname-1.23-481.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-Sys-Hostname-1.23-481.el9', 'cpu':'ppc64le', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-Sys-Hostname-1.23-481.el9', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-Sys-Hostname-1.23-481.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-Sys-Hostname-debuginfo-1.23-481.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-Sys-Hostname-debuginfo-1.23-481.el9', 'cpu':'ppc64le', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-Sys-Hostname-debuginfo-1.23-481.el9', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-Sys-Hostname-debuginfo-1.23-481.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-Term-Complete-1.403-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-Term-ReadLine-1.17-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-Test-1.31-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-Text-Abbrev-1.02-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-Thread-3.05-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-Thread-Semaphore-2.13-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-Tie-4.6-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-Tie-File-1.06-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-Tie-Memoize-1.1-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-Time-1.03-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-Time-Piece-1.3401-481.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-Time-Piece-1.3401-481.el9', 'cpu':'ppc64le', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-Time-Piece-1.3401-481.el9', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-Time-Piece-1.3401-481.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-Time-Piece-debuginfo-1.3401-481.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-Time-Piece-debuginfo-1.3401-481.el9', 'cpu':'ppc64le', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-Time-Piece-debuginfo-1.3401-481.el9', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-Time-Piece-debuginfo-1.3401-481.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-Unicode-UCD-0.75-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-User-pwent-1.03-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-utils-5.32.1-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-vars-1.05-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'perl-vmsish-1.04-481.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'}
];

var flag = 0;
foreach var package_array ( pkgs ) {
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'perl / perl-Attribute-Handlers / perl-AutoLoader / perl-AutoSplit / etc');
}
