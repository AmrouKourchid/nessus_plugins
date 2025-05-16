#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# Rocky Linux Security Advisory RLSA-2021:4743.
##

include('compat.inc');

if (description)
{
  script_id(184843);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/07");

  script_cve_id("CVE-2021-42574");
  script_xref(name:"RLSA", value:"2021:4743");

  script_name(english:"Rocky Linux 8 : llvm-toolset:rhel8 (RLSA-2021:4743)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Rocky Linux host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Rocky Linux 8 host has packages installed that are affected by a vulnerability as referenced in the
RLSA-2021:4743 advisory.

  - ** DISPUTED ** An issue was discovered in the Bidirectional Algorithm in the Unicode Specification through
    14.0. It permits the visual reordering of characters via control sequences, which can be used to craft
    source code that renders different logic than the logical ordering of tokens ingested by compilers and
    interpreters. Adversaries can leverage this to encode source code for compilers accepting Unicode such
    that targeted vulnerabilities are introduced invisibly to human reviewers. NOTE: the Unicode Consortium
    offers the following alternative approach to presenting this concern. An issue is noted in the nature of
    international text that can affect applications that implement support for The Unicode Standard and the
    Unicode Bidirectional Algorithm (all versions). Due to text display behavior when text includes left-to-
    right and right-to-left characters, the visual order of tokens may be different from their logical order.
    Additionally, control characters needed to fully support the requirements of bidirectional text can
    further obfuscate the logical order of tokens. Unless mitigated, an adversary could craft source code such
    that the ordering of tokens perceived by human reviewers does not match what will be processed by a
    compiler/interpreter/etc. The Unicode Consortium has documented this class of vulnerability in its
    document, Unicode Technical Report #36, Unicode Security Considerations. The Unicode Consortium also
    provides guidance on mitigations for this class of issues in Unicode Technical Standard #39, Unicode
    Security Mechanisms, and in Unicode Standard Annex #31, Unicode Identifier and Pattern Syntax. Also, the
    BIDI specification allows applications to tailor the implementation in ways that can mitigate misleading
    visual reordering in program text; see HL4 in Unicode Standard Annex #9, Unicode Bidirectional Algorithm.
    (CVE-2021-42574)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.rockylinux.org/RLSA-2021:4743");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2005819");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-42574");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/11/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/11/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:clang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:clang-analyzer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:clang-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:clang-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:clang-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:clang-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:clang-libs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:clang-resource-filesystem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:clang-tools-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:clang-tools-extra-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:compiler-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:compiler-rt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:compiler-rt-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:git-clang-format");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libomp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libomp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libomp-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libomp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libomp-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libomp-test-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:lld");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:lld-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:lld-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:lld-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:lld-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:lld-libs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:lld-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:lld-test-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:lldb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:lldb-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:lldb-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:lldb-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:llvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:llvm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:llvm-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:llvm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:llvm-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:llvm-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:llvm-googletest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:llvm-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:llvm-libs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:llvm-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:llvm-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:llvm-test-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:llvm-toolset");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python3-clang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python3-lit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python3-lldb");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:rocky:linux:8");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Rocky Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Rocky Linux 8.x', 'Rocky Linux ' + os_ver);

if (!get_kb_item('Host/RockyLinux/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Rocky Linux', cpu);

var pkgs = [
    {'reference':'clang-12.0.1-4.module+el8.5.0+715+58f51d49', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'clang-12.0.1-4.module+el8.5.0+715+58f51d49', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'clang-12.0.1-4.module+el8.5.0+715+58f51d49', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'clang-analyzer-12.0.1-4.module+el8.5.0+715+58f51d49', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'clang-debuginfo-12.0.1-4.module+el8.5.0+715+58f51d49', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'clang-debuginfo-12.0.1-4.module+el8.5.0+715+58f51d49', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'clang-debuginfo-12.0.1-4.module+el8.5.0+715+58f51d49', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'clang-debugsource-12.0.1-4.module+el8.5.0+715+58f51d49', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'clang-debugsource-12.0.1-4.module+el8.5.0+715+58f51d49', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'clang-debugsource-12.0.1-4.module+el8.5.0+715+58f51d49', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'clang-devel-12.0.1-4.module+el8.5.0+715+58f51d49', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'clang-devel-12.0.1-4.module+el8.5.0+715+58f51d49', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'clang-devel-12.0.1-4.module+el8.5.0+715+58f51d49', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'clang-libs-12.0.1-4.module+el8.5.0+715+58f51d49', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'clang-libs-12.0.1-4.module+el8.5.0+715+58f51d49', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'clang-libs-12.0.1-4.module+el8.5.0+715+58f51d49', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'clang-libs-debuginfo-12.0.1-4.module+el8.5.0+715+58f51d49', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'clang-libs-debuginfo-12.0.1-4.module+el8.5.0+715+58f51d49', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'clang-libs-debuginfo-12.0.1-4.module+el8.5.0+715+58f51d49', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'clang-resource-filesystem-12.0.1-4.module+el8.5.0+715+58f51d49', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'clang-resource-filesystem-12.0.1-4.module+el8.5.0+715+58f51d49', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'clang-resource-filesystem-12.0.1-4.module+el8.5.0+715+58f51d49', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'clang-tools-extra-12.0.1-4.module+el8.5.0+715+58f51d49', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'clang-tools-extra-12.0.1-4.module+el8.5.0+715+58f51d49', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'clang-tools-extra-12.0.1-4.module+el8.5.0+715+58f51d49', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'clang-tools-extra-debuginfo-12.0.1-4.module+el8.5.0+715+58f51d49', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'clang-tools-extra-debuginfo-12.0.1-4.module+el8.5.0+715+58f51d49', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'clang-tools-extra-debuginfo-12.0.1-4.module+el8.5.0+715+58f51d49', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'compiler-rt-12.0.1-1.module+el8.5.0+692+8756646f', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'compiler-rt-12.0.1-1.module+el8.5.0+692+8756646f', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'compiler-rt-12.0.1-1.module+el8.5.0+692+8756646f', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'compiler-rt-debuginfo-12.0.1-1.module+el8.5.0+692+8756646f', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'compiler-rt-debuginfo-12.0.1-1.module+el8.5.0+692+8756646f', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'compiler-rt-debuginfo-12.0.1-1.module+el8.5.0+692+8756646f', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'compiler-rt-debugsource-12.0.1-1.module+el8.5.0+692+8756646f', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'compiler-rt-debugsource-12.0.1-1.module+el8.5.0+692+8756646f', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'compiler-rt-debugsource-12.0.1-1.module+el8.5.0+692+8756646f', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'git-clang-format-12.0.1-4.module+el8.5.0+715+58f51d49', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'git-clang-format-12.0.1-4.module+el8.5.0+715+58f51d49', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'git-clang-format-12.0.1-4.module+el8.5.0+715+58f51d49', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libomp-12.0.1-1.module+el8.5.0+692+8756646f', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libomp-12.0.1-1.module+el8.5.0+692+8756646f', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libomp-12.0.1-1.module+el8.5.0+692+8756646f', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libomp-debuginfo-12.0.1-1.module+el8.5.0+692+8756646f', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libomp-debuginfo-12.0.1-1.module+el8.5.0+692+8756646f', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libomp-debuginfo-12.0.1-1.module+el8.5.0+692+8756646f', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libomp-debugsource-12.0.1-1.module+el8.5.0+692+8756646f', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libomp-debugsource-12.0.1-1.module+el8.5.0+692+8756646f', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libomp-debugsource-12.0.1-1.module+el8.5.0+692+8756646f', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libomp-devel-12.0.1-1.module+el8.5.0+692+8756646f', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libomp-devel-12.0.1-1.module+el8.5.0+692+8756646f', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libomp-devel-12.0.1-1.module+el8.5.0+692+8756646f', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libomp-test-12.0.1-1.module+el8.5.0+692+8756646f', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libomp-test-12.0.1-1.module+el8.5.0+692+8756646f', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libomp-test-12.0.1-1.module+el8.5.0+692+8756646f', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libomp-test-debuginfo-12.0.1-1.module+el8.5.0+692+8756646f', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libomp-test-debuginfo-12.0.1-1.module+el8.5.0+692+8756646f', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libomp-test-debuginfo-12.0.1-1.module+el8.5.0+692+8756646f', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'lld-12.0.1-1.module+el8.5.0+692+8756646f', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'lld-12.0.1-1.module+el8.5.0+692+8756646f', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'lld-12.0.1-1.module+el8.5.0+692+8756646f', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'lld-debuginfo-12.0.1-1.module+el8.5.0+692+8756646f', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'lld-debuginfo-12.0.1-1.module+el8.5.0+692+8756646f', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'lld-debuginfo-12.0.1-1.module+el8.5.0+692+8756646f', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'lld-debugsource-12.0.1-1.module+el8.5.0+692+8756646f', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'lld-debugsource-12.0.1-1.module+el8.5.0+692+8756646f', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'lld-debugsource-12.0.1-1.module+el8.5.0+692+8756646f', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'lld-devel-12.0.1-1.module+el8.5.0+692+8756646f', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'lld-devel-12.0.1-1.module+el8.5.0+692+8756646f', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'lld-devel-12.0.1-1.module+el8.5.0+692+8756646f', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'lld-libs-12.0.1-1.module+el8.5.0+692+8756646f', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'lld-libs-12.0.1-1.module+el8.5.0+692+8756646f', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'lld-libs-12.0.1-1.module+el8.5.0+692+8756646f', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'lld-libs-debuginfo-12.0.1-1.module+el8.5.0+692+8756646f', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'lld-libs-debuginfo-12.0.1-1.module+el8.5.0+692+8756646f', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'lld-libs-debuginfo-12.0.1-1.module+el8.5.0+692+8756646f', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'lld-test-12.0.1-1.module+el8.5.0+692+8756646f', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'lld-test-12.0.1-1.module+el8.5.0+692+8756646f', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'lld-test-12.0.1-1.module+el8.5.0+692+8756646f', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'lld-test-debuginfo-12.0.1-1.module+el8.5.0+692+8756646f', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'lld-test-debuginfo-12.0.1-1.module+el8.5.0+692+8756646f', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'lld-test-debuginfo-12.0.1-1.module+el8.5.0+692+8756646f', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'lldb-12.0.1-1.module+el8.5.0+692+8756646f', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'lldb-12.0.1-1.module+el8.5.0+692+8756646f', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'lldb-12.0.1-1.module+el8.5.0+692+8756646f', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'lldb-debuginfo-12.0.1-1.module+el8.5.0+692+8756646f', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'lldb-debuginfo-12.0.1-1.module+el8.5.0+692+8756646f', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'lldb-debuginfo-12.0.1-1.module+el8.5.0+692+8756646f', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'lldb-debugsource-12.0.1-1.module+el8.5.0+692+8756646f', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'lldb-debugsource-12.0.1-1.module+el8.5.0+692+8756646f', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'lldb-debugsource-12.0.1-1.module+el8.5.0+692+8756646f', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'lldb-devel-12.0.1-1.module+el8.5.0+692+8756646f', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'lldb-devel-12.0.1-1.module+el8.5.0+692+8756646f', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'lldb-devel-12.0.1-1.module+el8.5.0+692+8756646f', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'llvm-12.0.1-2.module+el8.5.0+692+8756646f', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'llvm-12.0.1-2.module+el8.5.0+692+8756646f', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'llvm-12.0.1-2.module+el8.5.0+692+8756646f', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'llvm-debuginfo-12.0.1-2.module+el8.5.0+692+8756646f', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'llvm-debuginfo-12.0.1-2.module+el8.5.0+692+8756646f', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'llvm-debuginfo-12.0.1-2.module+el8.5.0+692+8756646f', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'llvm-debugsource-12.0.1-2.module+el8.5.0+692+8756646f', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'llvm-debugsource-12.0.1-2.module+el8.5.0+692+8756646f', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'llvm-debugsource-12.0.1-2.module+el8.5.0+692+8756646f', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'llvm-devel-12.0.1-2.module+el8.5.0+692+8756646f', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'llvm-devel-12.0.1-2.module+el8.5.0+692+8756646f', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'llvm-devel-12.0.1-2.module+el8.5.0+692+8756646f', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'llvm-devel-debuginfo-12.0.1-2.module+el8.5.0+692+8756646f', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'llvm-devel-debuginfo-12.0.1-2.module+el8.5.0+692+8756646f', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'llvm-devel-debuginfo-12.0.1-2.module+el8.5.0+692+8756646f', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'llvm-doc-12.0.1-2.module+el8.5.0+692+8756646f', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'llvm-googletest-12.0.1-2.module+el8.5.0+692+8756646f', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'llvm-googletest-12.0.1-2.module+el8.5.0+692+8756646f', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'llvm-googletest-12.0.1-2.module+el8.5.0+692+8756646f', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'llvm-libs-12.0.1-2.module+el8.5.0+692+8756646f', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'llvm-libs-12.0.1-2.module+el8.5.0+692+8756646f', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'llvm-libs-12.0.1-2.module+el8.5.0+692+8756646f', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'llvm-libs-debuginfo-12.0.1-2.module+el8.5.0+692+8756646f', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'llvm-libs-debuginfo-12.0.1-2.module+el8.5.0+692+8756646f', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'llvm-libs-debuginfo-12.0.1-2.module+el8.5.0+692+8756646f', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'llvm-static-12.0.1-2.module+el8.5.0+692+8756646f', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'llvm-static-12.0.1-2.module+el8.5.0+692+8756646f', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'llvm-static-12.0.1-2.module+el8.5.0+692+8756646f', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'llvm-test-12.0.1-2.module+el8.5.0+692+8756646f', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'llvm-test-12.0.1-2.module+el8.5.0+692+8756646f', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'llvm-test-12.0.1-2.module+el8.5.0+692+8756646f', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'llvm-test-debuginfo-12.0.1-2.module+el8.5.0+692+8756646f', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'llvm-test-debuginfo-12.0.1-2.module+el8.5.0+692+8756646f', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'llvm-test-debuginfo-12.0.1-2.module+el8.5.0+692+8756646f', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'llvm-toolset-12.0.1-1.module+el8.5.0+692+8756646f', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'llvm-toolset-12.0.1-1.module+el8.5.0+692+8756646f', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'llvm-toolset-12.0.1-1.module+el8.5.0+692+8756646f', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-clang-12.0.1-4.module+el8.5.0+715+58f51d49', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-clang-12.0.1-4.module+el8.5.0+715+58f51d49', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-clang-12.0.1-4.module+el8.5.0+715+58f51d49', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-lit-12.0.1-1.module+el8.5.0+692+8756646f', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-lldb-12.0.1-1.module+el8.5.0+692+8756646f', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-lldb-12.0.1-1.module+el8.5.0+692+8756646f', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-lldb-12.0.1-1.module+el8.5.0+692+8756646f', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
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
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = 'Rocky-' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (reference && _release && (!exists_check || rpm_exists(release:_release, rpm:exists_check))) {
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'clang / clang-analyzer / clang-debuginfo / clang-debugsource / etc');
}
