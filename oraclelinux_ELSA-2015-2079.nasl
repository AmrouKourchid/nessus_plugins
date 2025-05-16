#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2015:2079 and 
# Oracle Linux Security Advisory ELSA-2015-2079 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(87018);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/22");

  script_cve_id(
    "CVE-2014-8484",
    "CVE-2014-8485",
    "CVE-2014-8501",
    "CVE-2014-8502",
    "CVE-2014-8503",
    "CVE-2014-8504",
    "CVE-2014-8737",
    "CVE-2014-8738"
  );
  script_xref(name:"RHSA", value:"2015:2079");

  script_name(english:"Oracle Linux 7 : binutils (ELSA-2015-2079)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 7 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2015-2079 advisory.

    [2.23.52.0.1-55]
    - Add missing delta to patch that fixes parsing corrupted archives.
      (#1162666)

    [2.23.52.0.1-54]
    - Import patch for PR 18270: Create AArch64 GOT entries for local symbols.
      (#1238783)

    [2.23.52.0.1-51]
    - Fix incorrectly generated binaries and DSOs on PPC platforms.
      (#1247126)

    [2.23.52.0.1-50]
    - Fix memory corruption parsing corrupt archives.
      (#1162666)

    [2.23.52.0.1-49]
    - Fix directory traversal vulnerability.
      (#1162655)

    [2.23.52.0.1-48]
    - Fix stack overflow in SREC parser.
      (#1162621)

    [2.23.52.0.1-47]
    - Fix stack overflow whilst parsing a corrupt iHex file.
      (#1162607)

    [2.23.52.0.1-46]
    - Fix out of bounds memory accesses when parsing corrupt PE binaries.
      (#1162594, #1162570)

    [2.23.52.0.1-45]
    - Change strings program to default to -a.  Fix problems parsing
      files containg corrupt ELF group sections.  (#1157276)

    [2.23.52.0.1-44]
    - Avoid reading beyond function boundary when disassembling.
      (#1060282)

    - For binary ouput, we don't have an ELF bfd output so can't access
      elf_elfheader.  (#1226864)

    [2.23.52.0.1-43]
    - Don't discard stap probe note sections on aarch64 (#1225091)

    [2.23.52.0.1-42]
    - Clamp maxpagesize at 1 (rather than 0) to avoid segfaults
      in the linker when passed a bogus max-page-size argument.
      (#1203449)

    [2.23.52.0.1-41]
    - Fixup bfd elf_link_add_object_symbols for ppc64 to prevent subsequent
      uninitialized accesses elsewhere. (#1172766)

    [2.23.52.0.1-40]
    - Minor testsuite adjustments for PPC changes in -38/-39.
      (#1183838)
      Fix md_assemble for PPC to handle arithmetic involving the TOC
      better.  (#1183838)

    [2.23.52.0.1-39]
    - Fix ppc64: segv in libbfd (#1172766).

    [2.23.52.0.1-38]
    - Unconditionally apply ppc64le patches (#1183838).

    [2.23.52.0.1-37]
    - Andreas's backport of z13 and dependent fixes for s390,
      including tesetcase fix from Apr 27, 2015.  (#1182153)

    [2.23.52.0.1-35]
    - Fixup testsuite for AArch64 (#1182111)
    - Add support for @localentry for LE PPC64 (#1194164)

    [2.23.52.0.1-34]
    - Do not install windmc(1) man page (#850832)

    [2.23.52.0.1-33]
    - Don't replace R_390_TLS_LE{32,64} with R_390_TLS_TPOFF for PIE
      (#872148)
    - Enable relro by default for arm and aarch64 (#1203449)
    - Backport 3 RELRO improvements for ppc64/ppc64le from upstream
      (#1175624)

    [2.23.52.0.1-31]
    - Backport upstream RELRO fixes. (#1200138)

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2015-2079.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected binutils and / or binutils-devel packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-8504");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/12/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/11/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:binutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:binutils-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2015-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

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
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 7', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);

var pkgs = [
    {'reference':'binutils-devel-2.23.52.0.1-55.el7', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'binutils-2.23.52.0.1-55.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'binutils-devel-2.23.52.0.1-55.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE}
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
  if (!empty_or_null(package_array['release'])) _release = 'EL' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (reference && _release) {
    if (exists_check) {
        if (rpm_exists(release:_release, rpm:exists_check) && rpm_check(release:_release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
    } else {
        if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
    }
  }
}

if (flag)
{
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'binutils / binutils-devel');
}
