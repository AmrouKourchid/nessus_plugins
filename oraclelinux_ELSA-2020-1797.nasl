#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2020-1797.
##

include('compat.inc');

if (description)
{
  script_id(180901);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/22");

  script_cve_id("CVE-2019-17451", "CVE-2019-1010204");

  script_name(english:"Oracle Linux 8 : binutils (ELSA-2020-1797)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2020-1797 advisory.

    [2.30-73.0.1]
    - Forward-port of Oracle patches from 2.30-68.0.2.
    - Reviewed-by: Elena Zannoni <elena.zannoni@oracle.com>

    [2.30-68.0.2]
    - Backport the non-cycle-detecting-capable deduplicating CTF linker
    - Backport a fix for an upstream hashtab crash (no upstream bug number),
      triggered by the above.
    - Fix deduplication of ambiguously-named types in CTF.
    - CTF types without names are not ambiguously-named.
    - Stop the CTF_LINK_EMPTY_CU_MAPPINGS flag crashing.
    - Only emit ambiguous types as hidden if they are named and there is already
      a type with that name.
    - Make sure completely empty dicts get their header written out properly
    - Do not fail if adding anonymous struct/union members to structs/unions that
      already contain other anonymous members at a different offset
    - Correctly look up pointers to non-root-visible structures
    - Emit error messages in dumping into the dump stream
    - Do not abort early on dump-time errors
    - Elide likely duplicates (same name, same kind) within a single TU (cross-
      TU duplicate/ambiguous-type detection works as before).
    - Fix linking of the CTF variable section
    - Fix spurious conflicts of variables (also affects the nondeduplicating linker)
    - Defend against CUs without names
    - When linking only a single input file, set the output CTF CU name to the
      name of the input
    - Support cv-qualified bitfields
    - Fix off-by-one error in SHA-1 sizing

    [2.30-73]
    - Remove bogus assertion.  (#1801879)

    [2.30-72]
    - Allow the BFD library to handle the copying of files containing secondary reloc sections.  (#1801879)

    [2.30-68.0.1]
    - Ensure 8-byte alignment for AArch64 stubs.
    - Add CTF support to OL8: CTF machinery, including libctf.so and
      libctf-nonbfd.so.  The linker does not yet deduplicate the CTF type section.
    - Backport of fix for upstream bug 23919, required by above
    - [Orabug: 30102938] [Orabug: 30102941]

    [2.30-71]
    - Fix a potential seg-fault in the BFD library when parsing pathalogical debug_info sections.  (#1779245)
    - Fix a potential memory exhaustion in the BFD library when parsing corrupt DWARF debug information.

    [2.30-70]
    - Re-enable strip merging build notes.  (#1777760)

    [2.30-69]
    - Fix linker testsuite failures triggered by annobin update.

    [2.30-68]
    - Backport H.J.Lus patch to add a workaround for the JCC Errata to the assembler.  (#1777002)

    [2.30-67]
    - Fix a buffer overrun in the note merging code.  (#1774507)

    [2.30-66]
    - Fix a seg-fault in gold when linking corrupt input files.  (#1739254)

    [2.30-65]
    - NVR bump to allow rebuild with reverted version of glibc in the buildroot.

    [2.30-64]
    - Stop note merging with no effect from creating null filled note sections.

    [2.30-63]
    - Stop objcopy from generating a exit failure status when merging corrupt notes.

    [2.30-62]
    - Fix binutils testsuite failure introduced by -60 patch.  (#1767711)

    [2.30-61]
    - Enable threading in the GOLD linker.  (#1729225)
    - Add check to readelf in order to prevent an integer overflow.

    [2.30-60]
    - Add support for SVE Vector PCS on AArch64.  (#1726637)
    - Add fixes for coverity test failures.
    - Improve objcopys ability to merge GNU build attribute notes.

    [2.30-59]
    - Stop the linker from merging groups with different settings of the SHF_EXCLUDE flag.  (#1730906)

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2020-1797.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected binutils and / or binutils-devel packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-17451");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/10/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/05/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/09/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:binutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:binutils-devel");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

var pkgs = [
    {'reference':'binutils-2.30-73.0.1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'binutils-devel-2.30-73.0.1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'binutils-devel-2.30-73.0.1.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'binutils-2.30-73.0.1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'binutils-devel-2.30-73.0.1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
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
      severity   : SECURITY_WARNING,
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
