#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2024:2590-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(203009);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/23");

  script_cve_id(
    "CVE-2024-21131",
    "CVE-2024-21138",
    "CVE-2024-21140",
    "CVE-2024-21144",
    "CVE-2024-21145",
    "CVE-2024-21147"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2024:2590-1");

  script_name(english:"SUSE SLES12 Security Update : java-11-openjdk (SUSE-SU-2024:2590-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES12 / SLES_SAP12 host has packages installed that are affected by multiple vulnerabilities as
referenced in the SUSE-SU-2024:2590-1 advisory.

    Updated to version 11.0.24+8 (July 2024 CPU):

    - CVE-2024-21131: Fixed a potential UTF8 size overflow (bsc#1228046).
    - CVE-2024-21138: Fixed an infinite loop due to excessive symbol
      length (bsc#1228047).
    - CVE-2024-21140: Fixed a pre-loop limit overflow in Range Check
      Elimination (bsc#1228048).
    - CVE-2024-21147: Fixed an out-of-bounds access in 2D image handling
      (bsc#1228052).
    - CVE-2024-21145: Fixed an index overflow in RangeCheckElimination
      (bsc#1228051).
    - CVE-2024-21144: Fixed an excessive loading time in Pack200 due to
      improper header validation (bsc#1228050).

Tenable has extracted the preceding description block directly from the SUSE security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227298");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228046");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228047");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228048");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228050");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228051");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228052");
  # https://lists.suse.com/pipermail/sle-security-updates/2024-July/019007.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9071c88e");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-21131");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-21138");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-21140");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-21144");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-21145");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-21147");
  script_set_attribute(attribute:"solution", value:
"Update the affected java-11-openjdk, java-11-openjdk-demo, java-11-openjdk-devel and / or java-11-openjdk-headless
packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-21147");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/07/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/07/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/07/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-11-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-11-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-11-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-11-openjdk-headless");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item("Host/SuSE/release");
if (isnull(os_release) || os_release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)(?:_SAP)?\d+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLES12|SLES_SAP12)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES12 / SLES_SAP12', 'SUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLES12" && (! preg(pattern:"^(5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES12 SP5", os_ver + " SP" + service_pack);
if (os_ver == "SLES_SAP12" && (! preg(pattern:"^(5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES_SAP12 SP5", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'java-11-openjdk-11.0.24.0-3.78.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'java-11-openjdk-demo-11.0.24.0-3.78.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'java-11-openjdk-devel-11.0.24.0-3.78.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'java-11-openjdk-headless-11.0.24.0-3.78.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'java-11-openjdk-11.0.24.0-3.78.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'java-11-openjdk-demo-11.0.24.0-3.78.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'java-11-openjdk-devel-11.0.24.0-3.78.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'java-11-openjdk-headless-11.0.24.0-3.78.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']}
];

var ltss_caveat_required = FALSE;
var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var exists_check = NULL;
  var rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && _release) {
    if (exists_check) {
      var check_flag = 0;
      foreach var check (exists_check) {
        if (!rpm_exists(release:_release, rpm:check)) continue;
        check_flag++;
      }
      if (!check_flag) continue;
    }
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'java-11-openjdk / java-11-openjdk-demo / java-11-openjdk-devel / etc');
}
