#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2015:1628 and 
# Oracle Linux Security Advisory ELSA-2015-1628 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(85488);
  script_version("2.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/22");

  script_cve_id(
    "CVE-2014-6568",
    "CVE-2015-0374",
    "CVE-2015-0381",
    "CVE-2015-0382",
    "CVE-2015-0391",
    "CVE-2015-0411",
    "CVE-2015-0432",
    "CVE-2015-0433",
    "CVE-2015-0441",
    "CVE-2015-0499",
    "CVE-2015-0501",
    "CVE-2015-0505",
    "CVE-2015-2568",
    "CVE-2015-2571",
    "CVE-2015-2573",
    "CVE-2015-2582",
    "CVE-2015-2620",
    "CVE-2015-2643",
    "CVE-2015-2648",
    "CVE-2015-4737",
    "CVE-2015-4752",
    "CVE-2015-4757"
  );
  script_xref(name:"RHSA", value:"2015:1628");

  script_name(english:"Oracle Linux 5 : mysql55-mysql (ELSA-2015-1628)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 5 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2015-1628 advisory.

    [5.5.45-1]
    - Rebase to 5.5.45
      Includes fixes for: CVE-2014-6568 CVE-2015-0374
      CVE-2015-0381 CVE-2015-0382 CVE-2015-0391 CVE-2015-0411 CVE-2015-0432
      CVE-2015-0501 CVE-2015-2568 CVE-2015-0499 CVE-2015-2571 CVE-2015-0433
      CVE-2015-0441 CVE-2015-0505 CVE-2015-2573 CVE-2015-2582 CVE-2015-2620
      CVE-2015-2643 CVE-2015-2648 CVE-2015-4737 CVE-2015-4752 CVE-2015-4757
      Resolves: #1247020

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2015-1628.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-0411");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2015-2582");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/01/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/08/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mysql55-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mysql55-mysql-bench");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mysql55-mysql-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mysql55-mysql-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mysql55-mysql-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mysql55-mysql-test");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");
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
if (! preg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 5', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);

var pkgs = [
    {'reference':'mysql55-mysql-5.5.45-1.el5', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mysql55-mysql-bench-5.5.45-1.el5', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mysql55-mysql-devel-5.5.45-1.el5', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mysql55-mysql-libs-5.5.45-1.el5', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mysql55-mysql-server-5.5.45-1.el5', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mysql55-mysql-test-5.5.45-1.el5', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mysql55-mysql-5.5.45-1.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mysql55-mysql-bench-5.5.45-1.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mysql55-mysql-devel-5.5.45-1.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mysql55-mysql-libs-5.5.45-1.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mysql55-mysql-server-5.5.45-1.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mysql55-mysql-test-5.5.45-1.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'mysql55-mysql / mysql55-mysql-bench / mysql55-mysql-devel / etc');
}
