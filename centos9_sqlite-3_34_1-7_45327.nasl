#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# the CentOS Stream Build Service.
##

include('compat.inc');

if (description)
{
  script_id(193931);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/25");

  script_cve_id("CVE-2023-7104");
  script_xref(name:"IAVA", value:"2024-A-0003-S");

  script_name(english:"CentOS 9 : sqlite-3.34.1-7.el9");

  script_set_attribute(attribute:"synopsis", value:
"The remote CentOS host is missing a security update for lemon.");
  script_set_attribute(attribute:"description", value:
"The remote CentOS Linux 9 host has packages installed that are affected by a vulnerability as referenced in the
sqlite-3.34.1-7.el9 build changelog.

  - A vulnerability was found in SQLite SQLite3 up to 3.43.0 and classified as critical. This issue affects
    the function sessionReadRecord of the file ext/session/sqlite3session.c of the component make alltest
    Handler. The manipulation leads to heap-based buffer overflow. It is recommended to apply a patch to fix
    this issue. The associated identifier of this vulnerability is VDB-248999. (CVE-2023-7104)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://kojihub.stream.centos.org/koji/buildinfo?buildID=45327");
  script_set_attribute(attribute:"solution", value:
"Update the CentOS 9 Stream lemon package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-7104");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/12/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/01/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/04/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:centos:centos:9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:lemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:sqlite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:sqlite-analyzer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:sqlite-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:sqlite-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:sqlite-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:sqlite-tcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:sqlite-tools");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CentOS Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');
include('rhel.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/CentOS/release');
if (isnull(os_release) || 'CentOS' >!< os_release) audit(AUDIT_OS_NOT, 'CentOS');
var os_ver = pregmatch(pattern: "CentOS(?: Stream)?(?: Linux)? release ([0-9]+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'CentOS');
os_ver = os_ver[1];
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '9')) audit(AUDIT_OS_NOT, 'CentOS 9.x', 'CentOS ' + os_ver);

if (!get_kb_item('Host/CentOS/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'CentOS', cpu);

var pkgs = [
    {'reference':'lemon-3.34.1-7.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sqlite-3.34.1-7.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sqlite-analyzer-3.34.1-7.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sqlite-devel-3.34.1-7.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sqlite-doc-3.34.1-7.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sqlite-libs-3.34.1-7.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sqlite-tcl-3.34.1-7.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sqlite-tools-3.34.1-7.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE}
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
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = 'CentOS-' + package_array['release'];
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'lemon / sqlite / sqlite-analyzer / sqlite-devel / sqlite-doc / etc');
}
