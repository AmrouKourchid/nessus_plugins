##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2020:4001 and
# CentOS Errata and Security Advisory 2020:4001 respectively.
##

include('compat.inc');

if (description)
{
  script_id(141612);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/09");

  script_cve_id("CVE-2020-0556");
  script_xref(name:"RHSA", value:"2020:4001");

  script_name(english:"CentOS 7 : bluez (RHSA-2020:4001)");

  script_set_attribute(attribute:"synopsis", value:
"The remote CentOS Linux host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote CentOS Linux 7 host has packages installed that are affected by a vulnerability as referenced in the
RHSA-2020:4001 advisory.

  - Improper access control in subsystem for BlueZ before version 5.54 may allow an unauthenticated user to
    potentially enable escalation of privilege and denial of service via adjacent access (CVE-2020-0556)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2020:4001");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-0556");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"vendor_severity", value:"Moderate");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/03/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bluez");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bluez-cups");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bluez-hid2hci");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bluez-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bluez-libs-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CentOS Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');
include('rhel.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/CentOS/release');
if (isnull(os_release) || 'CentOS' >!< os_release) audit(AUDIT_OS_NOT, 'CentOS');
var os_ver = pregmatch(pattern: "CentOS(?: Linux)? release ([0-9]+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'CentOS');
os_ver = os_ver[1];
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '7')) audit(AUDIT_OS_NOT, 'CentOS 7.x', 'CentOS ' + os_ver);

if (!get_kb_item('Host/CentOS/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'CentOS', cpu);

var pkgs = [
    {'reference':'bluez-5.44-7.el7', 'cpu':'ppc64le', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'bluez-5.44-7.el7', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'bluez-cups-5.44-7.el7', 'cpu':'ppc64le', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'bluez-cups-5.44-7.el7', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'bluez-hid2hci-5.44-7.el7', 'cpu':'ppc64le', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'bluez-hid2hci-5.44-7.el7', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'bluez-libs-5.44-7.el7', 'cpu':'ppc64le', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'bluez-libs-5.44-7.el7', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'bluez-libs-devel-5.44-7.el7', 'cpu':'ppc64le', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'bluez-libs-devel-5.44-7.el7', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE}
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
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
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
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'bluez / bluez-cups / bluez-hid2hci / etc');
}
