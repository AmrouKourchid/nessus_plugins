#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2023:4766.
##

include('compat.inc');

if (description)
{
  script_id(187242);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/12/22");

  script_cve_id("CVE-2023-32360");
  script_xref(name:"RHSA", value:"2023:4766");

  script_name(english:"CentOS 7 : cups (RHSA-2023:4766)");

  script_set_attribute(attribute:"synopsis", value:
"The remote CentOS Linux host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote CentOS Linux 7 host has packages installed that are affected by a vulnerability as referenced in the
RHSA-2023:4766 advisory.

  - An authentication issue was addressed with improved state management. This issue is fixed in macOS Big Sur
    11.7.7, macOS Monterey 12.6.6, macOS Ventura 13.4. An unauthenticated user may be able to access recently
    printed documents. (CVE-2023-32360)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2023:4766");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-32360");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_severity", value:"Important");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/05/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/08/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/12/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:cups");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:cups-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:cups-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:cups-filesystem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:cups-ipptool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:cups-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:cups-lpd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CentOS Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'reference':'cups-1.6.3-52.el7_9', 'cpu':'ppc64le', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cups-1.6.3-52.el7_9', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cups-client-1.6.3-52.el7_9', 'cpu':'ppc64le', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cups-client-1.6.3-52.el7_9', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cups-devel-1.6.3-52.el7_9', 'cpu':'ppc64le', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cups-devel-1.6.3-52.el7_9', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cups-filesystem-1.6.3-52.el7_9', 'cpu':'ppc64le', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cups-filesystem-1.6.3-52.el7_9', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cups-ipptool-1.6.3-52.el7_9', 'cpu':'ppc64le', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cups-ipptool-1.6.3-52.el7_9', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cups-libs-1.6.3-52.el7_9', 'cpu':'ppc64le', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cups-libs-1.6.3-52.el7_9', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cups-lpd-1.6.3-52.el7_9', 'cpu':'ppc64le', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cups-lpd-1.6.3-52.el7_9', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'cups / cups-client / cups-devel / etc');
}
