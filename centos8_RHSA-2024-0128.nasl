#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# Red Hat Security Advisory RHSA-2024:0128. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(187865);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/02/08");

  script_cve_id("CVE-2023-5367");
  script_xref(name:"RHSA", value:"2024:0128");

  script_name(english:"CentOS 8 : tigervnc (CESA-2024:0128)");

  script_set_attribute(attribute:"synopsis", value:
"The remote CentOS host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote CentOS Linux 8 host has packages installed that are affected by a vulnerability as referenced in the
CESA-2024:0128 advisory.

  - A out-of-bounds write flaw was found in the xorg-x11-server. This issue occurs due to an incorrect
    calculation of a buffer offset when copying data stored in the heap in the XIChangeDeviceProperty function
    in Xi/xiproperty.c and in RRChangeOutputProperty function in randr/rrproperty.c, allowing for possible
    escalation of privileges or denial of service. (CVE-2023-5367)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2024:0128");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-5367");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/10/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/01/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/01/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:8-stream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tigervnc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tigervnc-icons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tigervnc-license");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tigervnc-selinux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tigervnc-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tigervnc-server-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tigervnc-server-module");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CentOS Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if ('CentOS Stream' >!< os_release) audit(AUDIT_OS_NOT, 'CentOS 8-Stream');
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '8')) audit(AUDIT_OS_NOT, 'CentOS 8.x', 'CentOS ' + os_ver);

if (!get_kb_item('Host/CentOS/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'CentOS', cpu);

var pkgs = [
    {'reference':'tigervnc-1.13.1-2.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'tigervnc-1.13.1-2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'tigervnc-icons-1.13.1-2.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'tigervnc-icons-1.13.1-2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'tigervnc-license-1.13.1-2.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'tigervnc-license-1.13.1-2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'tigervnc-selinux-1.13.1-2.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'tigervnc-selinux-1.13.1-2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'tigervnc-server-1.13.1-2.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'tigervnc-server-1.13.1-2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'tigervnc-server-minimal-1.13.1-2.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'tigervnc-server-minimal-1.13.1-2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'tigervnc-server-module-1.13.1-2.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'tigervnc-server-module-1.13.1-2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
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
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'tigervnc / tigervnc-icons / tigervnc-license / tigervnc-selinux / etc');
}
