#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2024:3939.
##

include('compat.inc');

if (description)
{
  script_id(204712);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/25");

  script_cve_id(
    "CVE-2022-27635",
    "CVE-2022-36351",
    "CVE-2022-38076",
    "CVE-2022-40964",
    "CVE-2022-46329"
  );
  script_xref(name:"RHSA", value:"2024:3939");

  script_name(english:"CentOS 7 : linux-firmware (RHSA-2024:3939)");

  script_set_attribute(attribute:"synopsis", value:
"The remote CentOS Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote CentOS Linux 7 host has packages installed that are affected by multiple vulnerabilities as referenced in the
RHSA-2024:3939 advisory.

  - Improper access control for some Intel(R) PROSet/Wireless WiFi and Killer(TM) WiFi software may allow a
    privileged user to potentially enable escalation of privilege via local access. (CVE-2022-27635,
    CVE-2022-40964)

  - Improper input validation in some Intel(R) PROSet/Wireless WiFi and Killer(TM) WiFi software may allow an
    unauthenticated user to potentially enable denial of service via adjacent access. (CVE-2022-36351)

  - Improper input validation in some Intel(R) PROSet/Wireless WiFi and Killer(TM) WiFi software may allow an
    authenticated user to potentially enable escalation of privilege via local access. (CVE-2022-38076)

  - Protection mechanism failure for some Intel(R) PROSet/Wireless WiFi software may allow a privileged user
    to potentially enable escalation of privilege via local access. (CVE-2022-46329)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2024:3939");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-38076");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_severity", value:"Important");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/08/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/06/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/07/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:iwl100-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:iwl1000-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:iwl105-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:iwl135-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:iwl2000-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:iwl2030-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:iwl3160-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:iwl3945-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:iwl4965-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:iwl5000-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:iwl5150-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:iwl6000-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:iwl6000g2a-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:iwl6000g2b-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:iwl6050-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:iwl7260-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:linux-firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");
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
var os_ver = pregmatch(pattern: "CentOS(?: Linux)? release ([0-9]+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'CentOS');
os_ver = os_ver[1];
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '7')) audit(AUDIT_OS_NOT, 'CentOS 7.x', 'CentOS ' + os_ver);

if (!get_kb_item('Host/CentOS/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'CentOS', cpu);

var pkgs = [
    {'reference':'iwl100-firmware-39.31.5.1-83.el7_9', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'iwl1000-firmware-39.31.5.1-83.el7_9', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'iwl105-firmware-18.168.6.1-83.el7_9', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'iwl135-firmware-18.168.6.1-83.el7_9', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'iwl2000-firmware-18.168.6.1-83.el7_9', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'iwl2030-firmware-18.168.6.1-83.el7_9', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'iwl3160-firmware-25.30.13.0-83.el7_9', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'iwl3945-firmware-15.32.2.9-83.el7_9', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'iwl4965-firmware-228.61.2.24-83.el7_9', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'iwl5000-firmware-8.83.5.1_1-83.el7_9', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'iwl5150-firmware-8.24.2.2-83.el7_9', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'iwl6000-firmware-9.221.4.1-83.el7_9', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'iwl6000g2a-firmware-18.168.6.1-83.el7_9', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'iwl6000g2b-firmware-18.168.6.1-83.el7_9', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'iwl6050-firmware-41.28.5.1-83.el7_9', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'iwl7260-firmware-25.30.13.0-83.el7_9', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'linux-firmware-20200421-83.git78c0348.el7_9', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'iwl100-firmware / iwl1000-firmware / iwl105-firmware / etc');
}
