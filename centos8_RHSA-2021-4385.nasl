#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# Red Hat Security Advisory RHSA-2021:4385. The text
# itself is copyright (C) Red Hat, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(155099);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/24");

  script_cve_id("CVE-2021-3800", "CVE-2021-28153");
  script_xref(name:"RHSA", value:"2021:4385");

  script_name(english:"CentOS 8 : glib2 (CESA-2021:4385)");

  script_set_attribute(attribute:"synopsis", value:
"The remote CentOS host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote CentOS Linux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
CESA-2021:4385 advisory.

  - glib: g_file_replace() with G_FILE_CREATE_REPLACE_DESTINATION creates empty target for dangling symlink
    (CVE-2021-28153)

  - glib2: Possible privilege escalation thourgh pkexec and aliases (CVE-2021-3800)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2021:4385");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-28153");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-3800");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/11/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/11/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:8-stream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:glib2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:glib2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:glib2-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:glib2-fam");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:glib2-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:glib2-tests");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CentOS Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list", "Host/cpu");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('rpm.inc');
include('rhel.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var release = get_kb_item('Host/CentOS/release');
if (isnull(release) || 'CentOS' >!< release) audit(AUDIT_OS_NOT, 'CentOS');
var os_ver = pregmatch(pattern: "CentOS(?: Stream)?(?: Linux)? release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'CentOS');
var os_ver = os_ver[1];
if ('CentOS Stream' >!< release) audit(AUDIT_OS_NOT, 'CentOS 8-Stream');
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '8')) audit(AUDIT_OS_NOT, 'CentOS 8.x', 'CentOS ' + os_ver);

if (!get_kb_item('Host/CentOS/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'CentOS', cpu);

var pkgs = [
    {'reference':'glib2-2.56.4-156.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glib2-2.56.4-156.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glib2-devel-2.56.4-156.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glib2-devel-2.56.4-156.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glib2-doc-2.56.4-156.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glib2-doc-2.56.4-156.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glib2-fam-2.56.4-156.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glib2-fam-2.56.4-156.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glib2-static-2.56.4-156.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glib2-static-2.56.4-156.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glib2-tests-2.56.4-156.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glib2-tests-2.56.4-156.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var reference = NULL;
  var release = NULL;
  var sp = NULL;
  var cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = 'CentOS-' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (reference && release) {
    if (rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'glib2 / glib2-devel / glib2-doc / glib2-fam / glib2-static / etc');
}
