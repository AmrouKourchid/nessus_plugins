##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# Red Hat Security Advisory RHSA-2019:0984. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(145649);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/01/25");

  script_cve_id("CVE-2019-7164", "CVE-2019-7548");
  script_xref(name:"RHSA", value:"2019:0984");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");

  script_name(english:"CentOS 8 : python36:3.6 (CESA-2019:0984)");

  script_set_attribute(attribute:"synopsis", value:
"The remote CentOS host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote CentOS Linux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
CESA-2019:0984 advisory.

  - python-sqlalchemy: SQL Injection when the order_by parameter can be controlled (CVE-2019-7164)

  - python-sqlalchemy: SQL Injection when the group_by parameter can be controlled (CVE-2019-7548)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2019:0984");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-7164");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/02/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python-nose-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python-pymongo-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python-sqlalchemy-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python-virtualenv-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python3-PyMySQL");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python3-bson");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python3-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python3-docutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python3-nose");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python3-pygments");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python3-pymongo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python3-pymongo-gridfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python3-scipy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python3-sqlalchemy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python3-virtualenv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python3-wheel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python36");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python36-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python36-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python36-rpm-macros");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CentOS Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if ('CentOS Stream' >< os_release) audit(AUDIT_OS_NOT, 'CentOS 8.x', 'CentOS Stream ' + os_ver);
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '8')) audit(AUDIT_OS_NOT, 'CentOS 8.x', 'CentOS ' + os_ver);

if (!get_kb_item('Host/CentOS/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'CentOS', cpu);

var module_ver = get_kb_item('Host/RedHat/appstream/python36');
if (isnull(module_ver)) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module python36:3.6');
if ('3.6' >!< module_ver) audit(AUDIT_PACKAGE_NOT_AFFECTED, 'Module python36:' + module_ver);

var appstreams = {
    'python36:3.6': [
      {'reference':'python-nose-docs-1.3.7-30.module_el8.0.0+32+017b2cba', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python-nose-docs-1.3.7-30.module_el8.0.0+32+017b2cba', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python-pymongo-doc-3.6.1-9.module_el8.0.0+33+0a10c0e1', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python-pymongo-doc-3.6.1-9.module_el8.0.0+33+0a10c0e1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python-sqlalchemy-doc-1.3.2-1.module_el8.0.0+32+017b2cba', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python-sqlalchemy-doc-1.3.2-1.module_el8.0.0+32+017b2cba', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python-virtualenv-doc-15.1.0-18.module_el8.0.0+33+0a10c0e1', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python-virtualenv-doc-15.1.0-18.module_el8.0.0+33+0a10c0e1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-bson-3.6.1-9.module_el8.0.0+33+0a10c0e1', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-bson-3.6.1-9.module_el8.0.0+33+0a10c0e1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-docs-3.6.7-2.module_el8.0.0+33+0a10c0e1', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-docs-3.6.7-2.module_el8.0.0+33+0a10c0e1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-docutils-0.14-12.module_el8.0.0+33+0a10c0e1', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-docutils-0.14-12.module_el8.0.0+33+0a10c0e1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-nose-1.3.7-30.module_el8.0.0+32+017b2cba', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-nose-1.3.7-30.module_el8.0.0+32+017b2cba', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-pygments-2.2.0-20.module_el8.0.0+33+0a10c0e1', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-pygments-2.2.0-20.module_el8.0.0+33+0a10c0e1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-pymongo-3.6.1-9.module_el8.0.0+33+0a10c0e1', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-pymongo-3.6.1-9.module_el8.0.0+33+0a10c0e1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-pymongo-gridfs-3.6.1-9.module_el8.0.0+33+0a10c0e1', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-pymongo-gridfs-3.6.1-9.module_el8.0.0+33+0a10c0e1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-PyMySQL-0.8.0-10.module_el8.0.0+33+0a10c0e1', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-PyMySQL-0.8.0-10.module_el8.0.0+33+0a10c0e1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-scipy-1.0.0-19.module_el8.0.0+33+0a10c0e1', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-scipy-1.0.0-19.module_el8.0.0+33+0a10c0e1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-sqlalchemy-1.3.2-1.module_el8.0.0+33+0a10c0e1', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-sqlalchemy-1.3.2-1.module_el8.0.0+33+0a10c0e1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-virtualenv-15.1.0-18.module_el8.0.0+33+0a10c0e1', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-virtualenv-15.1.0-18.module_el8.0.0+33+0a10c0e1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-wheel-0.30.0-13.module_el8.0.0+33+0a10c0e1', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'python3-wheel-0.30.0-13.module_el8.0.0+33+0a10c0e1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'python36-3.6.8-2.module_el8.0.0+33+0a10c0e1', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python36-3.6.8-2.module_el8.0.0+33+0a10c0e1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python36-debug-3.6.8-2.module_el8.0.0+33+0a10c0e1', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python36-debug-3.6.8-2.module_el8.0.0+33+0a10c0e1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python36-devel-3.6.8-2.module_el8.0.0+33+0a10c0e1', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python36-devel-3.6.8-2.module_el8.0.0+33+0a10c0e1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python36-rpm-macros-3.6.8-2.module_el8.0.0+33+0a10c0e1', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python36-rpm-macros-3.6.8-2.module_el8.0.0+33+0a10c0e1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
    ]
};

var flag = 0;
appstreams_found = 0;
foreach module (keys(appstreams)) {
  var appstream = NULL;
  var appstream_name = NULL;
  var appstream_version = NULL;
  var appstream_split = split(module, sep:':', keep:FALSE);
  if (!empty_or_null(appstream_split)) {
    appstream_name = appstream_split[0];
    appstream_version = appstream_split[1];
    if (!empty_or_null(appstream_name)) appstream = get_one_kb_item('Host/RedHat/appstream/' + appstream_name);
  }
  if (!empty_or_null(appstream) && appstream_version == appstream || appstream_name == 'all') {
    appstreams_found++;
    foreach package_array ( appstreams[module] ) {
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
  }
}

if (!appstreams_found) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module python36:3.6');

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'python-nose-docs / python-pymongo-doc / python-sqlalchemy-doc / etc');
}
