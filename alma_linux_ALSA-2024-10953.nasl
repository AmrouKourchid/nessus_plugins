#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# AlmaLinux Security Advisory ALSA-2024:10953.
##

include('compat.inc');

if (description)
{
  script_id(213246);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/11");

  script_cve_id("CVE-2024-53899");
  script_xref(name:"ALSA", value:"2024:10953");
  script_xref(name:"RHSA", value:"2024:10953");

  script_name(english:"AlmaLinux 8 : python36:3.6 (ALSA-2024:10953)");

  script_set_attribute(attribute:"synopsis", value:
"The remote AlmaLinux host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote AlmaLinux 8 host has packages installed that are affected by a vulnerability as referenced in the
ALSA-2024:10953 advisory.

    * virtualenv: potential command injection via virtual environment activation scripts (CVE-2024-53899)

Tenable has extracted the preceding description block directly from the AlmaLinux security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.almalinux.org/8/ALSA-2024-10953.html");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2024:10953");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-53899");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(78);

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/11/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/12/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/12/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python-nose-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python-pymongo-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python-sqlalchemy-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python-virtualenv-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python3-PyMySQL");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python3-bson");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python3-distro");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python3-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python3-docutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python3-nose");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python3-pygments");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python3-pymongo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python3-pymongo-gridfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python3-scipy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python3-sqlalchemy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python3-virtualenv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python3-wheel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python3-wheel-wheel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python36");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python36-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python36-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python36-rpm-macros");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::appstream");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::baseos");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::highavailability");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::nfv");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::powertools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::realtime");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::resilientstorage");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::sap");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::sap_hana");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::supplementary");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Alma Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AlmaLinux/release", "Host/AlmaLinux/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/AlmaLinux/release');
if (isnull(os_release) || 'AlmaLinux' >!< os_release) audit(AUDIT_OS_NOT, 'AlmaLinux');
var os_ver = pregmatch(pattern: "AlmaLinux release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'AlmaLinux');
os_ver = os_ver[1];
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'AlmaLinux 8.x', 'AlmaLinux ' + os_ver);

if (!get_kb_item('Host/AlmaLinux/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('aarch64' >!< cpu && 'ppc' >!< cpu && 's390' >!< cpu && 'x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'AlmaLinux', cpu);

var pkgs = [
    {'reference':'python-nose-docs-1.3.7-31.module_el8.9.0+3700+efebe9fd', 'release':'8', 'el_string':'el8.9.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'python-pymongo-doc-3.7.0-1.module_el8.9.0+3700+efebe9fd', 'release':'8', 'el_string':'el8.9.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'python-sqlalchemy-doc-1.3.2-3.module_el8.10.0+3769+3838165b', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'python-virtualenv-doc-15.1.0-23.module_el8.10.0+3937+b6a3652f', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'python3-bson-3.7.0-1.module_el8.9.0+3700+efebe9fd', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.9.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'python3-bson-3.7.0-1.module_el8.9.0+3700+efebe9fd', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.9.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'python3-bson-3.7.0-1.module_el8.9.0+3700+efebe9fd', 'cpu':'s390x', 'release':'8', 'el_string':'el8.9.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'python3-bson-3.7.0-1.module_el8.9.0+3700+efebe9fd', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.9.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'python3-distro-1.4.0-2.module_el8.9.0+3700+efebe9fd', 'release':'8', 'el_string':'el8.9.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'python3-docs-3.6.7-2.module_el8.9.0+3700+efebe9fd', 'release':'8', 'el_string':'el8.9.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'python3-docutils-0.14-12.module_el8.9.0+3700+efebe9fd', 'release':'8', 'el_string':'el8.9.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'python3-nose-1.3.7-31.module_el8.9.0+3700+efebe9fd', 'release':'8', 'el_string':'el8.9.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'python3-pygments-2.2.0-22.module_el8.9.0+3700+efebe9fd', 'release':'8', 'el_string':'el8.9.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'python3-pymongo-3.7.0-1.module_el8.9.0+3700+efebe9fd', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.9.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'python3-pymongo-3.7.0-1.module_el8.9.0+3700+efebe9fd', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.9.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'python3-pymongo-3.7.0-1.module_el8.9.0+3700+efebe9fd', 'cpu':'s390x', 'release':'8', 'el_string':'el8.9.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'python3-pymongo-3.7.0-1.module_el8.9.0+3700+efebe9fd', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.9.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'python3-pymongo-gridfs-3.7.0-1.module_el8.9.0+3700+efebe9fd', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.9.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'python3-pymongo-gridfs-3.7.0-1.module_el8.9.0+3700+efebe9fd', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.9.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'python3-pymongo-gridfs-3.7.0-1.module_el8.9.0+3700+efebe9fd', 'cpu':'s390x', 'release':'8', 'el_string':'el8.9.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'python3-pymongo-gridfs-3.7.0-1.module_el8.9.0+3700+efebe9fd', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.9.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'python3-PyMySQL-0.10.1-2.module_el8.9.0+3700+efebe9fd', 'release':'8', 'el_string':'el8.9.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'python3-scipy-1.0.0-21.module_el8.9.0+3700+efebe9fd', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.9.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'python3-scipy-1.0.0-21.module_el8.9.0+3700+efebe9fd', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.9.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'python3-scipy-1.0.0-21.module_el8.9.0+3700+efebe9fd', 'cpu':'s390x', 'release':'8', 'el_string':'el8.9.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'python3-scipy-1.0.0-21.module_el8.9.0+3700+efebe9fd', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.9.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'python3-sqlalchemy-1.3.2-3.module_el8.10.0+3769+3838165b', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'python3-sqlalchemy-1.3.2-3.module_el8.10.0+3769+3838165b', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'python3-sqlalchemy-1.3.2-3.module_el8.10.0+3769+3838165b', 'cpu':'s390x', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'python3-sqlalchemy-1.3.2-3.module_el8.10.0+3769+3838165b', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'python3-virtualenv-15.1.0-23.module_el8.10.0+3937+b6a3652f', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'python3-wheel-0.31.1-3.module_el8.9.0+3700+efebe9fd', 'release':'8', 'el_string':'el8.9.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'python3-wheel-wheel-0.31.1-3.module_el8.9.0+3700+efebe9fd', 'release':'8', 'el_string':'el8.9.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'python36-3.6.8-39.module_el8.10.0+3769+3838165b', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'python36-3.6.8-39.module_el8.10.0+3769+3838165b', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'python36-3.6.8-39.module_el8.10.0+3769+3838165b', 'cpu':'s390x', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'python36-3.6.8-39.module_el8.10.0+3769+3838165b', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'python36-debug-3.6.8-39.module_el8.10.0+3769+3838165b', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'python36-debug-3.6.8-39.module_el8.10.0+3769+3838165b', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'python36-debug-3.6.8-39.module_el8.10.0+3769+3838165b', 'cpu':'s390x', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'python36-debug-3.6.8-39.module_el8.10.0+3769+3838165b', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'python36-devel-3.6.8-39.module_el8.10.0+3769+3838165b', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'python36-devel-3.6.8-39.module_el8.10.0+3769+3838165b', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'python36-devel-3.6.8-39.module_el8.10.0+3769+3838165b', 'cpu':'s390x', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'python36-devel-3.6.8-39.module_el8.10.0+3769+3838165b', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'python36-rpm-macros-3.6.8-39.module_el8.10.0+3769+3838165b', 'release':'8', 'el_string':'el8.10.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'}
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
  var cves = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = 'Alma-' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (!empty_or_null(package_array['cves'])) cves = package_array['cves'];
  if (reference && _release && (!exists_check || rpm_exists(release:_release, rpm:exists_check))) {
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj, cves:cves)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'python-nose-docs / python-pymongo-doc / python-sqlalchemy-doc / etc');
}
