#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2020:0195 and 
# Oracle Linux Security Advisory ELSA-2020-0195 respectively.
#

include('compat.inc');

if (description)
{
  script_id(133183);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/22");

  script_cve_id("CVE-2019-17626");
  script_xref(name:"RHSA", value:"2020:0195");

  script_name(english:"Oracle Linux 7 : python-reportlab (ELSA-2020-0195)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 7 host has packages installed that are affected by a vulnerability as referenced in the
ELSA-2020-0195 advisory.

    [2.5-9.el7_7.1]
    - Do not eval strings passed to toColor
    - Resolves: #1788552

    [2.5-9]
    - Mass rebuild 2014-01-24

    [2.5-8]
    - Mass rebuild 2013-12-27

    [2.5-7]
    - Rebuilt for https://fedoraproject.org/wiki/Fedora_19_Mass_Rebuild

    [2.5-6]
    - Add a dep on python-imaging to process images

    [2.5-5]
    - Rebuilt for https://fedoraproject.org/wiki/Fedora_18_Mass_Rebuild

    [2.5-4]
    - Rebuilt for https://fedoraproject.org/wiki/Fedora_17_Mass_Rebuild

    [2.5-3]
    - Rebuilt for https://fedoraproject.org/wiki/Fedora_15_Mass_Rebuild

    [2.5-2]
    - Update to version 2.5 of reportlab.
    - Remove tabs in specfile.

    [2.3-3]
    - Rebuilt for https://fedoraproject.org/wiki/Features/Python_2.7/MassRebuild

    [2.3-2]
    - Do not bundle fonts
    - Point the config to Fedora's font locations

    [2.3-1]
    - Updated to 2.3
    - New version is no longer noarch.

    [2.1-6]
    - Rebuild for https://fedoraproject.org/wiki/Fedora_11_Mass_Rebuild

    [2.1-5]
    - Rebuilt for https://fedoraproject.org/wiki/Fedora_11_Mass_Rebuild

    [2.1-4]
    - Fix locations for Python 2.6

    [2.1-3]
    - Rebuild for Python 2.6

    [2.1-2]
    - Remove luxi font. (#427845)
    - Add patch to not search for the luxi font.

    [2.1-1]
    - Update to 2.1.

    [2.0-2]
    - Make docs subpackage.

    [2.0-1]
    - Update to 2.0.

    [1.21.1-2]
    - Rebuild against new python.

    [1.21.1-1]
    - Update to 1.20.1.

    [1.20-5]
    - rebuilt for new gcc4.1 snapshot and glibc changes

    [1.20-4]
    - Add dist tag. (#176479)

    [1.20-3.fc4]
    - Switchback to sitelib patch.
    - Make package noarch.

    [1.20-2.fc4]
    - Use python_sitearch to fix x86_64 build.

    [1.20-1.fc4]
    - Rebuild for Python 2.4.
    - Update to 1.20.
    - Switch to the new python macros for python-abi
    - Add dist tag.

    [0:1.19-0.fdr.2]
    - Removed ghosts.

    [0:1.19-0.fdr.1]
    - Initial Fedora RPM build.

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2020-0195.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected python-reportlab and / or python-reportlab-docs packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-17626");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/01/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python-reportlab");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python-reportlab-docs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 7', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);

var pkgs = [
    {'reference':'python-reportlab-2.5-9.el7_7.1', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python-reportlab-docs-2.5-9.el7_7.1', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python-reportlab-2.5-9.el7_7.1', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python-reportlab-docs-2.5-9.el7_7.1', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'python-reportlab / python-reportlab-docs');
}
