#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2014:0026 and 
# Oracle Linux Security Advisory ELSA-2014-0026 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(71984);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/22");

  script_cve_id(
    "CVE-2013-5878",
    "CVE-2013-5884",
    "CVE-2013-5893",
    "CVE-2013-5896",
    "CVE-2013-5907",
    "CVE-2013-5910",
    "CVE-2014-0368",
    "CVE-2014-0373",
    "CVE-2014-0376",
    "CVE-2014-0411",
    "CVE-2014-0416",
    "CVE-2014-0422",
    "CVE-2014-0423",
    "CVE-2014-0428"
  );
  script_bugtraq_id(
    64863,
    64894,
    64907,
    64914,
    64918,
    64921,
    64922,
    64924,
    64926,
    64927,
    64930,
    64933,
    64935,
    64937
  );
  script_xref(name:"RHSA", value:"2014:0026");

  script_name(english:"Oracle Linux 6 : java-1.7.0-openjdk (ELSA-2014-0026)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 6 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2014-0026 advisory.

    [1.7.0.51-2.4.4.1.0.1.el6_5]
    - Update DISTRO_NAME in specfile

    [1.7.0.51-2.4.4.1.el6]
    - restored java7 provides
    - bumped release (builds exists)
    - Resolves: rhbz#1050935

    [1.7.0.51-2.4.4.0.el6]
    - updated to security icedtea 2.4.4
     - icedtea_version set to 2.4.4
     - updatever bumped to       51
     - release reset to 0
    - sync with fedora
     - added and applied patch411 1029588.patch (rh 1029588)
     - added aand applied patch410, 1015432 (rh 1015432)
    - Resolves: rhbz#1050935

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2014-0026.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-0428");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2013-5907");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/01/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/01/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/01/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-1.7.0-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-1.7.0-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-1.7.0-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-1.7.0-openjdk-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-1.7.0-openjdk-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 6', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);

var pkgs = [
    {'reference':'java-1.7.0-openjdk-1.7.0.51-2.4.4.1.0.1.el6_5', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-1.7.0-openjdk-demo-1.7.0.51-2.4.4.1.0.1.el6_5', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-1.7.0-openjdk-devel-1.7.0.51-2.4.4.1.0.1.el6_5', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-1.7.0-openjdk-javadoc-1.7.0.51-2.4.4.1.0.1.el6_5', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-1.7.0-openjdk-src-1.7.0.51-2.4.4.1.0.1.el6_5', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-1.7.0-openjdk-1.7.0.51-2.4.4.1.0.1.el6_5', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-1.7.0-openjdk-demo-1.7.0.51-2.4.4.1.0.1.el6_5', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-1.7.0-openjdk-devel-1.7.0.51-2.4.4.1.0.1.el6_5', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-1.7.0-openjdk-javadoc-1.7.0.51-2.4.4.1.0.1.el6_5', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-1.7.0-openjdk-src-1.7.0.51-2.4.4.1.0.1.el6_5', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'java-1.7.0-openjdk / java-1.7.0-openjdk-demo / java-1.7.0-openjdk-devel / etc');
}
