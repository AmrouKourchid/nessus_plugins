#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2012:1385 and 
# Oracle Linux Security Advisory ELSA-2012-1385 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(68645);
  script_version("1.19");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/23");

  script_cve_id(
    "CVE-2012-3216",
    "CVE-2012-4416",
    "CVE-2012-5068",
    "CVE-2012-5069",
    "CVE-2012-5071",
    "CVE-2012-5072",
    "CVE-2012-5073",
    "CVE-2012-5075",
    "CVE-2012-5077",
    "CVE-2012-5079",
    "CVE-2012-5081",
    "CVE-2012-5084",
    "CVE-2012-5085",
    "CVE-2012-5086",
    "CVE-2012-5089"
  );
  script_bugtraq_id(
    55501,
    56039,
    56058,
    56059,
    56063,
    56065,
    56071,
    56075,
    56076,
    56080,
    56081,
    56082,
    56083
  );
  script_xref(name:"RHSA", value:"2012:1385");

  script_name(english:"Oracle Linux 5 : java-1.6.0-openjdk (ELSA-2012-1385)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 5 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2012-1385 advisory.

    [1:1.6.0.0-1.28.1.10.10.0.1.el5_8]
    - Add oracle-enterprise.patch

    [1:1.6.0.0-1.28.1.10.10]
    - Updated to IcedTea6 1.10.10
    - Resolves rhbz#s 856124, 865346, 865348, 865350, 865352, 865354, 865357,
      865359, 865363, 865365, 865370, 865428, 865471, 865434, 865511, 865514,
      865519, 865531, 865541, 865568

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2012-1385.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2012-5086");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2012-5081");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/10/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/10/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-1.6.0-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-1.6.0-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-1.6.0-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-1.6.0-openjdk-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-1.6.0-openjdk-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2013-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 5', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);

var pkgs = [
    {'reference':'java-1.6.0-openjdk-1.6.0.0-1.28.1.10.10.0.1.el5_8', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-1.6.0-openjdk-demo-1.6.0.0-1.28.1.10.10.0.1.el5_8', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-1.6.0-openjdk-devel-1.6.0.0-1.28.1.10.10.0.1.el5_8', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-1.6.0-openjdk-javadoc-1.6.0.0-1.28.1.10.10.0.1.el5_8', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-1.6.0-openjdk-src-1.6.0.0-1.28.1.10.10.0.1.el5_8', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-1.6.0-openjdk-1.6.0.0-1.28.1.10.10.0.1.el5_8', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-1.6.0-openjdk-demo-1.6.0.0-1.28.1.10.10.0.1.el5_8', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-1.6.0-openjdk-devel-1.6.0.0-1.28.1.10.10.0.1.el5_8', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-1.6.0-openjdk-javadoc-1.6.0.0-1.28.1.10.10.0.1.el5_8', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-1.6.0-openjdk-src-1.6.0.0-1.28.1.10.10.0.1.el5_8', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'java-1.6.0-openjdk / java-1.6.0-openjdk-demo / java-1.6.0-openjdk-devel / etc');
}
