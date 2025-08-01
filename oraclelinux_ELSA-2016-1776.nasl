#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2016:1776 and 
# Oracle Linux Security Advisory ELSA-2016-1776 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(93147);
  script_version("2.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/22");

  script_cve_id(
    "CVE-2016-3458",
    "CVE-2016-3500",
    "CVE-2016-3508",
    "CVE-2016-3550",
    "CVE-2016-3606"
  );
  script_xref(name:"RHSA", value:"2016:1776");

  script_name(english:"Oracle Linux 5 / 6 / 7 : java-1.6.0-openjdk (ELSA-2016-1776)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 5 / 6 / 7 host has packages installed that are affected by multiple vulnerabilities as
referenced in the ELSA-2016-1776 advisory.

    [1:1.6.0.40-1.13.12.4.0.1]
    - Add oracle-enterprise.patch

    [1:1.6.0.40-1.13.12.4]
    - Bump source tarballs to try and really fix TCK failures this time.
    - Resolves: rhbz#1350043

    [1:1.6.0.40-1.13.12.3]
    - Bump source tarballs to missing -DNDEBUG on JDK native code.
    - Resolves: rhbz#1350043

    [1:1.6.0.40-1.13.12.2]
    - Escape macros in bootstrap comments
    - Resolves: rhbz#1350043

    [1:1.6.0.40-1.13.12.2]
    - Bump source tarballs to fix TCK failures.
    - Resolves: rhbz#1350043

    [1:1.6.0.40-1.13.12.1]
    - Introduce bootstrapping variable to test whether we are bootstrapping or not.
    - Add build requirement of xsltproc when bootstrapping.
    - Resolves: rhbz#1350043

    [1:1.6.0.40-1.13.12.1]
    - Separate bootstrap option as it should not be tied to the JDK used.
    - Enable bootstrapping on JIT architectures going forward.
    - Temporarily enable bootstrapping on all architectures to work around RH1334465/PR2956.
    - Resolves: rhbz#1350043

    [1:1.6.0.40-1.13.12.0]
    - Need to also remove DISTRIBUTION_PATCHES reference to wrapv patch.
    - Resolves: rhbz#1350043

    [1:1.6.0.40-1.13.12.0]
    - Update to IcedTea 1.13.12 & OpenJDK 6 b40.
    - Depend on mailcap for /etc/mime.types (PR2800)
    - Use configure macro and disable long-running JTreg & SystemTap tests from make check
    - Remove redundant patch-ecj target invocation for bootstrap build.
    - Add check section to run the new tests introduced in 1.13.12.
    - Add RHEL version of b40 tarball.
    - Require mailcap at build time as well, so configure finds /etc/mime.types
    - No need to require openssl at run time.
    - Drop old_gcc patch as this is now supported upstream (S8161262)
    - Resolves: rhbz#1350043

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2016-1776.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-3606");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/07/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/08/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-1.6.0-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-1.6.0-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-1.6.0-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-1.6.0-openjdk-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-1.6.0-openjdk-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2016-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^(5|6|7)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 5 / 6 / 7', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);

var pkgs = [
    {'reference':'java-1.6.0-openjdk-1.6.0.40-1.13.12.4.0.1.el5_11', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-1.6.0-openjdk-demo-1.6.0.40-1.13.12.4.0.1.el5_11', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-1.6.0-openjdk-devel-1.6.0.40-1.13.12.4.0.1.el5_11', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-1.6.0-openjdk-javadoc-1.6.0.40-1.13.12.4.0.1.el5_11', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-1.6.0-openjdk-src-1.6.0.40-1.13.12.4.0.1.el5_11', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-1.6.0-openjdk-1.6.0.40-1.13.12.4.0.1.el5_11', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-1.6.0-openjdk-demo-1.6.0.40-1.13.12.4.0.1.el5_11', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-1.6.0-openjdk-devel-1.6.0.40-1.13.12.4.0.1.el5_11', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-1.6.0-openjdk-javadoc-1.6.0.40-1.13.12.4.0.1.el5_11', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-1.6.0-openjdk-src-1.6.0.40-1.13.12.4.0.1.el5_11', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-1.6.0-openjdk-1.6.0.40-1.13.12.6.el6_8', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-1.6.0-openjdk-demo-1.6.0.40-1.13.12.6.el6_8', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-1.6.0-openjdk-devel-1.6.0.40-1.13.12.6.el6_8', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-1.6.0-openjdk-javadoc-1.6.0.40-1.13.12.6.el6_8', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-1.6.0-openjdk-src-1.6.0.40-1.13.12.6.el6_8', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-1.6.0-openjdk-1.6.0.40-1.13.12.6.el6_8', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-1.6.0-openjdk-demo-1.6.0.40-1.13.12.6.el6_8', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-1.6.0-openjdk-devel-1.6.0.40-1.13.12.6.el6_8', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-1.6.0-openjdk-javadoc-1.6.0.40-1.13.12.6.el6_8', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-1.6.0-openjdk-src-1.6.0.40-1.13.12.6.el6_8', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-1.6.0-openjdk-1.6.0.40-1.13.12.5.el7_2', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-1.6.0-openjdk-demo-1.6.0.40-1.13.12.5.el7_2', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-1.6.0-openjdk-devel-1.6.0.40-1.13.12.5.el7_2', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-1.6.0-openjdk-javadoc-1.6.0.40-1.13.12.5.el7_2', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-1.6.0-openjdk-src-1.6.0.40-1.13.12.5.el7_2', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'}
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
      severity   : SECURITY_WARNING,
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
