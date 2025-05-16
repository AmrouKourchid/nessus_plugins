#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2020:2970 and 
# Oracle Linux Security Advisory ELSA-2020-2970 respectively.
#

include('compat.inc');

if (description)
{
  script_id(138665);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/22");

  script_cve_id(
    "CVE-2020-14556",
    "CVE-2020-14562",
    "CVE-2020-14573",
    "CVE-2020-14577",
    "CVE-2020-14583",
    "CVE-2020-14593",
    "CVE-2020-14621"
  );
  script_xref(name:"RHSA", value:"2020:2970");
  script_xref(name:"IAVA", value:"2020-A-0322-S");

  script_name(english:"Oracle Linux 8 : java-11-openjdk (ELSA-2020-2970)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2020-2970 advisory.

    [1:11.0.8.10-0]
    - Update to shenandoah-jdk-11.0.8+10 (GA)
    - Switch to GA mode for final release.
    - Update release notes with last minute fix (JDK-8248505).
    - This tarball is embargoed until 2020-07-14 @ 1pm PT.
    - Resolves: rhbz#1838811

    [1:11.0.8.9-0.0.ea]
    - Update to shenandoah-jdk-11.0.8+9 (EA)
    - Update release notes for 11.0.8 release.
    - This tarball is embargoed until 2020-07-14 @ 1pm PT.
    - Resolves: rhbz#1838811

    [1:11.0.8.8-0.0.ea]
    - Update to shenandoah-jdk-11.0.8+8 (EA)
    - Resolves: rhbz#1838811

    [1:11.0.8.7-0.1.ea]
    - java-11-openjdk doesn't have a JRE tree, so don't try and copy alt-java there...
    - Resolves: rhbz#1838811

    [1:11.0.8.7-0.1.ea]
    - Create a copy of java as alt-java with alternatives and man pages
    - Resolves: rhbz#1838811

    [1:11.0.8.7-0.0.ea]
    - Update to shenandoah-jdk-11.0.8+7 (EA)
    - Resolves: rhbz#1838811

    [1:11.0.8.6-0.0.ea]
    - Update to shenandoah-jdk-11.0.8+6 (EA)
    - Resolves: rhbz#1838811

    [1:11.0.8.5-0.1.ea]
    - Disable stripping of debug symbols for static libraries part of
      the -static-libs sub-package.
    - Resolves: rhbz#1848701

    [1:11.0.8.5-0.0.ea]
    - Update to shenandoah-jdk-11.0.8+5 (EA)
    - Resolves: rhbz#1838811

    [1:11.0.8.4-0.0.ea]
    - Update to shenandoah-jdk-11.0.8+4 (EA)
    - Require tzdata 2020a due to resource changes in JDK-8243541
    - Resolves: rhbz#1838811

    [1:11.0.8.3-0.0.ea]
    - Update to shenandoah-jdk-11.0.8+3 (EA)
    - Resolves: rhbz#1838811

    [1:11.0.8.2-0.1.ea]
    - Build static-libs-image and add resulting files via -static-libs
      sub-package.
    - Resolves: rhbz#1848701

    [1:11.0.8.2-0.0.ea]
    - Update to shenandoah-jdk-11.0.8+2 (EA)
    - Resolves: rhbz#1838811

    [1:11.0.8.1-0.0.ea]
    - Update to shenandoah-jdk-11.0.8+1 (EA)
    - Switch to EA mode for 11.0.8 pre-release builds.
    - Drop JDK-8237396 & JDK-8228407 backports now applied upstream.
    - Resolves: rhbz#1838811

    [1:11.0.7.10-2]
    - Add JDK-8228407 backport to resolve crashes during verification.
    - Resolves: rhbz#1810557

    [1:11.0.7.10-2]
    - Amend release notes, removing issue actually fixed in 11.0.6.
    - Resolves: rhbz#1810557

    [1:11.0.7.10-2]
    - Add release notes.
    - Resolves: rhbz#1810557

    [1:11.0.7.10-2]
    - Make use of --with-extra-asflags introduced in jdk-11.0.6+1.
    - Resolves: rhbz#1810557

    [1:11.0.7.10-1]
    - Update to shenandoah-jdk-11.0.7+10 (GA)
    - Switch to GA mode for final release.
    - Resolves: rhbz#1810557

    [1:11.0.7.9-0.1.ea]
    - Update to shenandoah-jdk-11.0.7+9 (EA)
    - Resolves: rhbz#1810557

    [1:11.0.7.8-0.1.ea]
    - Update to shenandoah-jdk-11.0.7+8 (EA)
    - Resolves: rhbz#1810557

    [1:11.0.7.7-0.1.ea]
    - Update to shenandoah-jdk-11.0.7+7 (EA)
    - Resolves: rhbz#1810557

    [1:11.0.7.6-0.1.ea]
    - Update to shenandoah-jdk-11.0.7+6 (EA)
    - Resolves: rhbz#1810557

    [1:11.0.7.5-0.1.ea]
    - Update to shenandoah-jdk-11.0.7+5 (EA)
    - Resolves: rhbz#1810557

    [1:11.0.7.4-0.1.ea]
    - Update to shenandoah-jdk-11.0.7+4 (EA)
    - Resolves: rhbz#1810557

    [1:11.0.7.3-0.1.ea]
    - Update to shenandoah-jdk-11.0.7+3 (EA)
    - Resolves: rhbz#1810557

    [1:11.0.7.2-0.1.ea]
    - Update to shenandoah-jdk-11.0.7+2 (EA)
    - Resolves: rhbz#1810557

    [1:11.0.7.1-0.1.ea]
    - Update to shenandoah-jdk-11.0.7+1 (EA)
    - Switch to EA mode for 11.0.7 pre-release builds.
    - Drop JDK-8236039 backport now applied upstream.
    - Resolves: rhbz#1810557

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2020-2970.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-14556");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-14583");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-11-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-11-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-11-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-11-openjdk-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-11-openjdk-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-11-openjdk-javadoc-zip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-11-openjdk-jmods");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-11-openjdk-src");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-11-openjdk-static-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:8");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 8', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);

var pkgs = [
    {'reference':'java-11-openjdk-11.0.8.10-0.el8_2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-demo-11.0.8.10-0.el8_2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-devel-11.0.8.10-0.el8_2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-headless-11.0.8.10-0.el8_2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-javadoc-11.0.8.10-0.el8_2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-javadoc-zip-11.0.8.10-0.el8_2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-jmods-11.0.8.10-0.el8_2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-src-11.0.8.10-0.el8_2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-static-libs-11.0.8.10-0.el8_2', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-11.0.8.10-0.el8_2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-demo-11.0.8.10-0.el8_2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-devel-11.0.8.10-0.el8_2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-headless-11.0.8.10-0.el8_2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-javadoc-11.0.8.10-0.el8_2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-javadoc-zip-11.0.8.10-0.el8_2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-jmods-11.0.8.10-0.el8_2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-src-11.0.8.10-0.el8_2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-11-openjdk-static-libs-11.0.8.10-0.el8_2', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'java-11-openjdk / java-11-openjdk-demo / java-11-openjdk-devel / etc');
}
