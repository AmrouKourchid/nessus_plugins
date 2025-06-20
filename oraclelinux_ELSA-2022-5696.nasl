##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2022-5696.
##

include('compat.inc');

if (description)
{
  script_id(163442);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/23");

  script_cve_id("CVE-2022-21540", "CVE-2022-21541", "CVE-2022-34169");

  script_name(english:"Oracle Linux 8 : java-1.8.0-openjdk (ELSA-2022-5696)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2022-5696 advisory.

    [1:1.8.0.342.b07-1]
    - Update to shenandoah-jdk8u342-b07
    - Update release notes for shenandoah-8u342-b07.
    - Print release file during build, which should now include a correct SOURCE value from .src-rev
    - Update tarball script with IcedTea GitHub URL and .src-rev generation
    - Use 'git apply' with patches in the tarball script to allow binary diffs
    - Remove redundant 'REPOS' variable from tarball script
    - Include script to generate bug list for release notes
    - Update tzdata requirement to 2022a to match JDK-8283350
    - Rebase FIPS patches from fips branch and simplify by using a single patch from that repository
    - * RH2036462: sun.security.pkcs11.wrapper.PKCS11.getInstance breakage
    - * RH2090378: Revert to disabling system security properties and FIPS mode support together
    - Rebase RH1648249 nss.cfg patch so it applies after the FIPS patch
    - Perform configuration changes (e.g. nss.cfg, nss.fips.cfg, tzdb.dat) in installjdk
    - Enable system security properties in the RPM (now disabled by default in the FIPS repo)
    - Improve security properties test to check both enabled and disabled behaviour
    - Run security properties test with property debugging on
    - Explicitly require crypto-policies during build and runtime for system security properties
    - Resolves: rhbz#2099911
    - Resolves: rhbz#2108564
    - Resolves: rhbz#2084648
    - Resolves: rhbz#2106506

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2022-5696.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-34169");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/07/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/07/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/07/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-1.8.0-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-1.8.0-openjdk-accessibility");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-1.8.0-openjdk-accessibility-fastdebug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-1.8.0-openjdk-accessibility-slowdebug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-1.8.0-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-1.8.0-openjdk-demo-fastdebug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-1.8.0-openjdk-demo-slowdebug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-1.8.0-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-1.8.0-openjdk-devel-fastdebug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-1.8.0-openjdk-devel-slowdebug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-1.8.0-openjdk-fastdebug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-1.8.0-openjdk-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-1.8.0-openjdk-headless-fastdebug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-1.8.0-openjdk-headless-slowdebug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-1.8.0-openjdk-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-1.8.0-openjdk-javadoc-zip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-1.8.0-openjdk-slowdebug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-1.8.0-openjdk-src");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-1.8.0-openjdk-src-fastdebug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-1.8.0-openjdk-src-slowdebug");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/local_checks_enabled");

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
    {'reference':'java-1.8.0-openjdk-1.8.0.342.b07-2.el8_6', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-1.8.0-openjdk-accessibility-1.8.0.342.b07-2.el8_6', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-1.8.0-openjdk-accessibility-fastdebug-1.8.0.342.b07-2.el8_6', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-1.8.0-openjdk-accessibility-slowdebug-1.8.0.342.b07-2.el8_6', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-1.8.0-openjdk-demo-1.8.0.342.b07-2.el8_6', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-1.8.0-openjdk-demo-fastdebug-1.8.0.342.b07-2.el8_6', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-1.8.0-openjdk-demo-slowdebug-1.8.0.342.b07-2.el8_6', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-1.8.0-openjdk-devel-1.8.0.342.b07-2.el8_6', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-1.8.0-openjdk-devel-fastdebug-1.8.0.342.b07-2.el8_6', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-1.8.0-openjdk-devel-slowdebug-1.8.0.342.b07-2.el8_6', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-1.8.0-openjdk-fastdebug-1.8.0.342.b07-2.el8_6', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-1.8.0-openjdk-headless-1.8.0.342.b07-2.el8_6', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-1.8.0-openjdk-headless-fastdebug-1.8.0.342.b07-2.el8_6', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-1.8.0-openjdk-headless-slowdebug-1.8.0.342.b07-2.el8_6', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-1.8.0-openjdk-javadoc-1.8.0.342.b07-2.el8_6', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-1.8.0-openjdk-javadoc-zip-1.8.0.342.b07-2.el8_6', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-1.8.0-openjdk-slowdebug-1.8.0.342.b07-2.el8_6', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-1.8.0-openjdk-src-1.8.0.342.b07-2.el8_6', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-1.8.0-openjdk-src-fastdebug-1.8.0.342.b07-2.el8_6', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-1.8.0-openjdk-src-slowdebug-1.8.0.342.b07-2.el8_6', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-1.8.0-openjdk-1.8.0.342.b07-2.el8_6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-1.8.0-openjdk-accessibility-1.8.0.342.b07-2.el8_6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-1.8.0-openjdk-accessibility-fastdebug-1.8.0.342.b07-2.el8_6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-1.8.0-openjdk-accessibility-slowdebug-1.8.0.342.b07-2.el8_6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-1.8.0-openjdk-demo-1.8.0.342.b07-2.el8_6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-1.8.0-openjdk-demo-fastdebug-1.8.0.342.b07-2.el8_6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-1.8.0-openjdk-demo-slowdebug-1.8.0.342.b07-2.el8_6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-1.8.0-openjdk-devel-1.8.0.342.b07-2.el8_6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-1.8.0-openjdk-devel-fastdebug-1.8.0.342.b07-2.el8_6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-1.8.0-openjdk-devel-slowdebug-1.8.0.342.b07-2.el8_6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-1.8.0-openjdk-fastdebug-1.8.0.342.b07-2.el8_6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-1.8.0-openjdk-headless-1.8.0.342.b07-2.el8_6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-1.8.0-openjdk-headless-fastdebug-1.8.0.342.b07-2.el8_6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-1.8.0-openjdk-headless-slowdebug-1.8.0.342.b07-2.el8_6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-1.8.0-openjdk-javadoc-1.8.0.342.b07-2.el8_6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-1.8.0-openjdk-javadoc-zip-1.8.0.342.b07-2.el8_6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-1.8.0-openjdk-slowdebug-1.8.0.342.b07-2.el8_6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-1.8.0-openjdk-src-1.8.0.342.b07-2.el8_6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-1.8.0-openjdk-src-fastdebug-1.8.0.342.b07-2.el8_6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-1.8.0-openjdk-src-slowdebug-1.8.0.342.b07-2.el8_6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'java-1.8.0-openjdk / java-1.8.0-openjdk-accessibility / java-1.8.0-openjdk-accessibility-fastdebug / etc');
}
