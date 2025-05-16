#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2014:1636 and 
# Oracle Linux Security Advisory ELSA-2014-1636 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(78638);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/22");

  script_cve_id(
    "CVE-2014-6457",
    "CVE-2014-6468",
    "CVE-2014-6502",
    "CVE-2014-6504",
    "CVE-2014-6506",
    "CVE-2014-6511",
    "CVE-2014-6512",
    "CVE-2014-6517",
    "CVE-2014-6519",
    "CVE-2014-6531",
    "CVE-2014-6558",
    "CVE-2014-6562"
  );
  script_bugtraq_id(
    70488,
    70523,
    70533,
    70538,
    70544,
    70548,
    70552,
    70556,
    70564,
    70567,
    70570,
    70572
  );
  script_xref(name:"RHSA", value:"2014:1636");

  script_name(english:"Oracle Linux 6 : java-1.8.0-openjdk (ELSA-2014-1636)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 6 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2014-1636 advisory.

    [1:1.8.0.25-1.b17]
    - Update to October CPU patch update.
    - Resolves: RHBZ#1148896

    [1:1.8.0.20-3.b26]
    - fixed headless (policytool moved to normal)
     - jre/bin/policytool added to not headless exclude list
    - updated aarch694 source
    - ppc64le synced from fedora
    - Resolves: rhbz#1081073

    [1:1.8.0.20-2.b26]
    - forcing build by itself (jdk8 by jdk8)
    - Resolves: rhbz#1081073

    [1:1.8.0.20-1.b26]
    - updated to u20-b26
    - adapted patch9999 enableArm64.patch
    - adapted patch100 s390-java-opts.patch
    - adapted patch102 size_t.patch
    - removed upstreamed patch  0001-PPC64LE-arch-support-in-openjdk-1.8.patch
    - adapted  system-lcms.patch
    - removed patch8 set-active-window.patch
    - removed patch9 javadoc-error-jdk-8029145.patch
    - removed patch10 javadoc-error-jdk-8037484.patch
    - removed patch99 applet-hole.patch - itw 1.5.1 is able to ive without it
    - Resolves: rhbz#1081073

    [1:1.8.0.11-19.b12]
    - fixed desktop icons
    - Icon set to java-1.8.0
    - Development removed from policy tool
    - Resolves: rhbz#1081073

    [1:1.8.0.11-18.b12]
    - fixed jstack
    - Resolves: rhbz#1081073

    [1:1.8.0.11-15.b12]
    - fixed provides/obsolates
    - Resolves: rhbz#1081073

    [1:1.8.0.11-14.b12]
    - mayor rework of specfile - sync with f21
     - accessibility kept removed
     - lua script kept unsync
     - priority and epoch kept on 0 - not included disable-doclint patch
     - kept bundled lcms
     - unused OrderWithRequires
     - used with-stdcpplib instead of with-stdc++lib
    - Resolves: rhbz#1081073

    [1:1.8.0.11-4.b13]
    - Added security patches
    - Resolves: rhbz#1081073

    [1:1.8.0.5-6.b13]
    - Removed accessibility package
     - removed patch3 java-atk-wrapper-security.patch
     - removed its files and declaration
     - removed creation of libatk-wrapper.so and java-atk-wrapper.jar symlinks
     - removed generation of accessibility.properties
    - Resolves: rhbz#1113078

    [1:1.8.0.5-5.b13]
    - priority lowered to 00000
    - Resolves: rhbz#1081073

    [1:1.8.0.5-4.b13]
    - Initial import from fedora
    - Used bundled lcms2
     - added java-1.8.0-openjdk-disable-system-lcms.patch
     - --with-lcms changed to bundled
     - removed build requirement
     - excluded removal of lcms from remove-intree-libraries.sh
    - removed --with-extra-cflags=-fno-devirtualize and --with-extra-cxxflags=-fn
    o-devirtualize---
    - added patch998, rhel6-built.patch  to
     - fool autotools
     - replace all ++ chars in autoconfig files by pp
    - --with-stdc++lib=dynamic  replaced by --with-stdcpplib=dynamic
    - Bumped release
    - Set epoch to 0
    - removed patch6, disable-doclint-by-default.patch
    - Resolves: rhbz#1081073

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2014-1636.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-6562");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2014-6504");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-1.8.0-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-1.8.0-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-1.8.0-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-1.8.0-openjdk-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-1.8.0-openjdk-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-1.8.0-openjdk-src");
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
    {'reference':'java-1.8.0-openjdk-1.8.0.25-1.b17.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-1.8.0-openjdk-demo-1.8.0.25-1.b17.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-1.8.0-openjdk-devel-1.8.0.25-1.b17.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-1.8.0-openjdk-headless-1.8.0.25-1.b17.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-1.8.0-openjdk-javadoc-1.8.0.25-1.b17.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-1.8.0-openjdk-src-1.8.0.25-1.b17.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-1.8.0-openjdk-1.8.0.25-1.b17.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-1.8.0-openjdk-demo-1.8.0.25-1.b17.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-1.8.0-openjdk-devel-1.8.0.25-1.b17.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-1.8.0-openjdk-headless-1.8.0.25-1.b17.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-1.8.0-openjdk-javadoc-1.8.0.25-1.b17.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'java-1.8.0-openjdk-src-1.8.0.25-1.b17.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'java-1.8.0-openjdk / java-1.8.0-openjdk-demo / java-1.8.0-openjdk-devel / etc');
}
