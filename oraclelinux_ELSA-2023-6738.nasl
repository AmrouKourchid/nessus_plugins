#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2023-6738.
##

include('compat.inc');

if (description)
{
  script_id(185839);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/22");

  script_cve_id("CVE-2023-22025", "CVE-2023-22081");

  script_name(english:"Oracle Linux 9 : java-21-openjdk (ELSA-2023-6738)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 9 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2023-6738 advisory.

    [1:21.0.1.0.12-2.0.1]
    - Add Oracle vendor bug URL

    [1:21.0.1.0.12-2]
    - Switch to using portable binaries built on RHEL 7
    - Sync the copy of the portable specfile with the RHEL 7 version
    - Related: RHEL-12997

    [1:21.0.1.0.12-1]
    - Update to jdk-21.0.1.0+12 (GA)
    - Update release notes to 21.0.1.0+12
    - Sync the copy of the portable specfile with the latest update
    - Update openjdk_news script to specify subdirectory last
    - Add missing discover_trees script required by openjdk_news
    - Synchronise bundled versions with 21u sources (FreeType, LCMS, HarfBuzz, libpng)
    - Sync generate_tarball.sh with 11u & 17u version
    - Update bug URL for RHEL to point to the Red Hat customer portal
    - Fix upstream release URL for OpenJDK source
    - Following JDK-8005165, class data sharing can be enabled on all JIT architectures
    - Use tapsets from the misc tarball
    - Introduce 'prelease' for the portable release versioning, to handle EA builds
    - Make sure root installation directory is created first
    - Use in-place substitution for all but the first of the tapset changes
    - Synchronise runtime and buildtime tzdata requirements
    - Remove ghosts for binaries not in java-21-openjdk (pack200, rmid, unpack200)
    - Add missing jfr, jpackage and jwebserver alternative ghosts
    - Move jcmd to the headless package
    - Revert alt-java binary location to being within the JDK tree
    - Resolves: RHEL-12997
    - Resolves: RHEL-14954
    - Resolves: RHEL-14962
    - Resolves: RHEL-14958
    - Related: RHEL-14946
    - Resolves: RHEL-14959
    - Resolves: RHEL-14948

    [1:21.0.1.0.12-1]
    - Exclude classes_nocoops.jsa on i686 and arm32
    - Related: RHEL-14946

    [1:21.0.1.0.12-1]
    - Fix packaging of CDS archives
    - Resolves: RHEL-14946

    [1:21.0.0.0.35-2]
    - Update documentation (README.md)
    - Replace alt-java patch with a binary separate from the JDK
    - Drop stale patches that are of little use any more:
    - * nss.cfg has been disabled since early PKCS11 work and long superseded by FIPS work
    - * No accessibility subpackage to warrant RH1648242 & RH1648644 patches any more
    - * No use of system libjpeg turbo to warrant RH649512 patch any more
    - Replace RH1684077 pcsc-lite-libs patch with better JDK-8009550 fix being upstreamed
    - Adapt alt-java test to new binary where there is always a set_speculation function
    - Related: RHEL-12997

    [1:21.0.0.0.35-1]
    - Update to jdk-21.0.0+35
    - Update system crypto policy & FIPS patch from new fips-21u tree
    - Update generate_tarball.sh to sync with upstream vanilla script inc. no more ECC removal
    - Drop fakefeaturever now it is no longer needed
    - Change top_level_dir_name to use the VCS tag, matching new upstream release style tarball
    - Use upstream release URL for OpenJDK source
    - Re-enable tzdata tests now we are on the latest JDK and things are back in sync
    - Install jaxp.properties introduced by JDK-8303530
    - Install lible.so introduced by JDK-8306983
    - Related: RHEL-12997

    [1:21.0.0.0.35-1]
    - Replace smoke test files used in the staticlibs test, as fdlibm was removed by JDK-8303798
    - Related: RHEL-12997

    [1:20.0.0.0.36-1]
    - Update to jdk-20.0.2+9
    - Update release notes to 20.0.2+9
    - Update system crypto policy & FIPS patch from new fips-20u tree
    - Update generate_tarball.sh ICEDTEA_VERSION
    - Update CLDR reference data following update to 42 (Rocky Mountain-Normalzeit => Rocky-Mountain-
    Normalzeit)
    - Related: RHEL-12997

    [1:20.0.0.0.36-1]
    - Dropped JDK-8295447, JDK-8296239 & JDK-8299439 patches now upstream
    - Adapted rh1750419-redhat_alt_java.patch
    - Related: RHEL-12997

    [1:19.0.1.0.10-1]
    - Update to jdk-19.0.2 release
    - Update release notes to 19.0.2
    - Rebase FIPS patches from fips-19u branch
    - Remove references to sample directory removed by JDK-8284999
    - Add local patch JDK-8295447 (javac NPE) which was accepted into 19u upstream but not in the GA tag
    - Add local patches for JDK-8296239 & JDK-8299439 (Croatia Euro update) which are present in 8u, 11u & 17u
    releases
    - Related: RHEL-12997

    [1:18.0.2.0.9-1]
    - Update to jdk-18.0.2 release
    - Support JVM variant zero following JDK-8273494 no longer installing Zero's libjvm.so in the server
    directory
    - Rebase FIPS patches from fips-18u branch
    - Rebase RH1648249 nss.cfg patch so it applies after the FIPS patch
    - Drop now unused fresh_libjvm, build_hotspot_first, bootjdk and buildjdkver variables, as we don't build
    a JDK here
    - Drop tzdata patches added for 17.0.7 which will eventually appear in the upstream tarball when we reach
    OpenJDK 21
    - Disable tzdata tests until we are on the latest JDK and things are back in sync
    - Use empty nss.fips.cfg until it is again available via the FIPS patch
    - Related: RHEL-12997

    [1:18.0.2.0.9-1]
    - Update to ea version of jdk18
    - Add new slave jwebserver and corresponding manpage
    - Adjust rh1684077-openjdk_should_depend_on_pcsc-lite-libs_instead_of_pcsc-lite-devel.patch
    - Related: RHEL-12997

    [1:18.0.2.0.9-1]
    - Add javaver- and origin-specific javadoc and javadoczip alternatives.
    - Related: RHEL-12997

    [1:17.0.7.0.7-4]
    - Add files missed by centpkg import.
    - Related: rhbz#2192748

    [1:17.0.7.0.7-3]
    - Create java-21-openjdk package based on java-17-openjdk
    - Related: rhbz#2192748

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2023-6738.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-22025");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/10/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/11/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/11/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:linux:9:3:appstream_base");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:linux:9::appstream");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:linux:9::codeready_builder");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-21-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-21-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-21-openjdk-demo-fastdebug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-21-openjdk-demo-slowdebug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-21-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-21-openjdk-devel-fastdebug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-21-openjdk-devel-slowdebug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-21-openjdk-fastdebug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-21-openjdk-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-21-openjdk-headless-fastdebug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-21-openjdk-headless-slowdebug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-21-openjdk-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-21-openjdk-javadoc-zip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-21-openjdk-jmods");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-21-openjdk-jmods-fastdebug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-21-openjdk-jmods-slowdebug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-21-openjdk-slowdebug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-21-openjdk-src");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-21-openjdk-src-fastdebug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-21-openjdk-src-slowdebug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-21-openjdk-static-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-21-openjdk-static-libs-fastdebug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-21-openjdk-static-libs-slowdebug");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^9([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 9', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);

var pkgs = [
    {'reference':'java-21-openjdk-21.0.1.0.12-2.0.1.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-21-openjdk-demo-21.0.1.0.12-2.0.1.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-21-openjdk-demo-fastdebug-21.0.1.0.12-2.0.1.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-21-openjdk-demo-slowdebug-21.0.1.0.12-2.0.1.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-21-openjdk-devel-21.0.1.0.12-2.0.1.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-21-openjdk-devel-fastdebug-21.0.1.0.12-2.0.1.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-21-openjdk-devel-slowdebug-21.0.1.0.12-2.0.1.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-21-openjdk-fastdebug-21.0.1.0.12-2.0.1.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-21-openjdk-headless-21.0.1.0.12-2.0.1.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-21-openjdk-headless-fastdebug-21.0.1.0.12-2.0.1.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-21-openjdk-headless-slowdebug-21.0.1.0.12-2.0.1.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-21-openjdk-javadoc-21.0.1.0.12-2.0.1.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-21-openjdk-javadoc-zip-21.0.1.0.12-2.0.1.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-21-openjdk-jmods-21.0.1.0.12-2.0.1.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-21-openjdk-jmods-fastdebug-21.0.1.0.12-2.0.1.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-21-openjdk-jmods-slowdebug-21.0.1.0.12-2.0.1.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-21-openjdk-slowdebug-21.0.1.0.12-2.0.1.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-21-openjdk-src-21.0.1.0.12-2.0.1.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-21-openjdk-src-fastdebug-21.0.1.0.12-2.0.1.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-21-openjdk-src-slowdebug-21.0.1.0.12-2.0.1.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-21-openjdk-static-libs-21.0.1.0.12-2.0.1.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-21-openjdk-static-libs-fastdebug-21.0.1.0.12-2.0.1.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-21-openjdk-static-libs-slowdebug-21.0.1.0.12-2.0.1.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-21-openjdk-21.0.1.0.12-2.0.1.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-21-openjdk-demo-21.0.1.0.12-2.0.1.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-21-openjdk-demo-fastdebug-21.0.1.0.12-2.0.1.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-21-openjdk-demo-slowdebug-21.0.1.0.12-2.0.1.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-21-openjdk-devel-21.0.1.0.12-2.0.1.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-21-openjdk-devel-fastdebug-21.0.1.0.12-2.0.1.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-21-openjdk-devel-slowdebug-21.0.1.0.12-2.0.1.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-21-openjdk-fastdebug-21.0.1.0.12-2.0.1.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-21-openjdk-headless-21.0.1.0.12-2.0.1.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-21-openjdk-headless-fastdebug-21.0.1.0.12-2.0.1.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-21-openjdk-headless-slowdebug-21.0.1.0.12-2.0.1.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-21-openjdk-javadoc-21.0.1.0.12-2.0.1.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-21-openjdk-javadoc-zip-21.0.1.0.12-2.0.1.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-21-openjdk-jmods-21.0.1.0.12-2.0.1.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-21-openjdk-jmods-fastdebug-21.0.1.0.12-2.0.1.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-21-openjdk-jmods-slowdebug-21.0.1.0.12-2.0.1.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-21-openjdk-slowdebug-21.0.1.0.12-2.0.1.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-21-openjdk-src-21.0.1.0.12-2.0.1.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-21-openjdk-src-fastdebug-21.0.1.0.12-2.0.1.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-21-openjdk-src-slowdebug-21.0.1.0.12-2.0.1.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-21-openjdk-static-libs-21.0.1.0.12-2.0.1.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-21-openjdk-static-libs-fastdebug-21.0.1.0.12-2.0.1.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-21-openjdk-static-libs-slowdebug-21.0.1.0.12-2.0.1.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'}
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
      severity   : SECURITY_NOTE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'java-21-openjdk / java-21-openjdk-demo / java-21-openjdk-demo-fastdebug / etc');
}
