#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2025:1524-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(235675);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/10");

  script_cve_id("CVE-2025-21587", "CVE-2025-30691", "CVE-2025-30698");
  script_xref(name:"SuSE", value:"SUSE-SU-2025:1524-1");

  script_name(english:"SUSE SLES12 Security Update : java-1_8_0-openjdk (SUSE-SU-2025:1524-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES12 host has packages installed that are affected by multiple vulnerabilities as referenced in
the SUSE-SU-2025:1524-1 advisory.

    Update to version jdk8u452 (icedtea-3.35.0)

    Security issues fixed:

    - CVE-2025-21587: unauthorized creation, deletion or modification of critical data through the JSSE
    component.
      (bsc#1241274)
    - CVE-2025-30691: unauthorized update, insert or delete access to a subset of Oracle Java SE data through
    the Compiler
      component. (bsc#1241275)
    - CVE-2025-30698: unauthorized access to Oracle Java SE data and unauthorized ability to cause partial DoS
    through the
      2D component. (bsc#1241276)

    Non-security issues fixed:

    - JDK-8212096: javax/net/ssl/ServerName/SSLEngineExplorerMatchedSNI.java failed intermittently due to
    SSLException:
      Tag mismatch.
    - JDK-8261020: wrong format parameter in create_emergency_chunk_path.
    - JDK-8266881: enable debug log for SSLEngineExplorerMatchedSNI.java.
    - JDK-8268457: XML Transformer outputs Unicode supplementary character incorrectly to HTML.
    - JDK-8309841: Jarsigner should print a warning if an entry is removed.
    - JDK-8337494: clarify JarInputStream behavior.
    - JDK-8339637: (tz) update Timezone Data to 2024b.
    - JDK-8339644: improve parsing of Day/Month in tzdata rules
    - JDK-8339810: clean up the code in sun.tools.jar.Main to properly close resources and use ZipFile during
    extract.
    - JDK-8340552: harden TzdbZoneRulesCompiler against missing zone names.
    - JDK-8342562: enhance Deflater operations.
    - JDK-8346587: distrust TLS server certificates anchored by Camerfirma Root CAs.
    - JDK-8347847: enhance jar file support.
    - JDK-8347965: (tz) update Timezone Data to 2025a.
    - JDK-8348211: [8u] sun/management/jmxremote/startstop/JMXStartStopTest.java fails after backport of
    JDK-8066708.
    - JDK-8350816: [8u] update TzdbZoneRulesCompiler to ignore HST/EST/MST links.
    - JDK-8352097: (tz) zone.tab update missed in 2025a backport.
    - JDK-8353433: XCG currency code not recognized in JDK 8u.

Tenable has extracted the preceding description block directly from the SUSE security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1241274");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1241275");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1241276");
  script_set_attribute(attribute:"see_also", value:"https://lists.suse.com/pipermail/sle-updates/2025-May/039194.html");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21587");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-30691");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-30698");
  script_set_attribute(attribute:"solution", value:
"Update the affected java-1_8_0-openjdk, java-1_8_0-openjdk-demo, java-1_8_0-openjdk-devel and / or java-1_8_0-openjdk-
headless packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-21587");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/04/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/05/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/05/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_8_0-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_8_0-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_8_0-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_8_0-openjdk-headless");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item("Host/SuSE/release");
if (isnull(os_release) || os_release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)\d+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES12', 'SUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLES12" && (! preg(pattern:"^(5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES12 SP5", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'java-1_8_0-openjdk-1.8.0.452-27.114.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-extended-security-release-12.5']},
    {'reference':'java-1_8_0-openjdk-demo-1.8.0.452-27.114.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-extended-security-release-12.5']},
    {'reference':'java-1_8_0-openjdk-devel-1.8.0.452-27.114.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-extended-security-release-12.5']},
    {'reference':'java-1_8_0-openjdk-headless-1.8.0.452-27.114.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-extended-security-release-12.5']},
    {'reference':'java-1_8_0-openjdk-1.8.0.452-27.114.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'java-1_8_0-openjdk-demo-1.8.0.452-27.114.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'java-1_8_0-openjdk-devel-1.8.0.452-27.114.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'java-1_8_0-openjdk-headless-1.8.0.452-27.114.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']}
];

var ltss_caveat_required = FALSE;
var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var exists_check = NULL;
  var rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && _release) {
    if (exists_check) {
      var check_flag = 0;
      foreach var check (exists_check) {
        if (!rpm_exists(release:_release, rpm:check)) continue;
        if ('ltss' >< tolower(check)) ltss_caveat_required = TRUE;
        check_flag++;
      }
      if (!check_flag) continue;
    }
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
  }
}

if (flag)
{
  var ltss_plugin_caveat = NULL;
  if(ltss_caveat_required) ltss_plugin_caveat = '\n' +
    'NOTE: This vulnerability check contains fixes that apply to\n' +
    'packages only available in SUSE Enterprise Linux Server LTSS\n' +
    'repositories. Access to these package security updates require\n' +
    'a paid SUSE LTSS subscription.\n';
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get() + ltss_plugin_caveat
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'java-1_8_0-openjdk / java-1_8_0-openjdk-demo / etc');
}
