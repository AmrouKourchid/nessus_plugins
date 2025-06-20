#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2013:0751 and 
# Oracle Linux Security Advisory ELSA-2013-0751 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(68811);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/29");

  script_cve_id(
    "CVE-2013-0401",
    "CVE-2013-1488",
    "CVE-2013-1518",
    "CVE-2013-1537",
    "CVE-2013-1557",
    "CVE-2013-1558",
    "CVE-2013-1569",
    "CVE-2013-2383",
    "CVE-2013-2384",
    "CVE-2013-2415",
    "CVE-2013-2417",
    "CVE-2013-2419",
    "CVE-2013-2420",
    "CVE-2013-2421",
    "CVE-2013-2422",
    "CVE-2013-2423",
    "CVE-2013-2424",
    "CVE-2013-2426",
    "CVE-2013-2429",
    "CVE-2013-2430",
    "CVE-2013-2431",
    "CVE-2013-2436"
  );
  script_bugtraq_id(
    58504,
    58507,
    59131,
    59141,
    59153,
    59159,
    59162,
    59165,
    59166,
    59167,
    59170,
    59179,
    59184,
    59187,
    59190,
    59194,
    59206,
    59212,
    59213,
    59219,
    59228,
    59243
  );
  script_xref(name:"RHSA", value:"2013:0751");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/06/15");

  script_name(english:"Oracle Linux 6 : java-1.7.0-openjdk (ELSA-2013-0751)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 6 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2013-0751 advisory.

    [1.7.0.19-2.3.9.1.0.1.el6_4]
    - Update DISTRO_NAME in specfile

    [1.7.0.19-2.3.9.1.el6]
    - updated to updated IcedTea  2.3.9 with fix to one of security fixes
      -  fixed font glyph offset
    - Resolves: rhbz#950380

    [1.7.0.9-2.3.9.0.el6]
    - updated to IcedTea  2.3.9 with latest security patches
    - buildver sync to b19
    - rewritten java-1.7.0-openjdk-java-access-bridge-security.patch
    - Resolves: rhbz#950380

    [1.7.0.19-2.3.8.2.el6]
    - Added latest Fedora spec changes
    - Bumped release
    - Removed patch2 java-1.7.0-openjdk-java-access-bridge-idlj.patch (unapplied)
    - zlib in BuildReq restricted for  1.2.3-7 or higher
     - see https://bugzilla.redhat.com/show_bug.cgi?id=904231
    - Removed a -icedtea tag from the version
      - package have less and less connections to icedtea7
    - Added gcc-c++ build dependence. Sometimes caused troubles during rpm -bb
    - Added (Build)Requires for fontconfig and xorg-x11-fonts-Type1
      - see https://bugzilla.redhat.com/show_bug.cgi?id=721033 for details
    - Removed all fonconfig files. Fonts are now handled differently in JDK
      and those files are redundant. This is going to be usptreamed.
      - see https://bugzilla.redhat.com/show_bug.cgi?id=902227 for details
    - logging.properties marked as config(noreplace)
      - see https://bugzilla.redhat.com/show_bug.cgi?id=679180 for details
    - classes.jsa marked as ghost on full path
      - see https://bugzilla.redhat.com/show_bug.cgi?id=918172 for details
    - nss.cfg was marked as config(noreplace)
    - Add symlink to default soundfont (see 541466)
    - Resolves: rhbz#950380

    [1.7.0.9-2.3.8.1.el6]
    - Added and applied patch 116 - patch 116 rh905128-non_block_ciphers.patch
    - Added and applied patch 117 - patch 117 java-1.7.0-openjdk-nss-
    multiplePKCS11libraryInitialisationNnonCritical.patch
     - to enable handleStartupErrors = ignoreMultipleInitialisation in icedtea 2.3
    - Restorered removed nss support
    - Fixed java-1.7.0-openjdk-nss-config-{1,2} patches to be valid for icedtea 2.3.x
    - enable_nss switch to 0 - disabled
    - Resolves: rhbz#950380

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2013-0751.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-2431");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2013-2423");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Java Applet Reflection Type Confusion Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/03/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");

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

  script_copyright(english:"This script is Copyright (C) 2013-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'reference':'java-1.7.0-openjdk-1.7.0.19-2.3.9.1.0.1.el6_4', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-1.7.0-openjdk-demo-1.7.0.19-2.3.9.1.0.1.el6_4', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-1.7.0-openjdk-devel-1.7.0.19-2.3.9.1.0.1.el6_4', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-1.7.0-openjdk-javadoc-1.7.0.19-2.3.9.1.0.1.el6_4', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-1.7.0-openjdk-src-1.7.0.19-2.3.9.1.0.1.el6_4', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-1.7.0-openjdk-1.7.0.19-2.3.9.1.0.1.el6_4', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-1.7.0-openjdk-demo-1.7.0.19-2.3.9.1.0.1.el6_4', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-1.7.0-openjdk-devel-1.7.0.19-2.3.9.1.0.1.el6_4', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-1.7.0-openjdk-javadoc-1.7.0.19-2.3.9.1.0.1.el6_4', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-1.7.0-openjdk-src-1.7.0.19-2.3.9.1.0.1.el6_4', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'}
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
