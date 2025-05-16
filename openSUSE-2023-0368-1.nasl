#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2023:0368-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(185711);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/16");

  script_cve_id(
    "CVE-2023-5480",
    "CVE-2023-5482",
    "CVE-2023-5849",
    "CVE-2023-5850",
    "CVE-2023-5851",
    "CVE-2023-5852",
    "CVE-2023-5853",
    "CVE-2023-5854",
    "CVE-2023-5855",
    "CVE-2023-5856",
    "CVE-2023-5857",
    "CVE-2023-5858",
    "CVE-2023-5859",
    "CVE-2023-5996"
  );

  script_name(english:"openSUSE 15 Security Update : chromium (openSUSE-SU-2023:0368-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote openSUSE 15 host has packages installed that are affected by multiple vulnerabilities as referenced in the
openSUSE-SU-2023:0368-1 advisory.

  - Inappropriate implementation in Payments in Google Chrome prior to 119.0.6045.105 allowed a remote
    attacker to bypass XSS preventions via a malicious file. (Chromium security severity: High)
    (CVE-2023-5480)

  - Insufficient data validation in USB in Google Chrome prior to 119.0.6045.105 allowed a remote attacker to
    perform out of bounds memory access via a crafted HTML page. (Chromium security severity: High)
    (CVE-2023-5482)

  - Integer overflow in USB in Google Chrome prior to 119.0.6045.105 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (Chromium security severity: High) (CVE-2023-5849)

  - Incorrect security UI in Downloads in Google Chrome prior to 119.0.6045.105 allowed a remote attacker to
    perform domain spoofing via a crafted domain name. (Chromium security severity: Medium) (CVE-2023-5850)

  - Inappropriate implementation in Downloads in Google Chrome prior to 119.0.6045.105 allowed a remote
    attacker to obfuscate security UI via a crafted HTML page. (Chromium security severity: Medium)
    (CVE-2023-5851)

  - Use after free in Printing in Google Chrome prior to 119.0.6045.105 allowed a remote attacker who
    convinced a user to engage in specific UI gestures to potentially exploit heap corruption via specific UI
    gestures. (Chromium security severity: Medium) (CVE-2023-5852)

  - Incorrect security UI in Downloads in Google Chrome prior to 119.0.6045.105 allowed a remote attacker to
    obfuscate security UI via a crafted HTML page. (Chromium security severity: Medium) (CVE-2023-5853)

  - Use after free in Profiles in Google Chrome prior to 119.0.6045.105 allowed a remote attacker who
    convinced a user to engage in specific UI gestures to potentially exploit heap corruption via specific UI
    gestures. (Chromium security severity: Medium) (CVE-2023-5854)

  - Use after free in Reading Mode in Google Chrome prior to 119.0.6045.105 allowed a remote attacker who
    convinced a user to engage in specific UI gestures to potentially exploit heap corruption via specific UI
    gestures. (Chromium security severity: Medium) (CVE-2023-5855)

  - Use after free in Side Panel in Google Chrome prior to 119.0.6045.105 allowed a remote attacker who
    convinced a user to engage in specific UI gestures to potentially exploit heap corruption via a crafted
    HTML page. (Chromium security severity: Medium) (CVE-2023-5856)

  - Inappropriate implementation in Downloads in Google Chrome prior to 119.0.6045.105 allowed a remote
    attacker to potentially execute arbitrary code via a malicious file. (Chromium security severity: Medium)
    (CVE-2023-5857)

  - Inappropriate implementation in WebApp Provider in Google Chrome prior to 119.0.6045.105 allowed a remote
    attacker to obfuscate security UI via a crafted HTML page. (Chromium security severity: Low)
    (CVE-2023-5858)

  - Incorrect security UI in Picture In Picture in Google Chrome prior to 119.0.6045.105 allowed a remote
    attacker to perform domain spoofing via a crafted local HTML page. (Chromium security severity: Low)
    (CVE-2023-5859)

  - Use after free in WebAudio in Google Chrome prior to 119.0.6045.123 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)
    (CVE-2023-5996)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1216783");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1216978");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/KD6QFFZ2QOOLMG34Z7LCSOIITI7H7NZS/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3efcdfd3");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-5480");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-5482");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-5849");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-5850");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-5851");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-5852");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-5853");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-5854");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-5855");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-5856");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-5857");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-5858");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-5859");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-5996");
  script_set_attribute(attribute:"solution", value:
"Update the affected chromedriver, chromium and / or gn packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-5996");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/10/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/11/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/11/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromedriver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gn");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.5");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/SuSE/release');
if (isnull(os_release) || os_release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, 'openSUSE');
var _os_ver = pregmatch(pattern: "^SUSE([\d.]+)", string:os_release);
if (isnull(_os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'openSUSE');
_os_ver = _os_ver[1];
if (os_release !~ "^(SUSE15\.4|SUSE15\.5)$") audit(AUDIT_OS_RELEASE_NOT, 'openSUSE', '15.4 / 15.5', os_release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'openSUSE ' + _os_ver, cpu);

var pkgs = [
    {'reference':'chromedriver-119.0.6045.123-bp155.2.55.1', 'cpu':'aarch64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'chromedriver-119.0.6045.123-bp155.2.55.1', 'cpu':'x86_64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'chromedriver-119.0.6045.123-bp155.2.55.1', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'chromedriver-119.0.6045.123-bp155.2.55.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'chromium-119.0.6045.123-bp155.2.55.1', 'cpu':'aarch64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'chromium-119.0.6045.123-bp155.2.55.1', 'cpu':'x86_64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'chromium-119.0.6045.123-bp155.2.55.1', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'chromium-119.0.6045.123-bp155.2.55.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gn-0.20231023-bp155.5.3.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gn-0.20231023-bp155.5.3.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var _cpu = NULL;
  var rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && _release) {
    if (rpm_check(release:_release, cpu:_cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'chromedriver / chromium / gn');
}
