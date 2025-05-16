#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2023:0249-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(181649);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/09/21");

  script_cve_id(
    "CVE-2023-4900",
    "CVE-2023-4901",
    "CVE-2023-4902",
    "CVE-2023-4903",
    "CVE-2023-4904",
    "CVE-2023-4905",
    "CVE-2023-4906",
    "CVE-2023-4907",
    "CVE-2023-4908",
    "CVE-2023-4909"
  );

  script_name(english:"openSUSE 15 Security Update : chromium (openSUSE-SU-2023:0249-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote openSUSE 15 host has packages installed that are affected by multiple vulnerabilities as referenced in the
openSUSE-SU-2023:0249-1 advisory.

  - Inappropriate implementation in Custom Tabs in Google Chrome on Android prior to 117.0.5938.62 allowed a
    remote attacker to obfuscate a permission prompt via a crafted HTML page. (Chromium security severity:
    Medium) (CVE-2023-4900)

  - Inappropriate implementation in Prompts in Google Chrome prior to 117.0.5938.62 allowed a remote attacker
    to potentially spoof security UI via a crafted HTML page. (Chromium security severity: Medium)
    (CVE-2023-4901)

  - Inappropriate implementation in Input in Google Chrome prior to 117.0.5938.62 allowed a remote attacker to
    spoof security UI via a crafted HTML page. (Chromium security severity: Medium) (CVE-2023-4902)

  - Inappropriate implementation in Custom Mobile Tabs in Google Chrome on Android prior to 117.0.5938.62
    allowed a remote attacker to spoof security UI via a crafted HTML page. (Chromium security severity:
    Medium) (CVE-2023-4903)

  - Insufficient policy enforcement in Downloads in Google Chrome prior to 117.0.5938.62 allowed a remote
    attacker to bypass Enterprise policy restrictions via a crafted download. (Chromium security severity:
    Medium) (CVE-2023-4904)

  - Inappropriate implementation in Prompts in Google Chrome prior to 117.0.5938.62 allowed a remote attacker
    to spoof security UI via a crafted HTML page. (Chromium security severity: Medium) (CVE-2023-4905)

  - Insufficient policy enforcement in Autofill in Google Chrome prior to 117.0.5938.62 allowed a remote
    attacker to bypass Autofill restrictions via a crafted HTML page. (Chromium security severity: Low)
    (CVE-2023-4906)

  - Inappropriate implementation in Intents in Google Chrome on Android prior to 117.0.5938.62 allowed a
    remote attacker to obfuscate security UI via a crafted HTML page. (Chromium security severity: Low)
    (CVE-2023-4907)

  - Inappropriate implementation in Picture in Picture in Google Chrome prior to 117.0.5938.62 allowed a
    remote attacker to spoof security UI via a crafted HTML page. (Chromium security severity: Low)
    (CVE-2023-4908)

  - Inappropriate implementation in Interstitials in Google Chrome prior to 117.0.5938.62 allowed a remote
    attacker to obfuscate security UI via a crafted HTML page. (Chromium security severity: Low)
    (CVE-2023-4909)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1215279");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/MN26MICUYGDWUEPBBIGFRKH4W75UL6M2/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e475ffe8");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-4900");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-4901");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-4902");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-4903");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-4904");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-4905");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-4906");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-4907");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-4908");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-4909");
  script_set_attribute(attribute:"solution", value:
"Update the affected chromedriver and / or chromium packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-4909");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/09/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/09/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/09/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromedriver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium");
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
    {'reference':'chromedriver-117.0.5938.88-bp155.2.37.1', 'cpu':'aarch64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'chromedriver-117.0.5938.88-bp155.2.37.1', 'cpu':'x86_64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'chromedriver-117.0.5938.88-bp155.2.37.1', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'chromedriver-117.0.5938.88-bp155.2.37.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'chromium-117.0.5938.88-bp155.2.37.1', 'cpu':'aarch64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'chromium-117.0.5938.88-bp155.2.37.1', 'cpu':'x86_64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'chromium-117.0.5938.88-bp155.2.37.1', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'chromium-117.0.5938.88-bp155.2.37.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE}
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
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'chromedriver / chromium');
}
