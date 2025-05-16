#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2023:0251-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(181834);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/09/24");

  script_cve_id(
    "CVE-2023-2312",
    "CVE-2023-3420",
    "CVE-2023-3421",
    "CVE-2023-3422",
    "CVE-2023-4068",
    "CVE-2023-4069",
    "CVE-2023-4070",
    "CVE-2023-4071",
    "CVE-2023-4072",
    "CVE-2023-4073",
    "CVE-2023-4074",
    "CVE-2023-4075",
    "CVE-2023-4076",
    "CVE-2023-4077",
    "CVE-2023-4078",
    "CVE-2023-4349",
    "CVE-2023-4350",
    "CVE-2023-4351",
    "CVE-2023-4352",
    "CVE-2023-4353",
    "CVE-2023-4354",
    "CVE-2023-4355",
    "CVE-2023-4356",
    "CVE-2023-4357",
    "CVE-2023-4358",
    "CVE-2023-4359",
    "CVE-2023-4360",
    "CVE-2023-4361",
    "CVE-2023-4362",
    "CVE-2023-4363",
    "CVE-2023-4364",
    "CVE-2023-4365",
    "CVE-2023-4366",
    "CVE-2023-4367",
    "CVE-2023-4368",
    "CVE-2023-4572"
  );

  script_name(english:"openSUSE 15 Security Update : opera (openSUSE-SU-2023:0251-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote openSUSE 15 host has a package installed that is affected by multiple vulnerabilities as referenced in the
openSUSE-SU-2023:0251-1 advisory.

  - Use after free in Offline in Google Chrome on Android prior to 116.0.5845.96 allowed a remote attacker who
    had compromised the renderer process to potentially exploit heap corruption via a crafted HTML page.
    (Chromium security severity: High) (CVE-2023-2312)

  - Type Confusion in V8 in Google Chrome prior to 114.0.5735.198 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (Chromium security severity: High) (CVE-2023-3420)

  - Use after free in Media in Google Chrome prior to 114.0.5735.198 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (Chromium security severity: High) (CVE-2023-3421)

  - Use after free in Guest View in Google Chrome prior to 114.0.5735.198 allowed an attacker who convinced a
    user to install a malicious extension to potentially exploit heap corruption via a crafted HTML page.
    (Chromium security severity: High) (CVE-2023-3422)

  - Type Confusion in V8 in Google Chrome prior to 115.0.5790.170 allowed a remote attacker to perform
    arbitrary read/write via a crafted HTML page. (Chromium security severity: High) (CVE-2023-4068,
    CVE-2023-4070)

  - Type Confusion in V8 in Google Chrome prior to 115.0.5790.170 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (Chromium security severity: High) (CVE-2023-4069)

  - Heap buffer overflow in Visuals in Google Chrome prior to 115.0.5790.170 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)
    (CVE-2023-4071)

  - Out of bounds read and write in WebGL in Google Chrome prior to 115.0.5790.170 allowed a remote attacker
    to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)
    (CVE-2023-4072)

  - Out of bounds memory access in ANGLE in Google Chrome on Mac prior to 115.0.5790.170 allowed a remote
    attacker to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity:
    High) (CVE-2023-4073)

  - Use after free in Blink Task Scheduling in Google Chrome prior to 115.0.5790.170 allowed a remote attacker
    to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)
    (CVE-2023-4074)

  - Use after free in Cast in Google Chrome prior to 115.0.5790.170 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (Chromium security severity: High) (CVE-2023-4075)

  - Use after free in WebRTC in Google Chrome prior to 115.0.5790.170 allowed a remote attacker to potentially
    exploit heap corruption via a crafted WebRTC session. (Chromium security severity: High) (CVE-2023-4076)

  - Insufficient data validation in Extensions in Google Chrome prior to 115.0.5790.170 allowed an attacker
    who convinced a user to install a malicious extension to inject scripts or HTML into a privileged page via
    a crafted Chrome Extension. (Chromium security severity: Medium) (CVE-2023-4077)

  - Inappropriate implementation in Extensions in Google Chrome prior to 115.0.5790.170 allowed an attacker
    who convinced a user to install a malicious extension to inject scripts or HTML into a privileged page via
    a crafted Chrome Extension. (Chromium security severity: Medium) (CVE-2023-4078)

  - Use after free in Device Trust Connectors in Google Chrome prior to 116.0.5845.96 allowed a remote
    attacker to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity:
    High) (CVE-2023-4349)

  - Inappropriate implementation in Fullscreen in Google Chrome on Android prior to 116.0.5845.96 allowed a
    remote attacker to potentially spoof the contents of the Omnibox (URL bar) via a crafted HTML page.
    (Chromium security severity: High) (CVE-2023-4350)

  - Use after free in Network in Google Chrome prior to 116.0.5845.96 allowed a remote attacker who has
    elicited a browser shutdown to potentially exploit heap corruption via a crafted HTML page. (Chromium
    security severity: High) (CVE-2023-4351)

  - Type confusion in V8 in Google Chrome prior to 116.0.5845.96 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (Chromium security severity: High) (CVE-2023-4352)

  - Heap buffer overflow in ANGLE in Google Chrome prior to 116.0.5845.96 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)
    (CVE-2023-4353)

  - Heap buffer overflow in Skia in Google Chrome prior to 116.0.5845.96 allowed a remote attacker who had
    compromised the renderer process to potentially exploit heap corruption via a crafted HTML page. (Chromium
    security severity: High) (CVE-2023-4354)

  - Out of bounds memory access in V8 in Google Chrome prior to 116.0.5845.96 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)
    (CVE-2023-4355)

  - Use after free in Audio in Google Chrome prior to 116.0.5845.96 allowed a remote attacker who has
    convinced a user to engage in specific UI interaction to potentially exploit heap corruption via a crafted
    HTML page. (Chromium security severity: Medium) (CVE-2023-4356)

  - Insufficient validation of untrusted input in XML in Google Chrome prior to 116.0.5845.96 allowed a remote
    attacker to bypass file access restrictions via a crafted HTML page. (Chromium security severity: Medium)
    (CVE-2023-4357)

  - Use after free in DNS in Google Chrome prior to 116.0.5845.96 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (Chromium security severity: Medium) (CVE-2023-4358)

  - Inappropriate implementation in App Launcher in Google Chrome on iOS prior to 116.0.5845.96 allowed a
    remote attacker to potentially spoof elements of the security UI via a crafted HTML page. (Chromium
    security severity: Medium) (CVE-2023-4359)

  - Inappropriate implementation in Color in Google Chrome prior to 116.0.5845.96 allowed a remote attacker to
    obfuscate security UI via a crafted HTML page. (Chromium security severity: Medium) (CVE-2023-4360)

  - Inappropriate implementation in Autofill in Google Chrome on Android prior to 116.0.5845.96 allowed a
    remote attacker to bypass Autofill restrictions via a crafted HTML page. (Chromium security severity:
    Medium) (CVE-2023-4361)

  - Heap buffer overflow in Mojom IDL in Google Chrome prior to 116.0.5845.96 allowed a remote attacker who
    had compromised the renderer process and gained control of a WebUI process to potentially exploit heap
    corruption via a crafted HTML page. (Chromium security severity: Medium) (CVE-2023-4362)

  - Inappropriate implementation in WebShare in Google Chrome on Android prior to 116.0.5845.96 allowed a
    remote attacker to spoof the contents of a dialog URL via a crafted HTML page. (Chromium security
    severity: Medium) (CVE-2023-4363)

  - Inappropriate implementation in Permission Prompts in Google Chrome prior to 116.0.5845.96 allowed a
    remote attacker to obfuscate security UI via a crafted HTML page. (Chromium security severity: Medium)
    (CVE-2023-4364)

  - Inappropriate implementation in Fullscreen in Google Chrome prior to 116.0.5845.96 allowed a remote
    attacker to obfuscate security UI via a crafted HTML page. (Chromium security severity: Medium)
    (CVE-2023-4365)

  - Use after free in Extensions in Google Chrome prior to 116.0.5845.96 allowed an attacker who convinced a
    user to install a malicious extension to potentially exploit heap corruption via a crafted HTML page.
    (Chromium security severity: Medium) (CVE-2023-4366)

  - Insufficient policy enforcement in Extensions API in Google Chrome prior to 116.0.5845.96 allowed an
    attacker who convinced a user to install a malicious extension to bypass an enterprise policy via a
    crafted HTML page. (Chromium security severity: Medium) (CVE-2023-4367, CVE-2023-4368)

  - Use after free in MediaStream in Google Chrome prior to 116.0.5845.140 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)
    (CVE-2023-4572)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/OZ42BLWF46DJIINWQUMWAD3MX5OLXGUI/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?30e4cc01");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-2312");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-3420");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-3421");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-3422");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-4068");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-4069");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-4070");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-4071");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-4072");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-4073");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-4074");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-4075");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-4076");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-4077");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-4078");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-4349");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-4350");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-4351");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-4352");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-4353");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-4354");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-4355");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-4356");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-4357");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-4358");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-4359");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-4360");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-4361");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-4362");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-4363");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-4364");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-4365");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-4366");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-4367");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-4368");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-4572");
  script_set_attribute(attribute:"solution", value:
"Update the affected opera package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-4572");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/06/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/09/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/09/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:opera");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.4");
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
if (os_release !~ "^(SUSE15\.4)$") audit(AUDIT_OS_RELEASE_NOT, 'openSUSE', '15.4', os_release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'openSUSE ' + _os_ver, cpu);

var pkgs = [
    {'reference':'opera-102.0.4880.40-lp154.2.50.1', 'cpu':'x86_64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'opera');
}
