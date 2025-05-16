#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2020:4235.
##

include('compat.inc');

if (description)
{
  script_id(208648);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/09");

  script_cve_id(
    "CVE-2020-6557",
    "CVE-2020-15967",
    "CVE-2020-15968",
    "CVE-2020-15969",
    "CVE-2020-15970",
    "CVE-2020-15971",
    "CVE-2020-15972",
    "CVE-2020-15973",
    "CVE-2020-15974",
    "CVE-2020-15975",
    "CVE-2020-15976",
    "CVE-2020-15977",
    "CVE-2020-15978",
    "CVE-2020-15979",
    "CVE-2020-15980",
    "CVE-2020-15981",
    "CVE-2020-15982",
    "CVE-2020-15983",
    "CVE-2020-15984",
    "CVE-2020-15985",
    "CVE-2020-15986",
    "CVE-2020-15987",
    "CVE-2020-15988",
    "CVE-2020-15989",
    "CVE-2020-15990",
    "CVE-2020-15991",
    "CVE-2020-15992"
  );
  script_xref(name:"RHSA", value:"2020:4235");

  script_name(english:"CentOS 6 : chromium-browser (RHSA-2020:4235)");

  script_set_attribute(attribute:"synopsis", value:
"The remote CentOS Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote CentOS Linux 6 host has a package installed that is affected by multiple vulnerabilities as referenced in the
RHSA-2020:4235 advisory.

  - Use after free in payments in Google Chrome prior to 86.0.4240.75 allowed a remote attacker to potentially
    perform a sandbox escape via a crafted HTML page. (CVE-2020-15967)

  - Use after free in Blink in Google Chrome prior to 86.0.4240.75 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (CVE-2020-15968)

  - Use after free in WebRTC in Google Chrome prior to 86.0.4240.75 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (CVE-2020-15969)

  - Use after free in NFC in Google Chrome prior to 86.0.4240.75 allowed a remote attacker who had compromised
    the renderer process to potentially perform a sandbox escape via a crafted HTML page. (CVE-2020-15970)

  - Use after free in printing in Google Chrome prior to 86.0.4240.75 allowed a remote attacker who had
    compromised the renderer process to potentially perform a sandbox escape via a crafted HTML page.
    (CVE-2020-15971)

  - Use after free in audio in Google Chrome prior to 86.0.4240.75 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (CVE-2020-15972)

  - Insufficient policy enforcement in extensions in Google Chrome prior to 86.0.4240.75 allowed an attacker
    who convinced a user to install a malicious extension to bypass same origin policy via a crafted Chrome
    Extension. (CVE-2020-15973)

  - Integer overflow in Blink in Google Chrome prior to 86.0.4240.75 allowed a remote attacker to bypass site
    isolation via a crafted HTML page. (CVE-2020-15974)

  - Integer overflow in SwiftShader in Google Chrome prior to 86.0.4240.75 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (CVE-2020-15975)

  - Use after free in WebXR in Google Chrome on Android prior to 86.0.4240.75 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (CVE-2020-15976)

  - Insufficient data validation in dialogs in Google Chrome on OS X prior to 86.0.4240.75 allowed a remote
    attacker to obtain potentially sensitive information from disk via a crafted HTML page. (CVE-2020-15977)

  - Insufficient data validation in navigation in Google Chrome on Android prior to 86.0.4240.75 allowed a
    remote attacker who had compromised the renderer process to bypass navigation restrictions via a crafted
    HTML page. (CVE-2020-15978)

  - Inappropriate implementation in V8 in Google Chrome prior to 86.0.4240.75 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (CVE-2020-15979)

  - Insufficient policy enforcement in Intents in Google Chrome on Android prior to 86.0.4240.75 allowed a
    local attacker to bypass navigation restrictions via crafted Intents. (CVE-2020-15980)

  - Out of bounds read in audio in Google Chrome prior to 86.0.4240.75 allowed a remote attacker to obtain
    potentially sensitive information from process memory via a crafted HTML page. (CVE-2020-15981)

  - Inappropriate implementation in cache in Google Chrome prior to 86.0.4240.75 allowed a remote attacker to
    obtain potentially sensitive information from process memory via a crafted HTML page. (CVE-2020-15982)

  - Insufficient data validation in webUI in Google Chrome on ChromeOS prior to 86.0.4240.75 allowed a local
    attacker to bypass content security policy via a crafted HTML page. (CVE-2020-15983)

  - Insufficient policy enforcement in Omnibox in Google Chrome on iOS prior to 86.0.4240.75 allowed a remote
    attacker to spoof the contents of the Omnibox (URL bar) via a crafted URL. (CVE-2020-15984)

  - Inappropriate implementation in Blink in Google Chrome prior to 86.0.4240.75 allowed a remote attacker to
    spoof security UI via a crafted HTML page. (CVE-2020-15985)

  - Integer overflow in media in Google Chrome prior to 86.0.4240.75 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (CVE-2020-15986)

  - Use after free in WebRTC in Google Chrome prior to 86.0.4240.75 allowed a remote attacker to potentially
    exploit heap corruption via a crafted WebRTC stream. (CVE-2020-15987)

  - Insufficient policy enforcement in downloads in Google Chrome on Windows prior to 86.0.4240.75 allowed a
    remote attacker who convinced the user to open files to execute arbitrary code via a crafted HTML page.
    (CVE-2020-15988)

  - Uninitialized data in PDFium in Google Chrome prior to 86.0.4240.75 allowed a remote attacker to obtain
    potentially sensitive information from process memory via a crafted PDF file. (CVE-2020-15989)

  - Use after free in autofill in Google Chrome prior to 86.0.4240.75 allowed a remote attacker who had
    compromised the renderer process to potentially perform a sandbox escape via a crafted HTML page.
    (CVE-2020-15990)

  - Use after free in password manager in Google Chrome prior to 86.0.4240.75 allowed a remote attacker who
    had compromised the renderer process to potentially perform a sandbox escape via a crafted HTML page.
    (CVE-2020-15991)

  - Insufficient policy enforcement in networking in Google Chrome prior to 86.0.4240.75 allowed a remote
    attacker who had compromised the renderer process to bypass same origin policy via a crafted HTML page.
    (CVE-2020-15992)

  - Inappropriate implementation in networking in Google Chrome prior to 86.0.4240.75 allowed a remote
    attacker to perform domain spoofing via a crafted HTML page. (CVE-2020-6557)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2020:4235");
  script_set_attribute(attribute:"solution", value:
"Update the affected chromium-browser package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-15992");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"vendor_severity", value:"Critical");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/10/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:chromium-browser");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CentOS Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');
include('rhel.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/CentOS/release');
if (isnull(os_release) || 'CentOS' >!< os_release) audit(AUDIT_OS_NOT, 'CentOS');
var os_ver = pregmatch(pattern: "CentOS(?: Linux)? release ([0-9]+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'CentOS');
os_ver = os_ver[1];
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '6')) audit(AUDIT_OS_NOT, 'CentOS 6.x', 'CentOS ' + os_ver);

if (!get_kb_item('Host/CentOS/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'CentOS', cpu);

var pkgs = [
    {'reference':'chromium-browser-86.0.4240.75-1.el6_10', 'cpu':'x86_64', 'release':'CentOS-6', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE}
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
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (reference && _release) {
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'chromium-browser');
}
