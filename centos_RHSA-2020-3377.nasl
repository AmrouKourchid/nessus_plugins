#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2020:3377.
##

include('compat.inc');

if (description)
{
  script_id(208631);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/09");

  script_cve_id(
    "CVE-2020-6510",
    "CVE-2020-6511",
    "CVE-2020-6512",
    "CVE-2020-6513",
    "CVE-2020-6514",
    "CVE-2020-6515",
    "CVE-2020-6516",
    "CVE-2020-6517",
    "CVE-2020-6518",
    "CVE-2020-6519",
    "CVE-2020-6520",
    "CVE-2020-6521",
    "CVE-2020-6522",
    "CVE-2020-6523",
    "CVE-2020-6524",
    "CVE-2020-6525",
    "CVE-2020-6526",
    "CVE-2020-6527",
    "CVE-2020-6528",
    "CVE-2020-6529",
    "CVE-2020-6530",
    "CVE-2020-6531",
    "CVE-2020-6532",
    "CVE-2020-6533",
    "CVE-2020-6534",
    "CVE-2020-6535",
    "CVE-2020-6536",
    "CVE-2020-6537",
    "CVE-2020-6538",
    "CVE-2020-6539",
    "CVE-2020-6540",
    "CVE-2020-6541"
  );
  script_xref(name:"RHSA", value:"2020:3377");

  script_name(english:"CentOS 6 : chromium-browser (RHSA-2020:3377)");

  script_set_attribute(attribute:"synopsis", value:
"The remote CentOS Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote CentOS Linux 6 host has a package installed that is affected by multiple vulnerabilities as referenced in the
RHSA-2020:3377 advisory.

  - Heap buffer overflow in background fetch in Google Chrome prior to 84.0.4147.89 allowed a remote attacker
    to potentially exploit heap corruption via a crafted HTML page. (CVE-2020-6510)

  - Information leak in content security policy in Google Chrome prior to 84.0.4147.89 allowed a remote
    attacker to leak cross-origin data via a crafted HTML page. (CVE-2020-6511)

  - Type Confusion in V8 in Google Chrome prior to 84.0.4147.89 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (CVE-2020-6512, CVE-2020-6533)

  - Heap buffer overflow in PDFium in Google Chrome prior to 84.0.4147.89 allowed a remote attacker to
    potentially exploit heap corruption via a crafted PDF file. (CVE-2020-6513)

  - Inappropriate implementation in WebRTC in Google Chrome prior to 84.0.4147.89 allowed an attacker in a
    privileged network position to potentially exploit heap corruption via a crafted SCTP stream.
    (CVE-2020-6514)

  - Use after free in tab strip in Google Chrome prior to 84.0.4147.89 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (CVE-2020-6515)

  - Policy bypass in CORS in Google Chrome prior to 84.0.4147.89 allowed a remote attacker to leak cross-
    origin data via a crafted HTML page. (CVE-2020-6516)

  - Heap buffer overflow in history in Google Chrome prior to 84.0.4147.89 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (CVE-2020-6517)

  - Use after free in developer tools in Google Chrome prior to 84.0.4147.89 allowed a remote attacker who had
    convinced the user to use developer tools to potentially exploit heap corruption via a crafted HTML page.
    (CVE-2020-6518)

  - Policy bypass in CSP in Google Chrome prior to 84.0.4147.89 allowed a remote attacker to bypass content
    security policy via a crafted HTML page. (CVE-2020-6519)

  - Buffer overflow in Skia in Google Chrome prior to 84.0.4147.89 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (CVE-2020-6520)

  - Side-channel information leakage in autofill in Google Chrome prior to 84.0.4147.89 allowed a remote
    attacker to obtain potentially sensitive information from process memory via a crafted HTML page.
    (CVE-2020-6521)

  - Inappropriate implementation in external protocol handlers in Google Chrome prior to 84.0.4147.89 allowed
    a remote attacker to potentially perform a sandbox escape via a crafted HTML page. (CVE-2020-6522)

  - Out of bounds write in Skia in Google Chrome prior to 84.0.4147.89 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (CVE-2020-6523)

  - Heap buffer overflow in WebAudio in Google Chrome prior to 84.0.4147.89 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (CVE-2020-6524)

  - Heap buffer overflow in Skia in Google Chrome prior to 84.0.4147.89 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (CVE-2020-6525)

  - Inappropriate implementation in iframe sandbox in Google Chrome prior to 84.0.4147.89 allowed a remote
    attacker to bypass navigation restrictions via a crafted HTML page. (CVE-2020-6526)

  - Insufficient policy enforcement in CSP in Google Chrome prior to 84.0.4147.89 allowed a remote attacker to
    bypass content security policy via a crafted HTML page. (CVE-2020-6527)

  - Incorrect security UI in basic auth in Google Chrome on iOS prior to 84.0.4147.89 allowed a remote
    attacker to spoof the contents of the Omnibox (URL bar) via a crafted HTML page. (CVE-2020-6528)

  - Inappropriate implementation in WebRTC in Google Chrome prior to 84.0.4147.89 allowed an attacker in a
    privileged network position to leak cross-origin data via a crafted HTML page. (CVE-2020-6529)

  - Out of bounds memory access in developer tools in Google Chrome prior to 84.0.4147.89 allowed an attacker
    who convinced a user to install a malicious extension to potentially exploit heap corruption via a crafted
    Chrome Extension. (CVE-2020-6530)

  - Side-channel information leakage in scroll to text in Google Chrome prior to 84.0.4147.89 allowed a remote
    attacker to leak cross-origin data via a crafted HTML page. (CVE-2020-6531)

  - Use after free in SCTP in Google Chrome prior to 84.0.4147.105 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (CVE-2020-6532)

  - Heap buffer overflow in WebRTC in Google Chrome prior to 84.0.4147.89 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (CVE-2020-6534)

  - Insufficient data validation in WebUI in Google Chrome prior to 84.0.4147.89 allowed a remote attacker who
    had compromised the renderer process to inject scripts or HTML into a privileged page via a crafted HTML
    page. (CVE-2020-6535)

  - Incorrect security UI in PWAs in Google Chrome prior to 84.0.4147.89 allowed a remote attacker who had
    persuaded the user to install a PWA to spoof the contents of the Omnibox (URL bar) via a crafted PWA.
    (CVE-2020-6536)

  - Type confusion in V8 in Google Chrome prior to 84.0.4147.105 allowed a remote attacker to execute
    arbitrary code inside a sandbox via a crafted HTML page. (CVE-2020-6537)

  - Inappropriate implementation in WebView in Google Chrome on Android prior to 84.0.4147.105 allowed a
    remote attacker to leak cross-origin data via a crafted HTML page. (CVE-2020-6538)

  - Use after free in CSS in Google Chrome prior to 84.0.4147.105 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (CVE-2020-6539)

  - Buffer overflow in Skia in Google Chrome prior to 84.0.4147.105 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (CVE-2020-6540)

  - Use after free in WebUSB in Google Chrome prior to 84.0.4147.105 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (CVE-2020-6541)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2020:3377");
  script_set_attribute(attribute:"solution", value:
"Update the affected chromium-browser package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-6524");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-6522");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"vendor_severity", value:"Critical");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/08/10");
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
    {'reference':'chromium-browser-84.0.4147.105-2.el6_10', 'cpu':'x86_64', 'release':'CentOS-6', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE}
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
      severity   : SECURITY_HOLE,
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
