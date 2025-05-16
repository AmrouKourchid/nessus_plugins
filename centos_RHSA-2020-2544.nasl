#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2020:2544.
##

include('compat.inc');

if (description)
{
  script_id(208592);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/09");

  script_cve_id(
    "CVE-2020-6465",
    "CVE-2020-6466",
    "CVE-2020-6467",
    "CVE-2020-6468",
    "CVE-2020-6469",
    "CVE-2020-6470",
    "CVE-2020-6471",
    "CVE-2020-6472",
    "CVE-2020-6473",
    "CVE-2020-6474",
    "CVE-2020-6475",
    "CVE-2020-6476",
    "CVE-2020-6478",
    "CVE-2020-6479",
    "CVE-2020-6480",
    "CVE-2020-6481",
    "CVE-2020-6482",
    "CVE-2020-6483",
    "CVE-2020-6484",
    "CVE-2020-6485",
    "CVE-2020-6486",
    "CVE-2020-6487",
    "CVE-2020-6488",
    "CVE-2020-6489",
    "CVE-2020-6490",
    "CVE-2020-6491",
    "CVE-2020-6493",
    "CVE-2020-6494",
    "CVE-2020-6495",
    "CVE-2020-6496"
  );
  script_xref(name:"RHSA", value:"2020:2544");

  script_name(english:"CentOS 6 : chromium-browser (RHSA-2020:2544)");

  script_set_attribute(attribute:"synopsis", value:
"The remote CentOS Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote CentOS Linux 6 host has a package installed that is affected by multiple vulnerabilities as referenced in the
RHSA-2020:2544 advisory.

  - Use after free in reader mode in Google Chrome on Android prior to 83.0.4103.61 allowed a remote attacker
    who had compromised the renderer process to potentially perform a sandbox escape via a crafted HTML page.
    (CVE-2020-6465)

  - Use after free in media in Google Chrome prior to 83.0.4103.61 allowed a remote attacker who had
    compromised the renderer process to potentially perform a sandbox escape via a crafted HTML page.
    (CVE-2020-6466)

  - Use after free in WebRTC in Google Chrome prior to 83.0.4103.61 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (CVE-2020-6467)

  - Type confusion in V8 in Google Chrome prior to 83.0.4103.61 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (CVE-2020-6468)

  - Insufficient policy enforcement in developer tools in Google Chrome prior to 83.0.4103.61 allowed an
    attacker who convinced a user to install a malicious extension to potentially perform a sandbox escape via
    a crafted Chrome Extension. (CVE-2020-6469, CVE-2020-6471)

  - Insufficient validation of untrusted input in clipboard in Google Chrome prior to 83.0.4103.61 allowed a
    local attacker to inject arbitrary scripts or HTML (UXSS) via crafted clipboard contents. (CVE-2020-6470)

  - Insufficient policy enforcement in developer tools in Google Chrome prior to 83.0.4103.61 allowed an
    attacker who convinced a user to install a malicious extension to obtain potentially sensitive information
    from process memory or disk via a crafted Chrome Extension. (CVE-2020-6472)

  - Insufficient policy enforcement in Blink in Google Chrome prior to 83.0.4103.61 allowed a remote attacker
    to obtain potentially sensitive information from process memory via a crafted HTML page. (CVE-2020-6473)

  - Use after free in Blink in Google Chrome prior to 83.0.4103.61 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (CVE-2020-6474)

  - Incorrect implementation in full screen in Google Chrome prior to 83.0.4103.61 allowed a remote attacker
    to spoof security UI via a crafted HTML page. (CVE-2020-6475)

  - Insufficient policy enforcement in tab strip in Google Chrome prior to 83.0.4103.61 allowed an attacker
    who convinced a user to install a malicious extension to bypass navigation restrictions via a crafted
    Chrome Extension. (CVE-2020-6476)

  - Inappropriate implementation in full screen in Google Chrome prior to 83.0.4103.61 allowed a remote
    attacker to spoof security UI via a crafted HTML page. (CVE-2020-6478)

  - Inappropriate implementation in sharing in Google Chrome prior to 83.0.4103.61 allowed a remote attacker
    to spoof security UI via a crafted HTML page. (CVE-2020-6479)

  - Insufficient policy enforcement in enterprise in Google Chrome prior to 83.0.4103.61 allowed a local
    attacker to bypass navigation restrictions via UI actions. (CVE-2020-6480)

  - Insufficient policy enforcement in URL formatting in Google Chrome prior to 83.0.4103.61 allowed a remote
    attacker to perform domain spoofing via a crafted domain name. (CVE-2020-6481)

  - Insufficient policy enforcement in developer tools in Google Chrome prior to 83.0.4103.61 allowed an
    attacker who convinced a user to install a malicious extension to bypass navigation restrictions via a
    crafted Chrome Extension. (CVE-2020-6482)

  - Insufficient policy enforcement in payments in Google Chrome prior to 83.0.4103.61 allowed a remote
    attacker to bypass navigation restrictions via a crafted HTML page. (CVE-2020-6483)

  - Insufficient data validation in ChromeDriver in Google Chrome prior to 83.0.4103.61 allowed a remote
    attacker to bypass navigation restrictions via a crafted request. (CVE-2020-6484)

  - Insufficient data validation in media router in Google Chrome prior to 83.0.4103.61 allowed a remote
    attacker who had compromised the renderer process to bypass navigation restrictions via a crafted HTML
    page. (CVE-2020-6485)

  - Insufficient policy enforcement in navigations in Google Chrome prior to 83.0.4103.61 allowed a remote
    attacker to bypass navigation restrictions via a crafted HTML page. (CVE-2020-6486)

  - Insufficient policy enforcement in downloads in Google Chrome prior to 83.0.4103.61 allowed a remote
    attacker to bypass navigation restrictions via a crafted HTML page. (CVE-2020-6487, CVE-2020-6488)

  - Inappropriate implementation in developer tools in Google Chrome prior to 83.0.4103.61 allowed a remote
    attacker who had convinced the user to take certain actions in developer tools to obtain potentially
    sensitive information from disk via a crafted HTML page. (CVE-2020-6489)

  - Insufficient data validation in loader in Google Chrome prior to 83.0.4103.61 allowed a remote attacker
    who had been able to write to disk to leak cross-origin data via a crafted HTML page. (CVE-2020-6490)

  - Insufficient data validation in site information in Google Chrome prior to 83.0.4103.61 allowed a remote
    attacker to spoof security UI via a crafted domain name. (CVE-2020-6491)

  - Use after free in WebAuthentication in Google Chrome prior to 83.0.4103.97 allowed a remote attacker who
    had compromised the renderer process to potentially perform a sandbox escape via a crafted HTML page.
    (CVE-2020-6493)

  - Incorrect security UI in payments in Google Chrome on Android prior to 83.0.4103.97 allowed a remote
    attacker to spoof the contents of the Omnibox (URL bar) via a crafted HTML page. (CVE-2020-6494)

  - Insufficient policy enforcement in developer tools in Google Chrome prior to 83.0.4103.97 allowed an
    attacker who convinced a user to install a malicious extension to potentially perform a sandbox escape via
    a crafted Chrome Extension. (CVE-2020-6495)

  - Use after free in payments in Google Chrome on MacOS prior to 83.0.4103.97 allowed a remote attacker to
    potentially perform a sandbox escape via a crafted HTML page. (CVE-2020-6496)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2020:2544");
  script_set_attribute(attribute:"solution", value:
"Update the affected chromium-browser package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-6496");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-6493");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"vendor_severity", value:"Important");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/15");
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
    {'reference':'chromium-browser-83.0.4103.97-1.el6_10', 'cpu':'x86_64', 'release':'CentOS-6', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE}
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
