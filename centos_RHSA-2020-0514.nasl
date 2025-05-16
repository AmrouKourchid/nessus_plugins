#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2020:0514.
##

include('compat.inc');

if (description)
{
  script_id(208457);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/09");

  script_cve_id(
    "CVE-2019-18197",
    "CVE-2019-19880",
    "CVE-2019-19923",
    "CVE-2019-19925",
    "CVE-2019-19926",
    "CVE-2020-6381",
    "CVE-2020-6382",
    "CVE-2020-6385",
    "CVE-2020-6387",
    "CVE-2020-6388",
    "CVE-2020-6389",
    "CVE-2020-6390",
    "CVE-2020-6391",
    "CVE-2020-6392",
    "CVE-2020-6393",
    "CVE-2020-6394",
    "CVE-2020-6395",
    "CVE-2020-6396",
    "CVE-2020-6397",
    "CVE-2020-6398",
    "CVE-2020-6399",
    "CVE-2020-6400",
    "CVE-2020-6401",
    "CVE-2020-6402",
    "CVE-2020-6403",
    "CVE-2020-6404",
    "CVE-2020-6405",
    "CVE-2020-6406",
    "CVE-2020-6408",
    "CVE-2020-6409",
    "CVE-2020-6410",
    "CVE-2020-6411",
    "CVE-2020-6412",
    "CVE-2020-6413",
    "CVE-2020-6414",
    "CVE-2020-6415",
    "CVE-2020-6416",
    "CVE-2020-6417",
    "CVE-2020-6499",
    "CVE-2020-6500",
    "CVE-2020-6501",
    "CVE-2020-6502"
  );
  script_xref(name:"RHSA", value:"2020:0514");

  script_name(english:"CentOS 6 : chromium-browser (RHSA-2020:0514)");

  script_set_attribute(attribute:"synopsis", value:
"The remote CentOS Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote CentOS Linux 6 host has a package installed that is affected by multiple vulnerabilities as referenced in the
RHSA-2020:0514 advisory.

  - In xsltCopyText in transform.c in libxslt 1.1.33, a pointer variable isn't reset under certain
    circumstances. If the relevant memory area happened to be freed and reused in a certain way, a bounds
    check could fail and memory outside a buffer could be written to, or uninitialized data could be
    disclosed. (CVE-2019-18197)

  - sqlite: error mishandling because of incomplete fix of (CVE-2019-19880)

  - flattenSubquery in select.c in SQLite 3.30.1 mishandles certain uses of SELECT DISTINCT involving a LEFT
    JOIN in which the right-hand side is a view. This can cause a NULL pointer dereference (or incorrect
    results). (CVE-2019-19923)

  - zipfileUpdate in ext/misc/zipfile.c in SQLite 3.30.1 mishandles a NULL pathname during an update of a ZIP
    archive. (CVE-2019-19925)

  - multiSelect in select.c in SQLite 3.30.1 mishandles certain errors during parsing, as demonstrated by
    errors from sqlite3WindowRewrite() calls. NOTE: this vulnerability exists because of an incomplete fix for
    CVE-2019-19880. (CVE-2019-19926)

  - Integer overflow in JavaScript in Google Chrome on ChromeOS and Android prior to 80.0.3987.87 allowed a
    remote attacker to potentially exploit heap corruption via a crafted HTML page. (CVE-2020-6381)

  - Type confusion in JavaScript in Google Chrome prior to 80.0.3987.87 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (CVE-2020-6382)

  - Insufficient policy enforcement in storage in Google Chrome prior to 80.0.3987.87 allowed a remote
    attacker to bypass site isolation via a crafted HTML page. (CVE-2020-6385)

  - Out of bounds write in WebRTC in Google Chrome prior to 80.0.3987.87 allowed a remote attacker to
    potentially exploit heap corruption via a crafted video stream. (CVE-2020-6387, CVE-2020-6389)

  - Out of bounds access in WebAudio in Google Chrome prior to 80.0.3987.87 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (CVE-2020-6388)

  - Out of bounds memory access in streams in Google Chrome prior to 80.0.3987.87 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (CVE-2020-6390)

  - Insufficient validation of untrusted input in Blink in Google Chrome prior to 80.0.3987.87 allowed a local
    attacker to bypass content security policy via a crafted HTML page. (CVE-2020-6391)

  - Insufficient policy enforcement in extensions in Google Chrome prior to 80.0.3987.87 allowed an attacker
    who convinced a user to install a malicious extension to bypass navigation restrictions via a crafted
    Chrome Extension. (CVE-2020-6392)

  - Insufficient policy enforcement in Blink in Google Chrome prior to 80.0.3987.87 allowed a remote attacker
    to leak cross-origin data via a crafted HTML page. (CVE-2020-6393)

  - Insufficient policy enforcement in Blink in Google Chrome prior to 80.0.3987.87 allowed a remote attacker
    to bypass content security policy via a crafted HTML page. (CVE-2020-6394)

  - Out of bounds read in JavaScript in Google Chrome prior to 80.0.3987.87 allowed a remote attacker to
    obtain potentially sensitive information from process memory via a crafted HTML page. (CVE-2020-6395)

  - Inappropriate implementation in Skia in Google Chrome prior to 80.0.3987.87 allowed a remote attacker to
    spoof the contents of the Omnibox (URL bar) via a crafted HTML page. (CVE-2020-6396)

  - Inappropriate implementation in sharing in Google Chrome prior to 80.0.3987.87 allowed a remote attacker
    to spoof security UI via a crafted HTML page. (CVE-2020-6397)

  - Use of uninitialized data in PDFium in Google Chrome prior to 80.0.3987.87 allowed a remote attacker to
    potentially exploit heap corruption via a crafted PDF file. (CVE-2020-6398)

  - Insufficient policy enforcement in AppCache in Google Chrome prior to 80.0.3987.87 allowed a remote
    attacker to leak cross-origin data via a crafted HTML page. (CVE-2020-6399)

  - Inappropriate implementation in CORS in Google Chrome prior to 80.0.3987.87 allowed a remote attacker to
    leak cross-origin data via a crafted HTML page. (CVE-2020-6400)

  - Insufficient validation of untrusted input in Omnibox in Google Chrome prior to 80.0.3987.87 allowed a
    remote attacker to perform domain spoofing via IDN homographs via a crafted domain name. (CVE-2020-6401,
    CVE-2020-6411, CVE-2020-6412)

  - Insufficient policy enforcement in downloads in Google Chrome on OS X prior to 80.0.3987.87 allowed an
    attacker who convinced a user to install a malicious extension to execute arbitrary code via a crafted
    Chrome Extension. (CVE-2020-6402)

  - Incorrect implementation in Omnibox in Google Chrome on iOS prior to 80.0.3987.87 allowed a remote
    attacker to spoof the contents of the Omnibox (URL bar) via a crafted HTML page. (CVE-2020-6403)

  - Inappropriate implementation in Blink in Google Chrome prior to 80.0.3987.87 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (CVE-2020-6404)

  - Out of bounds read in SQLite in Google Chrome prior to 80.0.3987.87 allowed a remote attacker to obtain
    potentially sensitive information from process memory via a crafted HTML page. (CVE-2020-6405)

  - Use after free in audio in Google Chrome prior to 80.0.3987.87 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (CVE-2020-6406)

  - Insufficient policy enforcement in CORS in Google Chrome prior to 80.0.3987.87 allowed a local attacker to
    obtain potentially sensitive information via a crafted HTML page. (CVE-2020-6408)

  - Inappropriate implementation in Omnibox in Google Chrome prior to 80.0.3987.87 allowed a remote attacker
    who convinced the user to enter a URI to bypass navigation restrictions via a crafted domain name.
    (CVE-2020-6409)

  - Insufficient policy enforcement in navigation in Google Chrome prior to 80.0.3987.87 allowed a remote
    attacker to confuse the user via a crafted domain name. (CVE-2020-6410)

  - Inappropriate implementation in Blink in Google Chrome prior to 80.0.3987.87 allowed a remote attacker to
    bypass HTML validators via a crafted HTML page. (CVE-2020-6413)

  - Insufficient policy enforcement in Safe Browsing in Google Chrome prior to 80.0.3987.87 allowed a remote
    attacker to bypass navigation restrictions via a crafted HTML page. (CVE-2020-6414)

  - Inappropriate implementation in JavaScript in Google Chrome prior to 80.0.3987.87 allowed a remote
    attacker to potentially exploit heap corruption via a crafted HTML page. (CVE-2020-6415)

  - Insufficient data validation in streams in Google Chrome prior to 80.0.3987.87 allowed a remote attacker
    to potentially exploit heap corruption via a crafted HTML page. (CVE-2020-6416)

  - Inappropriate implementation in installer in Google Chrome prior to 80.0.3987.87 allowed a local attacker
    to execute arbitrary code via a crafted registry entry. (CVE-2020-6417)

  - Inappropriate implementation in AppCache in Google Chrome prior to 80.0.3987.87 allowed a remote attacker
    to bypass AppCache security restrictions via a crafted HTML page. (CVE-2020-6499)

  - Inappropriate implementation in interstitials in Google Chrome prior to 80.0.3987.87 allowed a remote
    attacker to spoof the contents of the Omnibox (URL bar) via a crafted HTML page. (CVE-2020-6500)

  - Insufficient policy enforcement in CSP in Google Chrome prior to 80.0.3987.87 allowed a remote attacker to
    bypass content security policy via a crafted HTML page. (CVE-2020-6501)

  - Incorrect implementation in permissions in Google Chrome prior to 80.0.3987.87 allowed a remote attacker
    to spoof security UI via a crafted HTML page. (CVE-2020-6502)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2020:0514");
  script_set_attribute(attribute:"solution", value:
"Update the affected chromium-browser package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-6416");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"vendor_severity", value:"Important");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/02/17");
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
    {'reference':'chromium-browser-80.0.3987.87-1.el6_10', 'cpu':'x86_64', 'release':'CentOS-6', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE}
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
