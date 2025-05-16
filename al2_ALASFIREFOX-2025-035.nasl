#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALASFIREFOX-2025-035.
##

include('compat.inc');

if (description)
{
  script_id(216952);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/06");

  script_cve_id(
    "CVE-2024-8900",
    "CVE-2024-9396",
    "CVE-2024-9397",
    "CVE-2024-9399",
    "CVE-2024-9400",
    "CVE-2024-10460",
    "CVE-2024-10461",
    "CVE-2024-10462",
    "CVE-2024-10464",
    "CVE-2024-10465",
    "CVE-2024-10466",
    "CVE-2024-10467",
    "CVE-2024-10468",
    "CVE-2024-10941",
    "CVE-2025-0238",
    "CVE-2025-0242",
    "CVE-2025-1009",
    "CVE-2025-1010",
    "CVE-2025-1011",
    "CVE-2025-1012",
    "CVE-2025-1013",
    "CVE-2025-1014",
    "CVE-2025-1016",
    "CVE-2025-1017"
  );
  script_xref(name:"IAVA", value:"2024-A-0279-S");
  script_xref(name:"IAVA", value:"2024-A-0607-S");
  script_xref(name:"IAVA", value:"2024-A-0695-S");
  script_xref(name:"IAVA", value:"2024-A-0769-S");
  script_xref(name:"IAVA", value:"2025-A-0009-S");
  script_xref(name:"IAVA", value:"2025-A-0079-S");

  script_name(english:"Amazon Linux 2 : firefox (ALASFIREFOX-2025-035)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of firefox installed on the remote host is prior to 128.7.0-1. It is, therefore, affected by multiple
vulnerabilities as referenced in the ALAS2FIREFOX-2025-035 advisory.

    The origin of an external protocol handler prompt could have been obscured using a data: URL within an
    `iframe`. This vulnerability affects Firefox < 132, Firefox ESR < 128.4, Thunderbird < 128.4, and
    Thunderbird < 132. (CVE-2024-10460)

    In multipart/x-mixed-replace responses, `Content-Disposition: attachment` in the response header was not
    respected and did not force a download, which could allow XSS attacks. This vulnerability affects Firefox
    < 132, Firefox ESR < 128.4, Thunderbird < 128.4, and Thunderbird < 132. (CVE-2024-10461)

    Truncation of a long URL could have allowed origin spoofing in a permission prompt. This vulnerability
    affects Firefox < 132, Firefox ESR < 128.4, Thunderbird < 128.4, and Thunderbird < 132. (CVE-2024-10462)

    Repeated writes to history interface attributes could have been used to cause a Denial of Service
    condition in the browser. This was addressed by introducing rate-limiting to this API. This vulnerability
    affects Firefox < 132, Firefox ESR < 128.4, Thunderbird < 128.4, and Thunderbird < 132. (CVE-2024-10464)

    A clipboard paste button could persist across tabs which allowed a spoofing attack. This vulnerability
    affects Firefox < 132, Firefox ESR < 128.4, Thunderbird < 128.4, and Thunderbird < 132. (CVE-2024-10465)

    By sending a specially crafted push message, a remote server could have hung the parent process, causing
    the browser to become unresponsive. This vulnerability affects Firefox < 132, Firefox ESR < 128.4,
    Thunderbird < 128.4, and Thunderbird < 132. (CVE-2024-10466)

    Memory safety bugs present in Firefox 131, Firefox ESR 128.3, and Thunderbird 128.3. Some of these bugs
    showed evidence of memory corruption and we presume that with enough effort some of these could have been
    exploited to run arbitrary code. This vulnerability affects Firefox < 132, Firefox ESR < 128.4,
    Thunderbird < 128.4, and Thunderbird < 132. (CVE-2024-10467)

    Potential race conditions in IndexedDB could have caused memory corruption, leading to a potentially
    exploitable crash. This vulnerability affects Firefox < 132 and Thunderbird < 132. (CVE-2024-10468)

    A malicious website could have included an iframe with an malformed URI resulting in a non-exploitable
    browser crash. This vulnerability affects Firefox < 126. (CVE-2024-10941)

    An attacker could write data to the user's clipboard, bypassing the user prompt, during a certain sequence
    of navigational events. This vulnerability affects Firefox < 129. (CVE-2024-8900)

    It is currently unknown if this issue is exploitable but a condition may arise where the structured clone
    of certain objects could lead to memory corruption. This vulnerability affects Firefox < 131, Firefox ESR
    < 128.3, Thunderbird < 128.3, and Thunderbird < 131. (CVE-2024-9396)

    A missing delay in directory upload UI could have made it possible for an attacker to trick a user into
    granting permission via clickjacking. This vulnerability affects Firefox < 131, Firefox ESR < 128.3,
    Thunderbird < 128.3, and Thunderbird < 131. (CVE-2024-9397)

    A website configured to initiate a specially crafted WebTransport session could crash the Firefox process
    leading to a denial of service condition. This vulnerability affects Firefox < 131, Firefox ESR < 128.3,
    Thunderbird < 128.3, and Thunderbird < 131. (CVE-2024-9399)

    A potential memory corruption vulnerability could be triggered if an attacker had the ability to trigger
    an OOM at a specific moment during JIT compilation. This vulnerability affects Firefox < 131, Firefox ESR
    < 128.3, Thunderbird < 128.3, and Thunderbird < 131. (CVE-2024-9400)

    Assuming a controlled failed memory allocation, an attacker could have caused a use-after-free, leading to
    a potentially exploitable crash. This vulnerability affects Firefox < 134, Firefox ESR < 128.6, Firefox
    ESR < 115.19, Thunderbird < 134, and Thunderbird ESR < 128.6. (CVE-2025-0238)

    Memory safety bugs present in Firefox 133, Thunderbird 133, Firefox ESR 115.18, Firefox ESR 128.5,
    Thunderbird 115.18, and Thunderbird 128.5. Some of these bugs showed evidence of memory corruption and we
    presume that with enough effort some of these could have been exploited to run arbitrary code. This
    vulnerability affects Firefox < 134, Firefox ESR < 128.6, Firefox ESR < 115.19, Thunderbird < 134, and
    Thunderbird ESR < 128.6. (CVE-2025-0242)

    An attacker could have caused a use-after-free via crafted XSLT data, leading to a potentially exploitable
    crash. This vulnerability affects Firefox < 135, Firefox ESR < 115.20, Firefox ESR < 128.7, Thunderbird <
    128.7, and Thunderbird < 135. (CVE-2025-1009)

    An attacker could have caused a use-after-free via the Custom Highlight API, leading to a potentially
    exploitable crash. This vulnerability affects Firefox < 135, Firefox ESR < 115.20, Firefox ESR < 128.7,
    Thunderbird < 128.7, and Thunderbird < 135. (CVE-2025-1010)

    A bug in WebAssembly code generation could have lead to a crash. It may have been possible for an attacker
    to leverage this to achieve code execution. This vulnerability affects Firefox < 135, Firefox ESR < 128.7,
    Thunderbird < 128.7, and Thunderbird < 135. (CVE-2025-1011)

    A race during concurrent delazification could have led to a use-after-free. This vulnerability affects
    Firefox < 135, Firefox ESR < 115.20, Firefox ESR < 128.7, Thunderbird < 128.7, and Thunderbird < 135.
    (CVE-2025-1012)

    A race condition could have led to private browsing tabs being opened in normal browsing windows. This
    could have resulted in a potential privacy leak. This vulnerability affects Firefox < 135, Firefox ESR <
    128.7, Thunderbird < 128.7, and Thunderbird < 135. (CVE-2025-1013)

    Certificate length was not properly checked when added to a certificate store. In practice only trusted
    data was processed. This vulnerability affects Firefox < 135, Firefox ESR < 128.7, Thunderbird < 128.7,
    and Thunderbird < 135. (CVE-2025-1014)

    Memory safety bugs present in Firefox 134, Thunderbird 134, Firefox ESR 115.19, Firefox ESR 128.6,
    Thunderbird 115.19, and Thunderbird 128.6. Some of these bugs showed evidence of memory corruption and we
    presume that with enough effort some of these could have been exploited to run arbitrary code. This
    vulnerability affects Firefox < 135, Firefox ESR < 115.20, Firefox ESR < 128.7, Thunderbird < 128.7, and
    Thunderbird < 135. (CVE-2025-1016)

    Memory safety bugs present in Firefox 134, Thunderbird 134, Firefox ESR 128.6, and Thunderbird 128.6. Some
    of these bugs showed evidence of memory corruption and we presume that with enough effort some of these
    could have been exploited to run arbitrary code. This vulnerability affects Firefox < 135, Firefox ESR <
    128.7, Thunderbird < 128.7, and Thunderbird < 135. (CVE-2025-1017)

Tenable has extracted the preceding description block directly from the tested product security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2/ALASFIREFOX-2025-035.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-10460.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-10461.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-10462.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-10464.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-10465.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-10466.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-10467.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-10468.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-10941.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-8900.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-9396.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-9397.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-9399.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-9400.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2025-0238.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2025-0242.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2025-1009.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2025-1010.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2025-1011.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2025-1012.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2025-1013.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2025-1014.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2025-1016.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2025-1017.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/faqs.html");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update firefox' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-1017");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/03/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:firefox-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Amazon Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AmazonLinux/release", "Host/AmazonLinux/rpm-list");

  exit(0);
}

include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var alas_release = get_kb_item("Host/AmazonLinux/release");
if (isnull(alas_release) || !strlen(alas_release)) audit(AUDIT_OS_NOT, "Amazon Linux");
var os_ver = pregmatch(pattern: "^AL(A|\d+|-\d+)", string:alas_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Amazon Linux");
os_ver = os_ver[1];
if (os_ver != "2")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux 2", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var REPOS_FOUND = TRUE;
var extras_list = get_kb_item("Host/AmazonLinux/extras_label_list");
if (isnull(extras_list)) REPOS_FOUND = FALSE;
var repository = '"amzn2extra-firefox"';
if (REPOS_FOUND && (repository >!< extras_list)) exit(0, AFFECTED_REPO_NOT_ENABLED);

var pkgs = [
    {'reference':'firefox-128.7.0-1.amzn2.0.2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE},
    {'reference':'firefox-128.7.0-1.amzn2.0.2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE},
    {'reference':'firefox-debuginfo-128.7.0-1.amzn2.0.2', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE},
    {'reference':'firefox-debuginfo-128.7.0-1.amzn2.0.2', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE}
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
  var cves = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (!empty_or_null(package_array['cves'])) cves = package_array['cves'];
  if (reference && _release && (!exists_check || rpm_exists(release:_release, rpm:exists_check))) {
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj, cves:cves)) flag++;
  }
}

if (flag)
{
  var extra = rpm_report_get();
  if (!REPOS_FOUND) extra = rpm_report_get() + report_repo_caveat();
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : extra
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "firefox / firefox-debuginfo");
}
