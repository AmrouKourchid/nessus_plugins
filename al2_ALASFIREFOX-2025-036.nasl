#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALASFIREFOX-2025-036.
##

include('compat.inc');

if (description)
{
  script_id(233705);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/03");

  script_cve_id(
    "CVE-2022-29912",
    "CVE-2024-43097",
    "CVE-2025-1931",
    "CVE-2025-1932",
    "CVE-2025-1933",
    "CVE-2025-1934",
    "CVE-2025-1935",
    "CVE-2025-1936",
    "CVE-2025-1937",
    "CVE-2025-1938"
  );
  script_xref(name:"IAVA", value:"2022-A-0188-S");
  script_xref(name:"IAVA", value:"2022-A-0190-S");
  script_xref(name:"IAVA", value:"2025-A-0146-S");

  script_name(english:"Amazon Linux 2 : firefox (ALASFIREFOX-2025-036)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of firefox installed on the remote host is prior to 128.8.0-1. It is, therefore, affected by multiple
vulnerabilities as referenced in the ALAS2FIREFOX-2025-036 advisory.

    Requests initiated through reader mode did not properly omit cookies with a SameSite attribute. This
    vulnerability affects Thunderbird < 91.9, Firefox ESR < 91.9, and Firefox < 100. (CVE-2022-29912)

    In resizeToAtLeast of SkRegion.cpp, there is a possible out of bounds write due to an integer overflow.
    This could lead to local escalation of privilege with no additional execution privileges needed. User
    interaction is not needed for exploitation. (CVE-2024-43097)

    It was possible to cause a use-after-free in the content process side of a WebTransport connection,
    leading to a potentially exploitable crash. This vulnerability affects Firefox < 136, Firefox ESR <
    115.21, Firefox ESR < 128.8, Thunderbird < 136, and Thunderbird < 128.8. (CVE-2025-1931)

    An inconsistent comparator in xslt/txNodeSorter could have resulted in potentially exploitable out-of-
    bounds access. Only affected version 122 and later. This vulnerability affects Firefox < 136, Firefox ESR
    < 128.8, Thunderbird < 136, and Thunderbird < 128.8. (CVE-2025-1932)

    On 64-bit CPUs, when the JIT compiles WASM i32 return values they can pick up bits from left over memory.
    This can potentially cause them to be treated as a different type. This vulnerability affects Firefox <
    136, Firefox ESR < 115.21, Firefox ESR < 128.8, Thunderbird < 136, and Thunderbird < 128.8.
    (CVE-2025-1933)

    It was possible to interrupt the processing of a RegExp bailout and run additional JavaScript, potentially
    triggering garbage collection when the engine was not expecting it. This vulnerability affects Firefox <
    136, Firefox ESR < 128.8, Thunderbird < 136, and Thunderbird < 128.8. (CVE-2025-1934)

    A web page could trick a user into setting that site as the default handler for a custom URL protocol.
    This vulnerability affects Firefox < 136, Firefox ESR < 128.8, Thunderbird < 136, and Thunderbird < 128.8.
    (CVE-2025-1935)

    jar: URLs retrieve local file content packaged in a ZIP archive. The null and everything after it was
    ignored when retrieving the content from the archive, but the fake extension after the null was used to
    determine the type of content. This could have been used to hide code in a web extension disguised as
    something else like an image. This vulnerability affects Firefox < 136, Firefox ESR < 128.8, Thunderbird <
    136, and Thunderbird < 128.8. (CVE-2025-1936)

    Memory safety bugs present in Firefox 135, Thunderbird 135, Firefox ESR 115.20, Firefox ESR 128.7, and
    Thunderbird 128.7. Some of these bugs showed evidence of memory corruption and we presume that with enough
    effort some of these could have been exploited to run arbitrary code. This vulnerability affects Firefox <
    136, Firefox ESR < 115.21, Firefox ESR < 128.8, Thunderbird < 136, and Thunderbird < 128.8.
    (CVE-2025-1937)

    Memory safety bugs present in Firefox 135, Thunderbird 135, Firefox ESR 128.7, and Thunderbird 128.7. Some
    of these bugs showed evidence of memory corruption and we presume that with enough effort some of these
    could have been exploited to run arbitrary code. This vulnerability affects Firefox < 136, Firefox ESR <
    128.8, Thunderbird < 136, and Thunderbird < 128.8. (CVE-2025-1938)

Tenable has extracted the preceding description block directly from the tested product security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2/ALASFIREFOX-2025-036.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-29912.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2024-43097.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2025-1931.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2025-1932.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2025-1933.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2025-1934.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2025-1935.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2025-1936.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2025-1937.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2025-1938.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/faqs.html");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update firefox' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-29912");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/05/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/03/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/04/01");

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
    {'reference':'firefox-128.8.0-1.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE},
    {'reference':'firefox-128.8.0-1.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE},
    {'reference':'firefox-debuginfo-128.8.0-1.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE},
    {'reference':'firefox-debuginfo-128.8.0-1.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE}
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
      severity   : SECURITY_WARNING,
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
